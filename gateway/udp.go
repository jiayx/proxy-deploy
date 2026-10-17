package gateway

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// UDP 网关：按客户端地址维护会话。会话建立前缓存客户端的数据报，从 QUIC Initial 包中
// 重组出 ClientHello 取得 SNI，选定路由后连接后端并回放缓存；此后双向转发数据报。
//
// Caddy 重载配置时会用 SO_REUSEPORT 再绑定一个同端口的新 socket，内核按四元组把数据报
// 分给新旧 socket 之一。所以会话表按监听地址放在进程级，新旧应用实例共用，
// 回包总是经由当前最新的 socket 发出，重载不会中断已建立的 QUIC 连接。
//
// 连接迁移：QUIC 按连接 ID 而不是地址识别连接。网关学习每个会话的服务端连接 ID：
// 握手期间从后端回包长包头的源连接 ID 得到长度和第一个 ID；客户端握手后通常会改用
// 服务端在加密帧中下发的新 ID，所以也从客户端短包头中学习它当前使用的 ID。
// 客户端地址变化后（NAT 重新映射、切换网络但沿用原 socket），新地址发来的数据报
// 仍带着这些 ID，网关据此找回原会话。后端看到的仍是网关的同一个 socket，不感知迁移。
// 客户端主动迁移并换用从未用过的 ID 时无法识别，需要重新连接。

const (
	maxPendingDatagrams = 16 // 选定路由前最多缓存的数据报数
	udpBufferSize       = 65535
	maxSessionCIDs      = 8 // 每个会话保留最近学到的连接 ID 数

	// migrateQuiet：只有原地址静默超过这段时间，才把回包切到新地址。真正切换网络时
	// 原地址不会再有数据；能看到连接 ID 的中间人伪造来源地址也无法在正常通信时劫持回包
	migrateQuiet = time.Second
)

// udpTable 是一个 UDP 监听地址上的会话表
type udpTable struct {
	mu       sync.Mutex
	sessions map[string]*udpSession // 客户端地址 → 会话
	cids     map[string]*udpSession // 服务端连接 ID → 会话
	cidLens  map[int]bool           // 学到的连接 ID 长度；短包头不含长度，按这些长度尝试查找
	writer   net.PacketConn         // 当前监听 socket（Caddy 的包装），用于判断归属
	udp      *net.UDPConn           // writer 底层的 UDP socket，回包经由它发出（支持 GSO）
	server   *Server                // 当前生效的配置，决定超时和新会话的路由

	janitor sync.Once
}

var udpTables sync.Map // 监听地址 → *udpTable

func newUDPTable() *udpTable {
	return &udpTable{sessions: map[string]*udpSession{}, cids: map[string]*udpSession{}, cidLens: map[int]bool{}}
}

func tableFor(key string) *udpTable {
	t, _ := udpTables.LoadOrStore(key, newUDPTable())
	return t.(*udpTable)
}

type udpSession struct {
	mu       sync.Mutex
	start    time.Time
	pending  [][]byte
	asm      cryptoAssembler
	route    *Route
	sni      string
	upstream *net.UDPConn
	closed   bool
	log      *zap.Logger
	rec      *connRecord // 按用户统计的连接记录
	recKey   connKey

	key     string   // 当前客户端地址，在 table.sessions 中的键；由 table.mu 保护
	cids    []string // 最近学到的连接 ID，最早的在前；由 table.mu 保护
	lastCID []byte   // 客户端最近使用的连接 ID，变化时才登记；由 mu 保护

	cidLen atomic.Int32 // 服务端连接 ID 长度，握手时从源连接 ID 学到
	raw    bool         // 专用端口：不识别 QUIC，直接交给 fallback，也不学习连接 ID

	client         atomic.Pointer[net.UDPAddr] // 回包地址，迁移时更新
	lastActive     atomic.Int64                // UnixNano，任一方向有数据
	lastFromClient atomic.Int64                // UnixNano，当前客户端地址最后一次发来数据
	established    atomic.Bool                 // 已选定路由并连接后端；reap 读取它而不拿 mu，避免与 handle 的加锁顺序相反
	up, down       atomic.Int64
}

func (s *udpSession) touch() { s.lastActive.Store(time.Now().UnixNano()) }

// attach 让 server 接管 table：新会话按它的配置路由，回包经由 pc 发出
func (t *udpTable) attach(s *Server, pc net.PacketConn) {
	uc := unwrapUDP(pc)
	if uc != nil {
		_ = uc.SetReadBuffer(socketBuffer)
		_ = uc.SetWriteBuffer(socketBuffer)
	}
	t.mu.Lock()
	t.server, t.writer, t.udp = s, pc, uc
	t.mu.Unlock()
	t.janitor.Do(func() { go t.reap() })
}

// detach 在 server 的 socket 关闭时调用；没有新实例接管时关闭全部会话
func (t *udpTable) detach(pc net.PacketConn) {
	t.mu.Lock()
	if t.writer != pc {
		t.mu.Unlock()
		return
	}
	t.writer, t.server, t.udp = nil, nil, nil
	sessions := t.sessions
	t.sessions, t.cids = map[string]*udpSession{}, map[string]*udpSession{}
	t.mu.Unlock()
	for _, sess := range sessions {
		sess.close("shutdown")
	}
}

func (t *udpTable) current() (*Server, *net.UDPConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.server, t.udp
}

// socketBuffer 是网关 UDP socket 的收发缓冲大小，减少突发流量下的丢包；
// 实际值受 net.core.rmem_max / wmem_max 限制
const socketBuffer = 4 << 20

// unwrapUDP 取出 Caddy 包装的监听 socket 底层的 *net.UDPConn
func unwrapUDP(pc net.PacketConn) *net.UDPConn {
	for {
		switch c := pc.(type) {
		case *net.UDPConn:
			return c
		case interface{ Unwrap() net.PacketConn }:
			pc = c.Unwrap()
		default:
			return nil
		}
	}
}

func (s *Server) serveUDP(pc net.PacketConn, t *udpTable) {
	buf := make([]byte, udpBufferSize)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Warn("udp read", zap.Error(err))
			continue
		}
		t.handle(addr, buf[:n])
	}
}

func (t *udpTable) handle(addr net.Addr, data []byte) {
	client, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	key := addr.String()
	t.mu.Lock()
	sess := t.sessions[key]
	if sess != nil {
		t.mu.Unlock()
		sess.lastFromClient.Store(time.Now().UnixNano())
		t.forward(sess, data)
		return
	}
	if migrated := t.byCID(data); migrated != nil {
		t.migrate(migrated, client, key) // 释放 t.mu
		t.forward(migrated, data)
		return
	}
	srv := t.server
	if srv == nil || (!srv.Raw && !isQUICInitial(data)) {
		t.mu.Unlock()
		return // 无法归属到任何会话的数据报
	}
	sess = &udpSession{key: key, start: time.Now(), raw: srv.Raw,
		log: srv.logger.With(zap.String("remote", key), zap.String("network", "udp"))}
	sess.client.Store(client)
	sess.lastFromClient.Store(time.Now().UnixNano())
	t.sessions[key] = sess
	t.mu.Unlock()
	t.forward(sess, data)
}

// byCID 按数据报中的目标连接 ID 查找已建立的会话；调用方持有 t.mu
func (t *udpTable) byCID(data []byte) *udpSession {
	if len(data) == 0 || data[0]&0x40 == 0 {
		return nil // 不是 QUIC 数据报（fixed bit 未置位）
	}
	if data[0]&0x80 != 0 { // 长包头：目标连接 ID 带长度
		if len(data) < 6 || int(data[5]) > len(data)-6 {
			return nil
		}
		return t.lookupCID(data[6 : 6+int(data[5])])
	}
	for n := range t.cidLens { // 短包头：连接 ID 紧跟第一个字节，长度由服务端决定
		if len(data) > 1+n {
			if sess := t.lookupCID(data[1 : 1+n]); sess != nil {
				return sess
			}
		}
	}
	return nil
}

func (t *udpTable) lookupCID(cid []byte) *udpSession {
	if sess := t.cids[string(cid)]; sess != nil && sess.established.Load() {
		return sess
	}
	return nil
}

// migrate 处理已知会话从新地址发来的数据报：原地址已静默时把会话切到新地址，
// 否则只转发、不改回包地址。调用时持有 t.mu，返回前释放
func (t *udpTable) migrate(sess *udpSession, client *net.UDPAddr, key string) {
	if time.Since(time.Unix(0, sess.lastFromClient.Load())) < migrateQuiet {
		t.mu.Unlock()
		return
	}
	old := sess.key
	if t.sessions[old] == sess {
		delete(t.sessions, old)
	}
	sess.key = key
	t.sessions[key] = sess
	sess.client.Store(client)
	sess.lastFromClient.Store(time.Now().UnixNano())
	t.mu.Unlock()
	sess.log.Info("client address changed", zap.String("from", old), zap.String("to", key))
}

// learnCIDs 从后端回包的长包头中记录服务端连接 ID（源连接 ID 字段）。
// buf 可能是 GRO 合并的多个数据报，每个 segment 字节一个
func (t *udpTable) learnCIDs(sess *udpSession, buf []byte, segment int) {
	if segment <= 0 {
		segment = len(buf)
	}
	for off := 0; off < len(buf); off += segment {
		b := buf[off:min(off+segment, len(buf))]
		if len(b) < 7 || b[0]&0xc0 != 0xc0 || (b[1]|b[2]|b[3]|b[4]) == 0 {
			continue // 只看长包头；版本为 0 的是版本协商包
		}
		scidAt := 6 + int(b[5])
		if scidAt >= len(b) {
			continue
		}
		n := int(b[scidAt])
		if n == 0 || n > 20 || scidAt+1+n > len(b) {
			continue
		}
		sess.cidLen.Store(int32(n))
		t.addCID(sess, string(b[scidAt+1:scidAt+1+n]))
	}
}

// learnClientCID 从客户端短包头中登记它当前使用的服务端连接 ID；调用方持有 sess.mu
func (t *udpTable) learnClientCID(sess *udpSession, data []byte) {
	n := int(sess.cidLen.Load())
	if n == 0 || len(data) <= 1+n || data[0]&0xc0 != 0x40 {
		return
	}
	cid := data[1 : 1+n]
	if bytes.Equal(cid, sess.lastCID) {
		return
	}
	sess.lastCID = bytes.Clone(cid)
	t.addCID(sess, string(cid))
}

// addCID 登记会话的一个连接 ID，超过上限时淘汰最早的
func (t *udpTable) addCID(sess *udpSession, cid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cids[cid] == sess {
		return
	}
	if len(sess.cids) >= maxSessionCIDs {
		if t.cids[sess.cids[0]] == sess {
			delete(t.cids, sess.cids[0])
		}
		sess.cids = sess.cids[1:]
	}
	t.cids[cid] = sess
	t.cidLens[len(cid)] = true
	sess.cids = append(sess.cids, cid)
}

// forget 从表中移除会话的地址和连接 ID；调用方持有 t.mu
func (t *udpTable) forget(sess *udpSession) {
	if t.sessions[sess.key] == sess {
		delete(t.sessions, sess.key)
	}
	for _, cid := range sess.cids {
		if t.cids[cid] == sess {
			delete(t.cids, cid)
		}
	}
}

// forward 处理一个客户端数据报：已建立的会话直接转发给后端；
// 否则缓存并继续重组 ClientHello，完成后选定路由、连接后端
func (t *udpTable) forward(sess *udpSession, data []byte) {
	sess.touch()
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.closed {
		return
	}
	if sess.upstream != nil {
		sess.up.Add(int64(len(data)))
		sess.route.stats.BytesUp.Add(int64(len(data)))
		if !sess.raw {
			t.learnClientCID(sess, data)
		}
		_, _ = sess.upstream.Write(data)
		return
	}
	if sess.raw {
		srv, _ := t.current()
		if srv == nil || srv.Fallback == nil {
			t.drop(sess)
			return
		}
		sess.pending = append(sess.pending, append([]byte(nil), data...))
		t.connect(sess, srv.Fallback)
		return
	}

	if len(sess.pending) >= maxPendingDatagrams {
		sess.log.Debug("ClientHello not found in initial datagrams")
		t.drop(sess)
		return
	}
	sess.pending = append(sess.pending, append([]byte(nil), data...))
	payloads, err := decryptInitials(data)
	if err != nil && !errors.Is(err, errNotInitial) {
		sess.log.Debug("decrypt QUIC Initial", zap.Error(err))
		t.drop(sess)
		return
	}
	for _, p := range payloads {
		if err := sess.asm.add(p); err != nil {
			sess.log.Debug("parse QUIC Initial", zap.Error(err))
			t.drop(sess)
			return
		}
	}
	msg := sess.asm.clientHello()
	if msg == nil {
		return
	}
	hello := parseClientHelloMessage(msg)
	if hello == nil {
		sess.log.Debug("invalid ClientHello")
		t.drop(sess)
		return
	}
	srv, _ := t.current()
	if srv == nil {
		t.drop(sess)
		return
	}
	sess.sni = hello.ServerName
	route := srv.match(sess.sni)
	sess.log = sess.log.With(zap.String("sni", sess.sni))
	if route == nil {
		sess.log.Debug("no route")
		t.drop(sess)
		return
	}
	t.connect(sess, route)
}

// connect 连接后端并回放缓存的数据报，然后开始转发回包；调用方持有 sess.mu
func (t *udpTable) connect(sess *udpSession, route *Route) {
	raddr, err := net.ResolveUDPAddr("udp", route.Upstream)
	if err == nil {
		sess.upstream, err = net.DialUDP("udp", nil, raddr)
	}
	if err != nil {
		sess.log.Warn("dial upstream", zap.String("upstream", route.Upstream), zap.Error(err))
		t.drop(sess)
		return
	}
	_ = sess.upstream.SetReadBuffer(socketBuffer)
	_ = sess.upstream.SetWriteBuffer(socketBuffer)
	enableGRO(sess.upstream)
	sess.route = route
	sess.log = sess.log.With(zap.String("route", route.Name))
	sess.rec, sess.recKey = trackConn(route.Name, "udp", sess.upstream.LocalAddr(), &sess.up, &sess.down)
	route.stats.Active.Add(1)
	route.stats.Total.Add(1)
	for _, d := range sess.pending {
		sess.up.Add(int64(len(d)))
		route.stats.BytesUp.Add(int64(len(d)))
		_, _ = sess.upstream.Write(d)
	}
	sess.pending = nil
	sess.established.Store(true)
	go t.pump(sess)
}

// pump 把后端的回包经由当前 socket 发回客户端；Linux 上成批收发（GRO/GSO）
func (t *udpTable) pump(sess *udpSession) {
	buf := make([]byte, udpBufferSize)
	oob := make([]byte, 64)
	for {
		n, segment, err := readBatch(sess.upstream, buf, oob)
		if err != nil {
			return // 会话关闭
		}
		sess.touch()
		sess.down.Add(int64(n))
		sess.route.stats.BytesDown.Add(int64(n))
		if !sess.raw {
			t.learnCIDs(sess, buf[:n], segment)
		}
		if _, w := t.current(); w != nil {
			_ = writeBatch(w, buf[:n], segment, sess.client.Load())
		}
	}
}

// drop 移除尚未建立的会话；调用方持有 sess.mu
func (t *udpTable) drop(sess *udpSession) {
	sess.closed = true
	sess.pending = nil
	t.mu.Lock()
	t.forget(sess)
	t.mu.Unlock()
}

// close 结束一个会话，已建立的会话记一条日志
func (sess *udpSession) close(reason string) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.closed {
		return
	}
	sess.closed = true
	if sess.upstream == nil {
		return
	}
	sess.upstream.Close()
	untrackConn(sess.rec, sess.recKey)
	sess.route.stats.Active.Add(-1)
	sess.log.Info("connection closed",
		zap.String("reason", reason),
		zap.String("user", sess.rec.userName()),
		zap.String("client", sess.client.Load().String()),
		zap.String("upstream", sess.route.Upstream),
		zap.String("upstream_local", sess.upstream.LocalAddr().String()),
		zap.Int64("bytes_up", sess.up.Load()),
		zap.Int64("bytes_down", sess.down.Load()),
		zap.Duration("duration", time.Since(sess.start)),
	)
}

// reap 定期清理空闲会话和迟迟没有完成 ClientHello 的会话
func (t *udpTable) reap() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		srv, _ := t.current()
		if srv == nil {
			continue
		}
		now := time.Now().UnixNano()
		var expired []*udpSession
		t.mu.Lock()
		for _, sess := range t.sessions {
			idle := time.Duration(now - sess.lastActive.Load())
			established := sess.established.Load()
			if (established && idle > time.Duration(srv.IdleTimeout)) ||
				(!established && idle > time.Duration(srv.HandshakeTimeout)) {
				expired = append(expired, sess)
			}
		}
		for _, sess := range expired {
			t.forget(sess)
		}
		t.mu.Unlock()
		for _, sess := range expired {
			sess.close("idle")
		}
	}
}
