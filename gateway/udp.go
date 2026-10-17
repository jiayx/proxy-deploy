package gateway

import (
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

const (
	maxPendingDatagrams = 16 // 选定路由前最多缓存的数据报数
	udpBufferSize       = 65535
)

// udpTable 是一个 UDP 监听地址上的会话表
type udpTable struct {
	mu       sync.Mutex
	sessions map[string]*udpSession
	writer   net.PacketConn // 当前监听 socket（Caddy 的包装），用于判断归属
	udp      *net.UDPConn   // writer 底层的 UDP socket，回包经由它发出（支持 GSO）
	server   *Server        // 当前生效的配置，决定超时和新会话的路由

	janitor sync.Once
}

var udpTables sync.Map // 监听地址 → *udpTable

func tableFor(key string) *udpTable {
	t, _ := udpTables.LoadOrStore(key, &udpTable{sessions: map[string]*udpSession{}})
	return t.(*udpTable)
}

type udpSession struct {
	mu       sync.Mutex
	client   *net.UDPAddr
	key      string
	start    time.Time
	pending  [][]byte
	asm      cryptoAssembler
	route    *Route
	sni      string
	upstream *net.UDPConn
	closed   bool
	log      *zap.Logger

	lastActive  atomic.Int64 // UnixNano
	established atomic.Bool  // 已选定路由并连接后端；reap 读取它而不拿 mu，避免与 handle 的加锁顺序相反
	up, down    atomic.Int64
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
	t.sessions = map[string]*udpSession{}
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
	srv := t.server
	if sess == nil {
		if srv == nil || !isQUICInitial(data) {
			t.mu.Unlock()
			return // 没有会话的非 Initial 数据报（例如重载前的旧连接迁移过来）无法路由
		}
		sess = &udpSession{client: client, key: key, start: time.Now(),
			log: srv.logger.With(zap.String("remote", key), zap.String("network", "udp"))}
		t.sessions[key] = sess
	}
	t.mu.Unlock()
	sess.touch()

	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.closed {
		return
	}
	if sess.upstream != nil {
		sess.up.Add(int64(len(data)))
		sess.route.stats.BytesUp.Add(int64(len(data)))
		_, _ = sess.upstream.Write(data)
		return
	}

	// 尚未选定路由：缓存数据报并继续重组 ClientHello
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
	sess.sni = hello.ServerName
	route := srv.match(sess.sni)
	sess.log = sess.log.With(zap.String("sni", sess.sni))
	if route == nil {
		sess.log.Debug("no route")
		t.drop(sess)
		return
	}
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
		if _, w := t.current(); w != nil {
			_ = writeBatch(w, buf[:n], segment, sess.client)
		}
	}
}

// drop 移除尚未建立的会话；调用方持有 sess.mu
func (t *udpTable) drop(sess *udpSession) {
	sess.closed = true
	sess.pending = nil
	t.mu.Lock()
	if t.sessions[sess.key] == sess {
		delete(t.sessions, sess.key)
	}
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
	sess.route.stats.Active.Add(-1)
	sess.log.Info("connection closed",
		zap.String("reason", reason),
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
		for key, sess := range t.sessions {
			idle := time.Duration(now - sess.lastActive.Load())
			established := sess.established.Load()
			if (established && idle > time.Duration(srv.IdleTimeout)) ||
				(!established && idle > time.Duration(srv.HandshakeTimeout)) {
				delete(t.sessions, key)
				expired = append(expired, sess)
			}
		}
		t.mu.Unlock()
		for _, sess := range expired {
			sess.close("idle")
		}
	}
}
