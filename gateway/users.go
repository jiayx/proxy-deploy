package gateway

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// 按用户统计：用户认证发生在后端（sing-box）里，网关从后端日志中得知每个连接属于谁。
//
// sing-box 为每个连接打印同一连接 ID 下的两行：
//
//	[ID 0ms] inbound/anytls[anytls]: inbound connection from 127.0.0.1:54730
//	[ID 0ms] inbound/anytls[anytls]: [alice] inbound connection to www.baidu.com:443
//
// 来源端口就是网关连接后端时使用的本地端口，于是网关把这个端口上登记的连接归到 alice。
// UDP（packet connection）的 from 行本身就带用户名。各连接的流量每秒累加到所属用户。

// userStats 是一个用户的累计统计，进程级保存，Caddy 重载不会清零；流量会持久化到 usage 文件
type userStats struct {
	name      string
	Active    atomic.Int64
	Total     atomic.Int64
	BytesUp   atomic.Int64
	BytesDown atomic.Int64

	// 本周期用量，跨过重置日清零；periodStart 是周期起点（Unix 秒）
	PeriodUp, PeriodDown atomic.Int64
	periodStart          atomic.Int64
	state                atomic.Value // string：上次检查的状态，变化时记日志
}

// UserPolicy 是用户的流量上限和到期设置
type UserPolicy struct {
	// TrafficLimit 是每个周期的流量上限（上下行合计，字节），0 表示不限
	TrafficLimit int64 `json:"traffic_limit,omitempty"`
	// ResetDay 是每月重置周期用量的日期（1-28，服务器本地时间），默认 1
	ResetDay int `json:"reset_day,omitempty"`
	// Expire 是到期时刻（RFC 3339），为空表示不过期
	Expire string `json:"expire,omitempty"`

	expireAt time.Time
}

// 用户状态
const (
	UserActive    = "active"
	UserOverLimit = "over_limit"
	UserExpired   = "expired"
)

var policies atomic.Pointer[map[string]*UserPolicy]

// setPolicies 替换全部用户策略（每次加载配置时）
func setPolicies(p map[string]*UserPolicy) { policies.Store(&p) }

func policyFor(name string) *UserPolicy {
	if m := policies.Load(); m != nil {
		if p := (*m)[name]; p != nil {
			return p
		}
	}
	return &UserPolicy{}
}

// currentPeriodStart 返回 now 所在周期的起点：最近一个不晚于 now 的重置日零点
func currentPeriodStart(now time.Time, resetDay int) time.Time {
	if resetDay < 1 || resetDay > 28 {
		resetDay = 1
	}
	start := time.Date(now.Year(), now.Month(), resetDay, 0, 0, 0, 0, now.Location())
	if start.After(now) {
		start = start.AddDate(0, -1, 0)
	}
	return start
}

// checkState 在跨过重置日时清零周期用量，返回用户当前状态
func (u *userStats) checkState(now time.Time) string {
	p := policyFor(u.name)
	start := currentPeriodStart(now, p.ResetDay).Unix()
	if old := u.periodStart.Load(); old < start && u.periodStart.CompareAndSwap(old, start) && old != 0 {
		u.PeriodUp.Store(0)
		u.PeriodDown.Store(0)
	}
	switch {
	case !p.expireAt.IsZero() && !now.Before(p.expireAt):
		return UserExpired
	case p.TrafficLimit > 0 && u.PeriodUp.Load()+u.PeriodDown.Load() >= p.TrafficLimit:
		return UserOverLimit
	}
	return UserActive
}

var userRegistry sync.Map // 用户名 → *userStats

func statsForUser(name string) *userStats {
	s, _ := userRegistry.LoadOrStore(name, &userStats{name: name})
	return s.(*userStats)
}

// UserSnapshot 是管理接口返回的一个用户的统计
type UserSnapshot struct {
	User         string `json:"user"`
	State        string `json:"state"`
	Active       int64  `json:"active"`
	Total        int64  `json:"total"`
	BytesUp      int64  `json:"bytes_up"`
	BytesDown    int64  `json:"bytes_down"`
	PeriodUp     int64  `json:"period_up"`
	PeriodDown   int64  `json:"period_down"`
	PeriodStart  string `json:"period_start,omitempty"`
	TrafficLimit int64  `json:"traffic_limit,omitempty"`
	Expire       string `json:"expire,omitempty"`
}

func userSnapshots() []UserSnapshot {
	flushAccounting() // 把活动连接尚未结算的流量计入
	var out []UserSnapshot
	now := time.Now()
	userRegistry.Range(func(_, v any) bool {
		s := v.(*userStats)
		p := policyFor(s.name)
		snap := UserSnapshot{User: s.name, State: s.checkState(now), Active: s.Active.Load(), Total: s.Total.Load(),
			BytesUp: s.BytesUp.Load(), BytesDown: s.BytesDown.Load(),
			PeriodUp: s.PeriodUp.Load(), PeriodDown: s.PeriodDown.Load(),
			TrafficLimit: p.TrafficLimit, Expire: p.Expire}
		if ps := s.periodStart.Load(); ps != 0 {
			snap.PeriodStart = time.Unix(ps, 0).Format(time.RFC3339)
		}
		out = append(out, snap)
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// connKey 标识网关到后端的一条连接：后端名、传输层和网关一侧的本地端口
type connKey struct {
	backend string
	network string // tcp | udp
	port    int
}

// connRecord 是一条被跟踪的连接；up/down 是该连接自己的计数器
type connRecord struct {
	up, down *atomic.Int64
	user     atomic.Pointer[userStats]
	close    func() // 断开连接；用户超额或到期时调用
	closing  atomic.Bool

	flushedUp, flushedDown int64 // 已计入用户的部分；由 acct.mu 保护
}

// userName 返回连接所属用户，尚未识别时为空
func (r *connRecord) userName() string {
	if u := r.user.Load(); u != nil {
		return u.name
	}
	return ""
}

var acct = struct {
	sync.Mutex
	conns map[connKey]*connRecord
	once  sync.Once
}{conns: map[connKey]*connRecord{}}

// trackConn 登记一条到后端的连接，返回的记录在连接结束时交给 untrackConn；
// closeFn 用于在用户超额或到期时断开连接
func trackConn(backend, network string, local net.Addr, up, down *atomic.Int64, closeFn func()) (*connRecord, connKey) {
	acct.once.Do(func() { go accountingLoop() })
	key := connKey{backend: backend, network: network, port: addrPort(local)}
	rec := &connRecord{up: up, down: down, close: closeFn}
	acct.Lock()
	acct.conns[key] = rec
	acct.Unlock()
	return rec, key
}

// untrackConn 结算连接的剩余流量并移除记录
func untrackConn(rec *connRecord, key connKey) {
	acct.Lock()
	defer acct.Unlock()
	flushLocked(rec)
	if acct.conns[key] == rec {
		delete(acct.conns, key)
	}
	if u := rec.user.Load(); u != nil {
		u.Active.Add(-1)
	}
}

// attributeUser 把后端在某个来源端口上的连接归到用户名下；packet 表示 UDP 关联
func attributeUser(backend string, packet bool, port int, user string) {
	acct.Lock()
	defer acct.Unlock()
	// sing-box 的 QUIC 协议（hysteria2、tuic）在 UDP 会话上打印 "inbound connection"，
	// 所以非 packet 的行先找 TCP 再找 UDP
	networks := []string{"tcp", "udp"}
	if packet {
		networks = []string{"udp"}
	}
	for _, network := range networks {
		rec := acct.conns[connKey{backend, network, port}]
		if rec == nil {
			continue
		}
		if rec.user.Load() == nil {
			u := statsForUser(user)
			rec.user.Store(u)
			u.Active.Add(1)
			u.Total.Add(1)
			if u.checkState(time.Now()) != UserActive {
				rec.disconnect() // 超额或到期的用户：认证一完成就断开
			}
		}
		return
	}
}

// flushAccounting 把所有活动连接自上次结算以来的流量计入所属用户
func flushAccounting() {
	acct.Lock()
	defer acct.Unlock()
	for _, rec := range acct.conns {
		flushLocked(rec)
	}
}

func flushLocked(rec *connRecord) {
	u := rec.user.Load()
	if u == nil {
		return // 尚未识别用户（或认证失败）的流量不计入任何用户
	}
	up, down := rec.up.Load(), rec.down.Load()
	u.BytesUp.Add(up - rec.flushedUp)
	u.BytesDown.Add(down - rec.flushedDown)
	u.PeriodUp.Add(up - rec.flushedUp)
	u.PeriodDown.Add(down - rec.flushedDown)
	rec.flushedUp, rec.flushedDown = up, down
}

// disconnect 异步断开连接（只执行一次）；断开过程会回调 untrackConn，所以不能在持有 acct 锁时同步调用
func (r *connRecord) disconnect() {
	if r.close != nil && r.closing.CompareAndSwap(false, true) {
		go r.close()
	}
}

// enforcePolicies 断开超额或到期用户的全部连接，并在用户状态变化时记日志
func enforcePolicies(logger *zap.Logger) {
	now := time.Now()
	blocked := map[*userStats]string{}
	userRegistry.Range(func(_, v any) bool {
		u := v.(*userStats)
		state := u.checkState(now)
		if old, _ := u.state.Swap(state).(string); old != state && (old != "" || state != UserActive) {
			logger.Info("user state changed", zap.String("user", u.name), zap.String("state", state))
		}
		if state != UserActive {
			blocked[u] = state
		}
		return true
	})
	if len(blocked) == 0 {
		return
	}
	acct.Lock()
	defer acct.Unlock()
	for _, rec := range acct.conns {
		if u := rec.user.Load(); u != nil && blocked[u] != "" {
			rec.disconnect()
		}
	}
}

func addrPort(a net.Addr) int {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.Port
	case *net.UDPAddr:
		return v.Port
	}
	_, p, _ := net.SplitHostPort(a.String())
	n, _ := strconv.Atoi(p)
	return n
}

// sing-box 连接日志：[连接ID 耗时] inbound/类型[标签]: [用户] inbound (packet )connection from|to 地址
var connLine = regexp.MustCompile(`^\w+\[\d+\] \[(\d+) [^\]]*\] inbound/[^:]*: (?:\[([^\]]+)\] )?inbound (packet )?connection (from|to) (\S+)`)

// logAccounting 从后端日志中提取连接与用户的对应关系
type logAccounting struct {
	backend string
	ports   map[string]int // 连接 ID → 来源端口，等待带用户名的行
}

const maxPendingIDs = 4096

func (a *logAccounting) line(line string) {
	m := connLine.FindStringSubmatch(line)
	if m == nil {
		return
	}
	id, user, packet, dir, addr := m[1], m[2], m[3] != "", m[4], m[5]
	if dir == "from" {
		host, p, err := net.SplitHostPort(addr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			return // 不是经网关来的连接
		}
		port, _ := strconv.Atoi(p)
		if user != "" {
			attributeUser(a.backend, packet, port, user)
			return
		}
		if len(a.ports) >= maxPendingIDs {
			a.ports = map[string]int{} // 认证失败的连接不会有后续行，定期丢弃
		}
		a.ports[id] = port
		return
	}
	if port, ok := a.ports[id]; ok && user != "" {
		delete(a.ports, id)
		attributeUser(a.backend, packet, port, user)
	}
}

// usage 文件：用户累计流量的持久化，Caddy 重启后接着累计
var usage = struct {
	sync.Mutex
	path   string
	loaded bool
}{}

type usageEntry struct {
	BytesUp     int64 `json:"bytes_up"`
	BytesDown   int64 `json:"bytes_down"`
	Total       int64 `json:"total"`
	PeriodUp    int64 `json:"period_up"`
	PeriodDown  int64 `json:"period_down"`
	PeriodStart int64 `json:"period_start"` // Unix 秒
}

type usageFile struct {
	Users map[string]usageEntry `json:"users"`
}

// setUsageFile 设置持久化路径；进程内第一次设置时读入已有数据
func setUsageFile(path string, logger *zap.Logger) {
	usage.Lock()
	defer usage.Unlock()
	usage.path = path
	if usage.loaded || path == "" {
		return
	}
	usage.loaded = true
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("read usage file", zap.Error(err))
		}
		return
	}
	var f usageFile
	if err := json.Unmarshal(data, &f); err != nil {
		logger.Warn("parse usage file", zap.Error(err))
		return
	}
	for name, u := range f.Users {
		s := statsForUser(name)
		s.BytesUp.Store(u.BytesUp)
		s.BytesDown.Store(u.BytesDown)
		s.Total.Store(u.Total)
		s.PeriodUp.Store(u.PeriodUp)
		s.PeriodDown.Store(u.PeriodDown)
		s.periodStart.Store(u.PeriodStart)
	}
}

// saveUsage 把用户累计流量原子地写入 usage 文件
func saveUsage() error {
	usage.Lock()
	defer usage.Unlock()
	if usage.path == "" {
		return nil
	}
	f := usageFile{Users: map[string]usageEntry{}}
	flushAccounting()
	userRegistry.Range(func(_, v any) bool {
		s := v.(*userStats)
		f.Users[s.name] = usageEntry{s.BytesUp.Load(), s.BytesDown.Load(), s.Total.Load(),
			s.PeriodUp.Load(), s.PeriodDown.Load(), s.periodStart.Load()}
		return true
	})
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(usage.path), 0700); err != nil {
		return err
	}
	tmp := usage.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, usage.path)
}

const usageSaveInterval = 30 * time.Second

// accountingLogger 是统计和执法使用的日志，由应用启动时设置
var accountingLogger atomic.Pointer[zap.Logger]

// accountingLoop 每秒结算活动连接的流量、执行用户策略，定期持久化
func accountingLoop() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastSave := time.Now()
	for range tick.C {
		flushAccounting()
		logger := accountingLogger.Load()
		if logger == nil {
			logger = zap.NewNop()
		}
		enforcePolicies(logger)
		if time.Since(lastSave) >= usageSaveInterval {
			_ = saveUsage()
			lastSave = time.Now()
		}
	}
}
