// Package gateway 是 proxy-gateway 的入口网关，以 Caddy 应用模块（proxy_gateway）的形式运行。
//
// 所有公网连接先进入网关：网关解析 TLS ClientHello 取得 SNI，匹配到代理协议的路由时
// 用 Caddy 管理的证书终结 TLS 并把明文转给回环地址上的协议后端；其余连接原样透传给网站。
// 网关同时记录每个连接的客户端地址和流量，供日志、统计和管理接口使用。
package gateway

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// App 是 proxy_gateway 应用
type App struct {
	Servers map[string]*Server `json:"servers,omitempty"`
	// Backends 是由网关启动并监管的协议后端进程，按名称索引
	Backends map[string]*Backend `json:"backends,omitempty"`
	// UsageFile 保存按用户累计的流量，Caddy 重启后接着累计；为空时不持久化
	UsageFile string `json:"usage_file,omitempty"`
	// Users 是各用户的流量上限和到期设置；超额或到期用户的连接会被断开
	Users map[string]*UserPolicy `json:"users,omitempty"`

	// TLSConnectionPolicies 用于终结 TLS 的路由；为空时使用默认策略（按 SNI 取 Caddy 管理的证书）
	TLSConnectionPolicies caddytls.ConnectionPolicies `json:"tls_connection_policies,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
	procs  []*process
}

// Server 是一个监听入口
type Server struct {
	Listen   []string `json:"listen"`
	Routes   []*Route `json:"routes,omitempty"`
	Fallback *Route   `json:"fallback,omitempty"`
	// Raw 表示这个端口专属于一个后端：不识别 TLS / QUIC，所有连接直接交给 Fallback。
	// 用于没有 SNI 的协议（如 Shadowsocks），它们的首包是随机字节，识别只会造成误判和等待
	Raw bool `json:"raw,omitempty"`

	// HandshakeTimeout 限制读取 ClientHello 和终结 TLS 的时间，默认 10 秒
	HandshakeTimeout caddy.Duration `json:"handshake_timeout,omitempty"`
	// DialTimeout 限制连接后端的时间，默认 5 秒
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`
	// IdleTimeout 是 UDP 会话的空闲超时，默认 2 分钟
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`

	app         *App
	tlsConfig   func() *tls.Config
	listeners   []net.Listener
	packetConns []packetConn
	logger      *zap.Logger
}

type packetConn struct {
	pc    net.PacketConn
	table *udpTable
}

const (
	TLSTerminate   = "terminate"
	TLSPassthrough = "passthrough"
)

// Route 把匹配的连接转发到一个后端
type Route struct {
	Name          string   `json:"name"`
	SNI           []string `json:"sni,omitempty"`
	TLS           string   `json:"tls"` // terminate | passthrough
	Upstream      string   `json:"upstream"`
	ProxyProtocol bool     `json:"proxy_protocol,omitempty"`

	stats *routeStats
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "proxy_gateway",
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger()

	for name, b := range a.Backends {
		if len(b.Command) == 0 {
			return fmt.Errorf("backend %s: command is required", name)
		}
	}
	for name, p := range a.Users {
		if p.Expire != "" {
			t, err := time.Parse(time.RFC3339, p.Expire)
			if err != nil {
				return fmt.Errorf("user %s: expire: %w", name, err)
			}
			p.expireAt = t
		}
	}

	needTLS := false
	for name, srv := range a.Servers {
		if len(srv.Listen) == 0 {
			return fmt.Errorf("server %s: listen is required", name)
		}
		routes := srv.Routes
		if srv.Fallback != nil {
			routes = append(routes[:len(routes):len(routes)], srv.Fallback)
		}
		udp, err := isUDPServer(srv.Listen)
		if err != nil {
			return fmt.Errorf("server %s: %w", name, err)
		}
		for i, r := range routes {
			if r.Name == "" || r.Upstream == "" {
				return fmt.Errorf("server %s route %d: name and upstream are required", name, i)
			}
			if udp && (r.TLS != TLSPassthrough || r.ProxyProtocol) {
				return fmt.Errorf("server %s route %s: UDP routes only support tls passthrough without proxy_protocol", name, r.Name)
			}
			switch r.TLS {
			case TLSTerminate:
				needTLS = true
			case TLSPassthrough:
			default:
				return fmt.Errorf("server %s route %s: tls must be %q or %q", name, r.Name, TLSTerminate, TLSPassthrough)
			}
			r.stats = statsFor(r.Name)
		}
		if srv.Fallback != nil && len(srv.Fallback.SNI) > 0 {
			return fmt.Errorf("server %s: fallback must not set sni", name)
		}
		if srv.Raw && (len(srv.Routes) > 0 || srv.Fallback == nil || srv.Fallback.TLS != TLSPassthrough) {
			return fmt.Errorf("server %s: raw requires a passthrough fallback and no routes", name)
		}
		if srv.HandshakeTimeout <= 0 {
			srv.HandshakeTimeout = caddy.Duration(10 * time.Second)
		}
		if srv.DialTimeout <= 0 {
			srv.DialTimeout = caddy.Duration(5 * time.Second)
		}
		if srv.IdleTimeout <= 0 {
			srv.IdleTimeout = caddy.Duration(2 * time.Minute)
		}
		srv.app = a
		srv.logger = a.logger.With(zap.String("server", name))
	}

	if needTLS {
		if len(a.TLSConnectionPolicies) == 0 {
			a.TLSConnectionPolicies = caddytls.ConnectionPolicies{new(caddytls.ConnectionPolicy)}
		}
		if err := a.TLSConnectionPolicies.Provision(ctx); err != nil {
			return fmt.Errorf("tls connection policies: %w", err)
		}
		for _, srv := range a.Servers {
			srv.tlsConfig = func() *tls.Config { return a.TLSConnectionPolicies.TLSConfig(a.ctx) }
		}
	}
	return nil
}

func (a *App) Start() error {
	setUsageFile(a.UsageFile, a.logger)
	setPolicies(a.Users)
	for name := range a.Users {
		statsForUser(name) // 还没有流量的用户也出现在统计里
	}
	accountingLogger.Store(a.logger)
	// 先启动后端，监听开始后转发过来的连接才有去处
	names := make([]string, 0, len(a.Backends))
	for name := range a.Backends {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		a.procs = append(a.procs, acquireBackend(name, a.Backends[name], a.logger))
	}
	for name, srv := range a.Servers {
		for _, addr := range srv.Listen {
			na, err := caddy.ParseNetworkAddress(addr)
			if err != nil {
				return fmt.Errorf("server %s: %w", name, err)
			}
			for port := uint(0); port < na.PortRangeSize(); port++ {
				// Caddy 在重载配置时复用同一个 socket（UDP 为同端口的新 socket），不会断开监听
				ln, err := na.Listen(a.ctx, port, net.ListenConfig{})
				if err != nil {
					return fmt.Errorf("server %s: listen %s: %w", name, addr, err)
				}
				switch l := ln.(type) {
				case net.Listener:
					srv.listeners = append(srv.listeners, l)
					go srv.serve(l)
				case net.PacketConn:
					t := tableFor(na.JoinHostPort(port))
					t.attach(srv, l)
					srv.packetConns = append(srv.packetConns, packetConn{l, t})
					go srv.serveUDP(l, t)
				}
			}
			srv.logger.Info("listening", zap.String("address", addr))
		}
	}
	return nil
}

// Stop 只关闭监听，已建立的连接继续运行直到结束，Caddy 重载配置不会断开代理连接
func (a *App) Stop() error {
	for _, srv := range a.Servers {
		for _, l := range srv.listeners {
			_ = l.Close()
		}
		srv.listeners = nil
		for _, p := range srv.packetConns {
			_ = p.pc.Close()
			p.table.detach(p.pc)
		}
		srv.packetConns = nil
	}
	for _, p := range a.procs {
		releaseBackend(p)
	}
	a.procs = nil
	if err := saveUsage(); err != nil {
		a.logger.Warn("save usage", zap.Error(err))
	}
	return nil
}

// isUDPServer 判断监听地址是否都是 UDP；同一个 server 不能混用 TCP 和 UDP
func isUDPServer(listen []string) (bool, error) {
	var tcp, udp bool
	for _, addr := range listen {
		na, err := caddy.ParseNetworkAddress(addr)
		if err != nil {
			return false, err
		}
		switch na.Network {
		case "tcp", "tcp4", "tcp6":
			tcp = true
		case "udp", "udp4", "udp6":
			udp = true
		default:
			return false, fmt.Errorf("unsupported network %q", na.Network)
		}
	}
	if tcp && udp {
		return false, fmt.Errorf("listen mixes tcp and udp addresses")
	}
	return udp, nil
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
