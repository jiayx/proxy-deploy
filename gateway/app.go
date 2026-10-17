// Package gateway 是 proxy-deploy 的入口网关，以 Caddy 应用模块（proxy_gateway）的形式运行。
//
// 所有公网连接先进入网关：网关解析 TLS ClientHello 取得 SNI，匹配到代理协议的路由时
// 用 Caddy 管理的证书终结 TLS 并把明文转给回环地址上的协议后端；其余连接原样透传给网站。
// 网关同时记录每个连接的客户端地址和流量，供日志、统计和管理接口使用。
package gateway

import (
	"crypto/tls"
	"fmt"
	"net"
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

	// TLSConnectionPolicies 用于终结 TLS 的路由；为空时使用默认策略（按 SNI 取 Caddy 管理的证书）
	TLSConnectionPolicies caddytls.ConnectionPolicies `json:"tls_connection_policies,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
}

// Server 是一个监听入口
type Server struct {
	Listen   []string `json:"listen"`
	Routes   []*Route `json:"routes,omitempty"`
	Fallback *Route   `json:"fallback,omitempty"`

	// HandshakeTimeout 限制读取 ClientHello 和终结 TLS 的时间，默认 10 秒
	HandshakeTimeout caddy.Duration `json:"handshake_timeout,omitempty"`
	// DialTimeout 限制连接后端的时间，默认 5 秒
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	app       *App
	tlsConfig func() *tls.Config
	listeners []net.Listener
	logger    *zap.Logger
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

	needTLS := false
	for name, srv := range a.Servers {
		if len(srv.Listen) == 0 {
			return fmt.Errorf("server %s: listen is required", name)
		}
		routes := srv.Routes
		if srv.Fallback != nil {
			routes = append(routes[:len(routes):len(routes)], srv.Fallback)
		}
		for i, r := range routes {
			if r.Name == "" || r.Upstream == "" {
				return fmt.Errorf("server %s route %d: name and upstream are required", name, i)
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
		if srv.HandshakeTimeout <= 0 {
			srv.HandshakeTimeout = caddy.Duration(10 * time.Second)
		}
		if srv.DialTimeout <= 0 {
			srv.DialTimeout = caddy.Duration(5 * time.Second)
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
	for name, srv := range a.Servers {
		for _, addr := range srv.Listen {
			na, err := caddy.ParseNetworkAddress(addr)
			if err != nil {
				return fmt.Errorf("server %s: %w", name, err)
			}
			if na.Network != "tcp" && na.Network != "tcp4" && na.Network != "tcp6" {
				return fmt.Errorf("server %s: unsupported network %q", name, na.Network)
			}
			for port := uint(0); port < na.PortRangeSize(); port++ {
				// Caddy 在重载配置时复用同一个 socket，不会断开监听
				ln, err := na.Listen(a.ctx, port, net.ListenConfig{})
				if err != nil {
					return fmt.Errorf("server %s: listen %s: %w", name, addr, err)
				}
				l := ln.(net.Listener)
				srv.listeners = append(srv.listeners, l)
				go srv.serve(l)
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
	}
	return nil
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
