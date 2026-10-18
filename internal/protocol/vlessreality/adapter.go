// Package vlessreality 实现 VLESS + Reality 协议的部署适配器，服务端使用 sing-box。
//
// Reality 自己完成 TLS 握手：客户端使用伪装目标网站（默认 www.microsoft.com）的 SNI，
// 认证通过的连接由 sing-box 处理，未通过的（包括主动探测）被转给真正的目标网站，
// 探测者看到的是目标网站的真实证书和内容。网关按 SNI 把连接原样透传给 sing-box，
// 不终结 TLS，也不需要证书。
package vlessreality

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/jiayx/proxy-gateway/internal/config"
	"github.com/jiayx/proxy-gateway/internal/protocol"
	"github.com/jiayx/proxy-gateway/internal/protocol/singbox"
	"github.com/jiayx/proxy-gateway/pkg/paths"
	"github.com/jiayx/proxy-gateway/pkg/secrets"
)

const (
	name       = "vless-reality"
	defaultSNI = "www.microsoft.com"
	flow       = "xtls-rprx-vision"
)

type Adapter struct {
	layout *paths.Layout
}

func New(layout *paths.Layout) *Adapter {
	return &Adapter{layout: layout}
}

func (a *Adapter) Name() string                  { return name }
func (a *Adapter) LoopbackPort() int             { return 20004 }
func (a *Adapter) Transport() protocol.Transport { return protocol.TransportTCP }
func (a *Adapter) Options() []string             { return []string{"private_key", "short_id", "handshake"} }
func (a *Adapter) PassthroughTLS() bool          { return true }
func (a *Adapter) DefaultSNI() string            { return defaultSNI }
func (a *Adapter) ConfigPath() string {
	return filepath.Join(a.layout.ProtocolDir(name), "config.json")
}

func (a *Adapter) Install(ctx context.Context) error { return singbox.Install(ctx, a.layout) }

func (a *Adapter) CheckConfig(ctx context.Context, path string) error {
	return singbox.Check(ctx, a.layout, path)
}

var shortIDPattern = regexp.MustCompile(`^([0-9a-f]{2}){0,8}$`)

func (a *Adapter) Validate(cfg *config.ProtocolConfig) error {
	if _, err := secrets.RealityPublicKey(protocol.StringOption(cfg, "private_key")); err != nil {
		return fmt.Errorf("private_key：%v（proxy-gateway init-config 会生成）", err)
	}
	if !shortIDPattern.MatchString(protocol.StringOption(cfg, "short_id")) {
		return fmt.Errorf("short_id 必须是 0 到 16 位偶数长度的小写十六进制")
	}
	if hs := protocol.StringOption(cfg, "handshake"); hs != "" {
		if _, _, err := net.SplitHostPort(hs); err != nil {
			return fmt.Errorf("handshake 应为 host:port：%v", err)
		}
	}
	return nil
}

// handshake 返回伪装握手的目标网站，默认是 SNI 对应网站的 443 端口
func handshake(cfg *config.ProtocolConfig, sni string) (string, int) {
	hs := protocol.StringOption(cfg, "handshake")
	if hs == "" {
		return sni, 443
	}
	host, port, _ := net.SplitHostPort(hs)
	p, _ := strconv.Atoi(port)
	return host, p
}

func (a *Adapter) GenerateConfig(cfg *config.ProtocolConfig, rt protocol.Runtime) ([]byte, error) {
	host, port := handshake(cfg, rt.SNI)
	var users []any
	for _, u := range rt.Users {
		users = append(users, map[string]any{"name": u.Name, "uuid": u.UUID(name), "flow": flow})
	}
	return singbox.Config(rt.ListenAddr, map[string]any{
		"type":  "vless",
		"tag":   name,
		"users": users,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": rt.SNI,
			"reality": map[string]any{
				"enabled":     true,
				"handshake":   map[string]any{"server": host, "server_port": port},
				"private_key": protocol.StringOption(cfg, "private_key"),
				"short_id":    []string{protocol.StringOption(cfg, "short_id")},
			},
		},
	})
}

func (a *Adapter) Service(cfg *config.ProtocolConfig, rt protocol.Runtime) (*protocol.Service, error) {
	return &protocol.Service{Args: singbox.Args(a.layout, a.ConfigPath())}, nil
}

func (a *Adapter) ClientConfig(cfg *config.ProtocolConfig, c protocol.ClientContext) (*config.ClientConfig, error) {
	pub, err := secrets.RealityPublicKey(protocol.StringOption(cfg, "private_key"))
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", flow)
	q.Set("security", "reality")
	q.Set("sni", c.SNI)
	q.Set("fp", "chrome")
	q.Set("pbk", pub)
	q.Set("sid", protocol.StringOption(cfg, "short_id"))
	q.Set("type", "tcp")
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(c.User.UUID(name)),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		RawQuery: q.Encode(),
		Fragment: protocol.LinkName(name, c.User),
	}
	return &config.ClientConfig{Protocol: name, URI: u.String(),
		Notes: []string{"Reality 使用伪装目标网站的 SNI，客户端不校验本服务器的证书"}}, nil
}
