// Package hysteria2 实现 Hysteria 2 协议的部署适配器，服务端使用 sing-box。
//
// Hysteria 2 运行在 QUIC/UDP 上：单独占用一个 UDP 端口时直接监听公网端口，
// 与其他 QUIC 协议共享端口时由 Caddy l4 按 QUIC SNI 转发到回环地址。
// 证书使用 Caddy 统一管理的文件，sing-box 在文件变化（续期）时自动重新加载。
package hysteria2

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/internal/protocol/singbox"
	"github.com/jiayx/proxy-deploy/pkg/paths"
)

const name = "hysteria2"

type Adapter struct {
	layout *paths.Layout
}

func New(layout *paths.Layout) *Adapter {
	return &Adapter{layout: layout}
}

func (a *Adapter) Name() string                  { return name }
func (a *Adapter) LoopbackPort() int             { return 20002 }
func (a *Adapter) Transport() protocol.Transport { return protocol.TransportUDP }
func (a *Adapter) Options() []string             { return []string{"masquerade_url"} }
func (a *Adapter) NeedsCertificate() bool        { return true }
func (a *Adapter) ConfigPath() string {
	return filepath.Join(a.layout.ProtocolDir(name), "config.json")
}

func (a *Adapter) Install(ctx context.Context) error { return singbox.Install(ctx, a.layout) }

func (a *Adapter) CheckConfig(ctx context.Context, path string) error {
	return singbox.Check(ctx, a.layout, path)
}

func (a *Adapter) GenerateConfig(cfg *config.ProtocolConfig, rt protocol.Runtime) ([]byte, error) {
	if rt.Cert == nil {
		return nil, fmt.Errorf("hysteria2: certificate is required")
	}
	// 非 Hysteria 客户端（如浏览器的 HTTP/3 请求）看到的是伪装网站，默认就是本机部署的网站
	masquerade := map[string]any{"type": "proxy", "url": rt.SiteURL}
	if u := protocol.StringOption(cfg, "masquerade_url"); u != "" {
		masquerade["url"] = u
		masquerade["rewrite_host"] = true
	}
	var users []any
	for _, u := range rt.Users {
		users = append(users, map[string]any{"name": u.Name, "password": u.Password(name)})
	}
	return singbox.Config(rt.ListenAddr, map[string]any{
		"type":  "hysteria2",
		"tag":   name,
		"users": users,
		"tls": map[string]any{
			"enabled":          true,
			"alpn":             []string{"h3"},
			"certificate_path": rt.Cert.CertPath,
			"key_path":         rt.Cert.KeyPath,
		},
		"masquerade": masquerade,
	})
}

func (a *Adapter) Service(cfg *config.ProtocolConfig, rt protocol.Runtime) (*protocol.Service, error) {
	return &protocol.Service{Args: singbox.Args(a.layout, a.ConfigPath())}, nil
}

func (a *Adapter) ClientConfig(cfg *config.ProtocolConfig, c protocol.ClientContext) (*config.ClientConfig, error) {
	q := url.Values{}
	q.Set("sni", c.SNI)
	if c.Insecure {
		q.Set("insecure", "1")
	}
	u := url.URL{
		Scheme:   "hysteria2",
		User:     url.User(c.User.Password(name)),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:     "/",
		RawQuery: q.Encode(),
		Fragment: protocol.LinkName(name, c.User),
	}
	return &config.ClientConfig{Protocol: name, URI: u.String()}, nil
}
