// Package tuic 实现 TUIC v5 协议的部署适配器，服务端使用 sing-box。
//
// TUIC 运行在 QUIC/UDP 上，与 Hysteria2 等协议共享 UDP 入口端口，由网关按 QUIC SNI 转发。
// QUIC 由 sing-box 终结，证书使用 Caddy 统一管理的文件，续期后 sing-box 自动重新加载。
package tuic

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/internal/protocol/singbox"
	"github.com/jiayx/proxy-deploy/pkg/paths"
)

const (
	name = "tuic"
	alpn = "h3"
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	congestion  = map[string]bool{"bbr": true, "cubic": true, "new_reno": true}
)

type Adapter struct {
	layout *paths.Layout
}

func New(layout *paths.Layout) *Adapter {
	return &Adapter{layout: layout}
}

func (a *Adapter) Name() string                  { return name }
func (a *Adapter) Transport() protocol.Transport { return protocol.TransportUDP }
func (a *Adapter) NeedsCertificate() bool        { return true }
func (a *Adapter) ConfigPath() string {
	return filepath.Join(a.layout.ProtocolDir(name), "config.json")
}

func (a *Adapter) Install(ctx context.Context) error { return singbox.Install(ctx, a.layout) }

func (a *Adapter) CheckConfig(ctx context.Context, path string) error {
	return singbox.Check(ctx, a.layout, path)
}

func (a *Adapter) Validate(cfg *config.ProtocolConfig) error {
	if !uuidPattern.MatchString(protocol.StringOption(cfg, "uuid")) {
		return fmt.Errorf("config.uuid 必须是 UUID（proxyd init-config 会生成）")
	}
	if err := protocol.RequirePassword(cfg); err != nil {
		return err
	}
	if cc := protocol.StringOption(cfg, "congestion_control"); cc != "" && !congestion[cc] {
		return fmt.Errorf("config.congestion_control 只能是 bbr、cubic 或 new_reno")
	}
	return nil
}

func congestionControl(cfg *config.ProtocolConfig) string {
	if cc := protocol.StringOption(cfg, "congestion_control"); cc != "" {
		return cc
	}
	return "bbr"
}

func (a *Adapter) GenerateConfig(cfg *config.ProtocolConfig, rt protocol.Runtime) ([]byte, error) {
	if rt.Cert == nil {
		return nil, fmt.Errorf("tuic: certificate is required")
	}
	return singbox.Config(rt.ListenAddr, map[string]any{
		"type": "tuic",
		"tag":  name,
		"users": []any{map[string]any{
			"name":     "default",
			"uuid":     protocol.StringOption(cfg, "uuid"),
			"password": protocol.StringOption(cfg, "password"),
		}},
		"congestion_control": congestionControl(cfg),
		"tls": map[string]any{
			"enabled":          true,
			"alpn":             []string{alpn},
			"certificate_path": rt.Cert.CertPath,
			"key_path":         rt.Cert.KeyPath,
		},
	})
}

func (a *Adapter) Service(cfg *config.ProtocolConfig, rt protocol.Runtime) (*protocol.Service, error) {
	return &protocol.Service{Args: singbox.Args(a.layout, a.ConfigPath())}, nil
}

func (a *Adapter) ClientConfig(cfg *config.ProtocolConfig, c protocol.ClientContext) (*config.ClientConfig, error) {
	q := url.Values{}
	q.Set("sni", c.SNI)
	q.Set("alpn", alpn)
	q.Set("congestion_control", congestionControl(cfg))
	q.Set("udp_relay_mode", "native")
	if c.Insecure {
		q.Set("allow_insecure", "1") // 不同客户端分别使用 allow_insecure 和 insecure
		q.Set("insecure", "1")
	}
	u := url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(protocol.StringOption(cfg, "uuid"), protocol.StringOption(cfg, "password")),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return &config.ClientConfig{Protocol: name, URI: u.String()}, nil
}
