// Package anytls 实现 AnyTLS 协议的部署适配器，服务端使用 sing-box。
//
// AnyTLS 是 TCP 协议，与网站共享 TCP 入口端口，由 Caddy l4 按 SNI 分流。
// Caddy 用统一管理的证书终结客户端 TLS，再把明文转发到回环地址上的 sing-box anytls inbound，
// 所以 inbound 本身不配置 TLS。
// （anytls-go 是协议的参考实现，定位为演示，且服务端强制使用自签 TLS，不适合这种部署方式。）
package anytls

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/internal/protocol/singbox"
	"github.com/jiayx/proxy-deploy/pkg/paths"
)

const name = "anytls"

type Adapter struct {
	layout *paths.Layout
}

func New(layout *paths.Layout) *Adapter {
	return &Adapter{layout: layout}
}

func (a *Adapter) Name() string                  { return name }
func (a *Adapter) LoopbackPort() int             { return 20003 }
func (a *Adapter) Transport() protocol.Transport { return protocol.TransportTCP }
func (a *Adapter) Options() []string             { return []string{"padding_scheme"} }
func (a *Adapter) ConfigPath() string {
	return filepath.Join(a.layout.ProtocolDir(name), "config.json")
}

func (a *Adapter) Validate(cfg *config.ProtocolConfig) error {
	_, err := paddingScheme(cfg)
	return err
}

// paddingScheme 读取可选的 padding_scheme：多行字符串或字符串列表，每行一条规则
func paddingScheme(cfg *config.ProtocolConfig) ([]string, error) {
	switch v := cfg.Options["padding_scheme"].(type) {
	case nil:
		return nil, nil
	case string:
		return strings.Fields(v), nil
	case []any:
		lines := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("padding_scheme 只能包含字符串")
			}
			lines = append(lines, s)
		}
		return lines, nil
	}
	return nil, fmt.Errorf("padding_scheme 应为字符串或字符串列表")
}

func (a *Adapter) Install(ctx context.Context) error { return singbox.Install(ctx, a.layout) }

func (a *Adapter) CheckConfig(ctx context.Context, path string) error {
	return singbox.Check(ctx, a.layout, path)
}

func (a *Adapter) GenerateConfig(cfg *config.ProtocolConfig, rt protocol.Runtime) ([]byte, error) {
	var users []any
	for _, u := range rt.Users {
		users = append(users, map[string]any{"name": u.Name, "password": u.Password(name)})
	}
	inbound := map[string]any{"type": "anytls", "tag": name, "users": users}
	scheme, err := paddingScheme(cfg)
	if err != nil {
		return nil, err
	}
	if len(scheme) > 0 {
		inbound["padding_scheme"] = scheme
	}
	return singbox.Config(rt.ListenAddr, inbound)
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
		Scheme:   "anytls",
		User:     url.User(c.User.Password(name)),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:     "/",
		RawQuery: q.Encode(),
		Fragment: protocol.LinkName(name, c.User),
	}
	return &config.ClientConfig{Protocol: name, URI: u.String()}, nil
}
