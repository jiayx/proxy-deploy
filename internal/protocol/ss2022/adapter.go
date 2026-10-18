// Package ss2022 实现 Shadowsocks 2022（SIP022）协议的部署适配器，服务端使用 sing-box。
//
// Shadowsocks 没有 TLS 握手，网关无法按 SNI 分流，所以它独占一个公网端口（TCP 和 UDP）：
// 网关在这个端口上不做识别，把全部连接转给回环地址上的 sing-box，流量照样计入网关统计。
package ss2022

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/jiayx/proxy-gateway/internal/config"
	"github.com/jiayx/proxy-gateway/internal/protocol"
	"github.com/jiayx/proxy-gateway/internal/protocol/singbox"
	"github.com/jiayx/proxy-gateway/pkg/paths"
)

const (
	name          = "ss2022"
	defaultMethod = "2022-blake3-aes-128-gcm"
)

// keyLengths 是各加密方式要求的密钥字节数。多用户（SIP022 的 EIH）只支持 AES，
// 所以不提供 2022-blake3-chacha20-poly1305
var keyLengths = map[string]int{
	"2022-blake3-aes-128-gcm": 16,
	"2022-blake3-aes-256-gcm": 32,
}

type Adapter struct {
	layout *paths.Layout
}

func New(layout *paths.Layout) *Adapter {
	return &Adapter{layout: layout}
}

func (a *Adapter) Name() string                  { return name }
func (a *Adapter) Transport() protocol.Transport { return protocol.TransportBoth }
func (a *Adapter) Options() []string             { return []string{"method", "password"} }
func (a *Adapter) NeedsDedicatedPort() bool      { return true }
func (a *Adapter) LoopbackPort() int             { return 20006 }
func (a *Adapter) ConfigPath() string {
	return filepath.Join(a.layout.ProtocolDir(name), "config.json")
}

func (a *Adapter) Install(ctx context.Context) error { return singbox.Install(ctx, a.layout) }

func (a *Adapter) CheckConfig(ctx context.Context, path string) error {
	return singbox.Check(ctx, a.layout, path)
}

func method(cfg *config.ProtocolConfig) string {
	if m := protocol.StringOption(cfg, "method"); m != "" {
		return m
	}
	return defaultMethod
}

func (a *Adapter) Validate(cfg *config.ProtocolConfig) error {
	m := method(cfg)
	n, ok := keyLengths[m]
	if !ok {
		return fmt.Errorf("method 只支持 2022-blake3-aes-128-gcm、2022-blake3-aes-256-gcm（多用户不支持 chacha20）")
	}
	key, err := base64.StdEncoding.DecodeString(protocol.StringOption(cfg, "password"))
	if err != nil || len(key) != n {
		return fmt.Errorf("password（服务端密钥）必须是 %d 字节随机密钥的 base64 编码（%s；proxy-gateway init-config 会生成）", n, m)
	}
	return nil
}

// userKey 返回用户的密钥，长度与服务端密钥相同
func userKey(cfg *config.ProtocolConfig, u protocol.User) string {
	return u.Key(name, keyLengths[method(cfg)])
}

// GenerateConfig 使用多用户格式：password 是服务端密钥，每个用户另有自己的密钥
func (a *Adapter) GenerateConfig(cfg *config.ProtocolConfig, rt protocol.Runtime) ([]byte, error) {
	var users []any
	for _, u := range rt.Users {
		users = append(users, map[string]any{"name": u.Name, "password": userKey(cfg, u)})
	}
	return singbox.Config(rt.ListenAddr, map[string]any{
		"type":     "shadowsocks",
		"tag":      name,
		"method":   method(cfg),
		"password": protocol.StringOption(cfg, "password"),
		"users":    users,
	})
}

func (a *Adapter) Service(cfg *config.ProtocolConfig, rt protocol.Runtime) (*protocol.Service, error) {
	return &protocol.Service{Args: singbox.Args(a.layout, a.ConfigPath())}, nil
}

// ClientConfig 返回 SIP002 格式的链接；按 SIP022，2022 加密方式的 userinfo 使用百分号编码而非 base64，
// 多用户时客户端密码为 "服务端密钥:用户密钥"
func (a *Adapter) ClientConfig(cfg *config.ProtocolConfig, c protocol.ClientContext) (*config.ClientConfig, error) {
	u := url.URL{
		Scheme:   "ss",
		User:     url.UserPassword(method(cfg), protocol.StringOption(cfg, "password")+":"+userKey(cfg, c.User)),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Fragment: protocol.LinkName(name, c.User),
	}
	return &config.ClientConfig{Protocol: name, URI: u.String()}, nil
}
