// Package ss2022 实现 Shadowsocks 2022（SIP022）协议的部署适配器，服务端使用 sing-box。
//
// Shadowsocks 没有 TLS 握手，网关无法按 SNI 分流，所以它直接监听一个单独的公网端口
// （TCP 和 UDP），不经过网关。客户端真实地址对 sing-box 可见。
package ss2022

import (
	"context"
	"encoding/base64"
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

const (
	name          = "ss2022"
	defaultMethod = "2022-blake3-aes-128-gcm"
)

// keyLengths 是各加密方式要求的密钥字节数
var keyLengths = map[string]int{
	"2022-blake3-aes-128-gcm":       16,
	"2022-blake3-aes-256-gcm":       32,
	"2022-blake3-chacha20-poly1305": 32,
}

type Adapter struct {
	layout *paths.Layout
}

func New(layout *paths.Layout) *Adapter {
	return &Adapter{layout: layout}
}

func (a *Adapter) Name() string                  { return name }
func (a *Adapter) Transport() protocol.Transport { return protocol.TransportBoth }
func (a *Adapter) ListenDirect() bool            { return true }
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
		return fmt.Errorf("config.method 只支持 2022-blake3-aes-128-gcm、2022-blake3-aes-256-gcm、2022-blake3-chacha20-poly1305")
	}
	key, err := base64.StdEncoding.DecodeString(protocol.StringOption(cfg, "password"))
	if err != nil || len(key) != n {
		return fmt.Errorf("config.password 必须是 %d 字节随机密钥的 base64 编码（%s；proxyd init-config 会生成）", n, m)
	}
	return nil
}

func (a *Adapter) GenerateConfig(cfg *config.ProtocolConfig, rt protocol.Runtime) ([]byte, error) {
	return singbox.Config(rt.ListenAddr, map[string]any{
		"type":     "shadowsocks",
		"tag":      name,
		"method":   method(cfg),
		"password": protocol.StringOption(cfg, "password"),
	})
}

func (a *Adapter) Service(cfg *config.ProtocolConfig, rt protocol.Runtime) (*protocol.Service, error) {
	return &protocol.Service{Args: singbox.Args(a.layout, a.ConfigPath())}, nil
}

// ClientConfig 返回 SIP002 格式的链接；按 SIP022，2022 加密方式的 userinfo 使用百分号编码而非 base64
func (a *Adapter) ClientConfig(cfg *config.ProtocolConfig, c protocol.ClientContext) (*config.ClientConfig, error) {
	u := url.URL{
		Scheme:   "ss",
		User:     url.UserPassword(method(cfg), protocol.StringOption(cfg, "password")),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Fragment: name,
	}
	return &config.ClientConfig{Protocol: name, URI: u.String()}, nil
}
