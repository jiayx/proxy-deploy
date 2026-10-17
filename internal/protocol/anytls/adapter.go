// Package anytls 实现 AnyTLS 协议的部署适配器。
//
// AnyTLS 是 TCP 协议，与网站共享 TCP 入口端口，由 Caddy l4 按 SNI 分流。
// anytls-go 服务端自身强制 TLS（启动时生成自签证书，不能指定证书），
// 所以 Caddy 用统一管理的证书终结客户端 TLS，再以 TLS 连接回环地址上的 anytls-server。
// 客户端看到的始终是 Caddy 签发的证书。
package anytls

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strconv"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

const (
	name    = "anytls"
	version = "0.0.13"
)

type Adapter struct {
	layout *paths.Layout
}

func New(layout *paths.Layout) *Adapter {
	return &Adapter{layout: layout}
}

func (a *Adapter) Name() string                  { return name }
func (a *Adapter) Transport() protocol.Transport { return protocol.TransportTCP }
func (a *Adapter) BackendTLS() bool              { return true }

// ConfigPath: anytls-server 只接受命令行参数，没有配置文件
func (a *Adapter) ConfigPath() string { return "" }

func (a *Adapter) Validate(cfg *config.ProtocolConfig) error {
	if protocol.StringOption(cfg, "password") == "" {
		return fmt.Errorf("config.password is required")
	}
	return nil
}

func (a *Adapter) Install(ctx context.Context) error {
	u := fmt.Sprintf("https://github.com/anytls/anytls-go/releases/download/v%s/anytls_%s_%s_%s.zip",
		version, version, runtime.GOOS, runtime.GOARCH)
	return system.InstallVersioned(a.layout.VersionedBin(name, version), a.layout.ProtocolBin(name),
		func(dest string) error { return system.DownloadAndExtract(ctx, u, "anytls-server", dest, 0755) })
}

func (a *Adapter) GenerateConfig(cfg *config.ProtocolConfig, rt protocol.Runtime) ([]byte, error) {
	return nil, nil
}

func (a *Adapter) Service(cfg *config.ProtocolConfig, rt protocol.Runtime) (*protocol.Service, error) {
	args := []string{a.layout.ProtocolBin(name), "-l", rt.ListenAddr, "-p", protocol.EnvRef("ANYTLS_PASSWORD")}
	if s := protocol.StringOption(cfg, "padding_scheme"); s != "" {
		args = append(args, "-padding-scheme", s)
	}
	return &protocol.Service{
		Args: args,
		Env:  map[string]string{"ANYTLS_PASSWORD": protocol.StringOption(cfg, "password")},
	}, nil
}

func (a *Adapter) ClientConfig(cfg *config.ProtocolConfig, c protocol.ClientContext) (*config.ClientConfig, error) {
	q := url.Values{}
	q.Set("sni", c.SNI)
	if c.Insecure {
		q.Set("insecure", "1")
	}
	u := url.URL{
		Scheme:   "anytls",
		User:     url.User(protocol.StringOption(cfg, "password")),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:     "/",
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return &config.ClientConfig{Protocol: name, URI: u.String()}, nil
}
