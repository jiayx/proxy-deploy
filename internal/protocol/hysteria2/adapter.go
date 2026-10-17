// Package hysteria2 实现 Hysteria 2 协议的部署适配器。
//
// Hysteria 2 运行在 QUIC/UDP 上：单独占用一个 UDP 端口时直接监听公网端口，
// 与其他 QUIC 协议共享端口时由 Caddy l4 按 QUIC SNI 转发到回环地址。
// 证书使用 Caddy 统一管理的文件，续期后由编排器自动重启。
package hysteria2

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

const (
	name    = "hysteria2"
	release = "app/v2.13.0"
)

// checksums 取自上游发布的 hashes.txt，按 GOOS/GOARCH 固定；升级版本时一并更新
var checksums = map[string]string{
	"linux/amd64": "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691",
	"linux/arm64": "a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7",
}

type Adapter struct {
	layout *paths.Layout
}

func New(layout *paths.Layout) *Adapter {
	return &Adapter{layout: layout}
}

func (a *Adapter) Name() string                  { return name }
func (a *Adapter) Transport() protocol.Transport { return protocol.TransportUDP }
func (a *Adapter) NeedsCertificate() bool        { return true }
func (a *Adapter) ConfigPath() string            { return a.layout.ProtocolConfig(name) }

func (a *Adapter) Validate(cfg *config.ProtocolConfig) error {
	return protocol.RequirePassword(cfg)
}

func (a *Adapter) Install(ctx context.Context) error {
	sum, ok := checksums[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return fmt.Errorf("hysteria2 %s 不支持 %s/%s", release, runtime.GOOS, runtime.GOARCH)
	}
	u := fmt.Sprintf("https://github.com/apernet/hysteria/releases/download/%s/hysteria-%s-%s",
		release, runtime.GOOS, runtime.GOARCH)
	return system.InstallVersioned(a.layout.VersionedBin(name, release), a.layout.ProtocolBin(name),
		func(dest string) error { return system.Download(ctx, u, sum, dest, 0755) })
}

type serverConfig struct {
	Listen string `yaml:"listen"`
	TLS    struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"tls"`
	Auth struct {
		Type     string `yaml:"type"`
		Password string `yaml:"password"`
	} `yaml:"auth"`
	Masquerade struct {
		Type  string `yaml:"type"`
		Proxy struct {
			URL         string `yaml:"url"`
			RewriteHost bool   `yaml:"rewriteHost"`
			Insecure    bool   `yaml:"insecure"`
		} `yaml:"proxy"`
	} `yaml:"masquerade"`
}

func (a *Adapter) GenerateConfig(cfg *config.ProtocolConfig, rt protocol.Runtime) ([]byte, error) {
	if rt.Cert == nil {
		return nil, fmt.Errorf("hysteria2: certificate is required")
	}
	var c serverConfig
	c.Listen = rt.ListenAddr
	c.TLS.Cert = rt.Cert.CertPath
	c.TLS.Key = rt.Cert.KeyPath
	c.Auth.Type = "password"
	c.Auth.Password = protocol.StringOption(cfg, "password")

	// 非 Hysteria 客户端（如浏览器的 HTTP/3 请求）看到的是伪装网站，默认就是本机部署的网站
	c.Masquerade.Type = "proxy"
	if u := protocol.StringOption(cfg, "masquerade_url"); u != "" {
		c.Masquerade.Proxy.URL = u
		c.Masquerade.Proxy.RewriteHost = true
	} else {
		c.Masquerade.Proxy.URL = rt.SiteURL
		c.Masquerade.Proxy.Insecure = true // 回环地址上的内部站点，证书名不匹配
	}
	return yaml.Marshal(&c)
}

func (a *Adapter) Service(cfg *config.ProtocolConfig, rt protocol.Runtime) (*protocol.Service, error) {
	return &protocol.Service{
		Args: []string{a.layout.ProtocolBin(name), "server", "-c", a.ConfigPath()},
		Env:  map[string]string{"HYSTERIA_DISABLE_UPDATE_CHECK": "1"},
	}, nil
}

func (a *Adapter) ClientConfig(cfg *config.ProtocolConfig, c protocol.ClientContext) (*config.ClientConfig, error) {
	q := url.Values{}
	q.Set("sni", c.SNI)
	if c.Insecure {
		q.Set("insecure", "1")
	}
	u := url.URL{
		Scheme:   "hysteria2",
		User:     url.User(protocol.StringOption(cfg, "password")),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:     "/",
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return &config.ClientConfig{Protocol: name, URI: u.String()}, nil
}
