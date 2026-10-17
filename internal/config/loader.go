package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/jiayx/proxy-deploy/pkg/secrets"
)

// Load 从文件路径加载 deploy.yaml 并填充默认值
func Load(path string) (*DeployConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg DeployConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // 拼错的字段名直接报错，而不是悄悄使用默认值
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate 检查配置基本合法性并填充默认值
func (c *DeployConfig) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if c.Server.Address == "" {
		c.Server.Address = c.Domain
	}

	switch c.Certificates.Provider {
	case "":
		c.Certificates.Provider = "letsencrypt"
		fallthrough
	case "letsencrypt", "acme":
		if c.Certificates.Email == "" {
			return fmt.Errorf("certificates.email is required for provider %q", c.Certificates.Provider)
		}
		if c.Certificates.Provider == "acme" && c.Certificates.CA == "" {
			return fmt.Errorf("certificates.ca is required for provider acme")
		}
	case "internal":
	default:
		return fmt.Errorf("certificates.provider: unknown provider %q (letsencrypt, acme, internal)", c.Certificates.Provider)
	}

	if c.Entry.HTTPSPort == 0 {
		c.Entry.HTTPSPort = 443
	}
	if c.Entry.HTTPPort == 0 {
		c.Entry.HTTPPort = 80
	}

	for name, port := range map[string]int{"entry.https_port": c.Entry.HTTPSPort, "entry.http_port": c.Entry.HTTPPort} {
		if port < 1 || port > 65535 {
			return fmt.Errorf("%s: invalid port %d", name, port)
		}
	}

	seen := map[string]bool{}
	for i, p := range c.Protocols {
		if p.Name == "" {
			return fmt.Errorf("protocols[%d]: name is required", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("protocols[%d]: duplicate protocol %q (each protocol can be configured once)", i, p.Name)
		}
		seen[p.Name] = true
		if p.Port < 0 || p.Port > 65535 {
			return fmt.Errorf("protocols[%d]: invalid port %d", i, p.Port)
		}
	}
	for i, w := range c.Web {
		switch w.Type {
		case "static":
		case "reverse_proxy":
			if w.Upstream == "" {
				return fmt.Errorf("web[%d]: upstream is required for reverse_proxy", i)
			}
		default:
			return fmt.Errorf("web[%d]: unknown type %q (static, reverse_proxy)", i, w.Type)
		}
	}
	return nil
}

// Example 返回一个带注释的示例配置，协议凭据随机生成
func Example() string {
	privateKey, _ := secrets.RealityKeyPair()
	return fmt.Sprintf(exampleTemplate, secrets.Password(), secrets.Password(), secrets.UUID(), privateKey, secrets.ShortID())
}

const exampleTemplate = `# proxy-deploy 配置示例
domain: example.com

server:
  address: example.com      # 客户端连接的地址，默认等于 domain

certificates:
  provider: letsencrypt     # letsencrypt | acme | internal（自签，测试用）
  email: admin@example.com

entry:
  https_port: 443           # TCP 入口，Caddy l4 按 SNI 分流
  http_port: 80             # HTTP 跳转与 ACME HTTP-01 验证

protocols:
  - name: hysteria2         # UDP/QUIC，默认使用 UDP/<https_port>
    enabled: true
    # sni: hysteria2.example.com   # 默认 <name>.<domain>，需要解析到本机
    config:
      password: "%s"

  - name: anytls            # TCP，与网站共享 TCP/<https_port>，按 SNI 分流
    enabled: true
    config:
      password: "%s"

  - name: vless-reality     # TCP，与网站共享 TCP/<https_port>；网关按 SNI 原样透传，Reality 自己握手
    enabled: false
    # sni: www.microsoft.com       # 伪装目标网站，默认 www.microsoft.com；建议换成离服务器近、支持 TLS 1.3 的网站
    config:
      uuid: "%s"
      private_key: "%s"     # 公钥由它推导，客户端链接里会给出
      short_id: "%s"
      # handshake: www.microsoft.com:443   # 伪装握手的目标，默认是 sni 的 443 端口

web:
  - name: site
    type: static            # 不填 root 时使用安装目录下的 www
`
