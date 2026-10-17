package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load 从文件路径加载 deploy.yaml 并填充默认值
func Load(path string) (*DeployConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg DeployConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
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

	for i, p := range c.Protocols {
		if p.Name == "" {
			return fmt.Errorf("protocols[%d]: name is required", i)
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

// Example 返回一个带注释的示例配置
func Example() string {
	return `# proxy-deploy 配置示例
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
      password: change-me

  - name: anytls            # TCP，与网站共享 TCP/<https_port>，按 SNI 分流
    enabled: true
    config:
      password: change-me

web:
  - name: site
    type: static            # 不填 root 时使用安装目录下的 www
`
}
