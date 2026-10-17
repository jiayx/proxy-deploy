package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jiayx/proxy-deploy/pkg/secrets"
)

var (
	userNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	sizePattern     = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([KMGT]i?B|B)?$`)
	sizeUnits       = map[string]float64{"": 1, "B": 1,
		"KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
		"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}
)

// ParseSize 解析流量大小，如 500GB（十进制）、200GiB（二进制）；空字符串为 0
func ParseSize(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	m := sizePattern.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("%q is not a size like 200GiB or 500GB", s)
	}
	n, _ := strconv.ParseFloat(m[1], 64)
	return int64(n * sizeUnits[m[2]]), nil
}

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

	if len(c.Users) == 0 {
		return fmt.Errorf("users: at least one user is required (proxyd init-config generates one)")
	}
	names, secrets := map[string]bool{}, map[string]bool{}
	for i, u := range c.Users {
		if !userNamePattern.MatchString(u.Name) {
			return fmt.Errorf("users[%d]: name %q must be 1-32 letters, digits, '-' or '_'", i, u.Name)
		}
		if len(u.Secret) < 16 {
			return fmt.Errorf("users[%d] %s: secret must be at least 16 characters", i, u.Name)
		}
		if names[u.Name] || secrets[u.Secret] {
			return fmt.Errorf("users[%d] %s: duplicate name or secret", i, u.Name)
		}
		if _, err := ParseSize(u.TrafficLimit); err != nil {
			return fmt.Errorf("users[%d] %s: traffic_limit: %w", i, u.Name, err)
		}
		if u.ResetDay < 0 || u.ResetDay > 28 {
			return fmt.Errorf("users[%d] %s: reset_day must be between 1 and 28", i, u.Name)
		}
		if u.Expire != "" {
			if _, err := time.Parse(time.DateOnly, u.Expire); err != nil {
				return fmt.Errorf("users[%d] %s: expire must be a date like 2027-01-31", i, u.Name)
			}
		}
		names[u.Name], secrets[u.Secret] = true, true
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
	return fmt.Sprintf(exampleTemplate, secrets.Password(), privateKey, secrets.ShortID(), secrets.Key(16))
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

# 用户：各协议的密码、UUID、密钥都由 secret 推导，客户端链接按用户输出（proxyd client-config <用户>）
users:
  - name: default
    secret: "%s"          # 更换即作废该用户的全部旧凭据
    # traffic_limit: 200GiB    # 每个周期的流量上限（上下行合计），不填不限
    # reset_day: 1             # 每月几号重置流量（1-28），默认 1
    # expire: 2027-01-31       # 到期日，当天结束前可用，不填不过期

protocols:
  - name: hysteria2         # UDP/QUIC，默认使用 UDP/<https_port>
    enabled: true
    # sni: hysteria2.example.com   # 默认 <name>.<domain>，需要解析到本机

  - name: anytls            # TCP，与网站共享 TCP/<https_port>，按 SNI 分流
    enabled: true

  - name: vless-reality     # TCP，与网站共享 TCP/<https_port>；网关按 SNI 原样透传，Reality 自己握手
    enabled: false
    # sni: www.microsoft.com       # 伪装目标网站，默认 www.microsoft.com；建议换成离服务器近、支持 TLS 1.3 的网站
    config:
      private_key: "%s"     # 公钥由它推导，客户端链接里会给出
      short_id: "%s"
      # handshake: www.microsoft.com:443   # 伪装握手的目标，默认是 sni 的 443 端口

  - name: tuic              # UDP/QUIC，与 hysteria2 共享 UDP/<https_port>，网关按 QUIC SNI 分流
    enabled: false
    # config:
    #   congestion_control: bbr        # bbr | cubic | new_reno

  - name: ss2022            # Shadowsocks 2022，没有 TLS，独占单独的端口（TCP 和 UDP，网关不识别直接转发）
    enabled: false
    port: 8388              # 必填，不能与入口端口相同；需在防火墙放行 TCP 和 UDP
    config:
      # method: 2022-blake3-aes-128-gcm   # 或 2022-blake3-aes-256-gcm（密钥 32 字节）
      password: "%s"        # 服务端密钥；每个用户另有由 secret 推导的密钥

web:
  - name: site
    type: static            # 不填 root 时使用安装目录下的 www
`
