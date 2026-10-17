package config

// DeployConfig 是整个部署的配置（deploy.yaml）
type DeployConfig struct {
	Domain       string            `yaml:"domain"`
	Server       ServerConfig      `yaml:"server"`
	Certificates CertificateConfig `yaml:"certificates"`
	Entry        EntryConfig       `yaml:"entry"`
	Users        []UserConfig      `yaml:"users"`
	Protocols    []ProtocolConfig  `yaml:"protocols"`
	Web          []WebConfig       `yaml:"web"`
}

// ServerConfig 服务器信息
type ServerConfig struct {
	// Address 是客户端连接时使用的地址，默认等于 domain
	Address string `yaml:"address,omitempty"`
}

// CertificateConfig 证书配置
type CertificateConfig struct {
	Provider    string            `yaml:"provider"` // letsencrypt | acme | internal
	Email       string            `yaml:"email,omitempty"`
	CA          string            `yaml:"ca,omitempty"` // provider=acme 时的 ACME directory URL
	DNSProvider string            `yaml:"dns_provider,omitempty"`
	DNSConfig   map[string]string `yaml:"dns_config,omitempty"`
}

// EntryConfig 公网入口配置
type EntryConfig struct {
	HTTPSPort int `yaml:"https_port,omitempty"`
	HTTPPort  int `yaml:"http_port,omitempty"`
}

// UserConfig 是一个用户。各协议的密码、UUID、密钥都由 Secret 推导，更换 Secret 即作废旧凭据
type UserConfig struct {
	Name   string `yaml:"name"`
	Secret string `yaml:"secret"`
}

// ProtocolConfig 协议配置
type ProtocolConfig struct {
	Name    string         `yaml:"name"`
	Enabled bool           `yaml:"enabled"`
	Port    int            `yaml:"port,omitempty"` // 公网端口，默认 entry.https_port
	SNI     string         `yaml:"sni,omitempty"`  // 默认 <name>.<domain>
	Config  map[string]any `yaml:"config"`         // 协议特定配置
}

// WebConfig 网站配置
type WebConfig struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`               // static | reverse_proxy
	Host     string `yaml:"host,omitempty"`     // 为空表示兜底站点
	Root     string `yaml:"root,omitempty"`     // static
	Upstream string `yaml:"upstream,omitempty"` // reverse_proxy，如 127.0.0.1:3000
}

// Certificate 是某个域名证书在磁盘上的位置
type Certificate struct {
	Name     string
	CertPath string
	KeyPath  string
}

// ClientConfig 客户端连接信息
type ClientConfig struct {
	User     string
	Protocol string
	URI      string
	Notes    []string
}
