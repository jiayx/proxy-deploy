package protocol

import (
	"context"
	"fmt"
	"sort"

	"github.com/jiayx/proxy-deploy/internal/config"
)

// Adapter 是每种代理协议的适配接口。
// 编排器负责端口规划、证书、systemd 和入口路由，适配器只描述协议本身：
// 怎么安装、配置文件长什么样、怎么启动、客户端怎么连。
type Adapter interface {
	// Name 返回协议标识符，与 deploy.yaml 中的 name 字段一致
	Name() string

	// Transport 返回传输层类型，决定入口如何规划
	Transport() Transport

	// Install 下载并安装协议二进制，幂等
	Install(ctx context.Context) error

	// GenerateConfig 生成配置文件内容；返回 nil 表示该协议不使用配置文件
	GenerateConfig(cfg *config.ProtocolConfig, rt Runtime) ([]byte, error)

	// ConfigPath 返回协议配置文件路径
	ConfigPath() string

	// Service 返回启动服务端的命令和环境变量
	Service(cfg *config.ProtocolConfig, rt Runtime) (*Service, error)

	// ClientConfig 返回供客户端连接用的配置信息
	ClientConfig(cfg *config.ProtocolConfig, c ClientContext) (*config.ClientConfig, error)
}

// Runtime 是编排器在规划后提供给适配器的运行信息
type Runtime struct {
	ListenAddr string              // 服务端应监听的地址
	SNI        string              // 客户端使用的 SNI
	Cert       *config.Certificate // 统一管理的证书；仅 CertConsumer 会拿到
	SiteURL    string              // 内部网站的明文 HTTP 地址（回环），可用于伪装或回落
}

// Service 描述一个服务端进程
type Service struct {
	// Args 第一个元素是可执行文件绝对路径。不要放敏感信息：
	// unit 文件是公开可读的，密码等应写在权限为 0600 的配置文件里
	Args []string
}

// Validator 由需要在规划阶段校验配置的协议实现
type Validator interface {
	Validate(cfg *config.ProtocolConfig) error
}

// ConfigChecker 由能在启动前校验配置文件的协议实现。
// 部署时先把配置写到临时路径 path 并校验，通过后才替换正式配置
type ConfigChecker interface {
	CheckConfig(ctx context.Context, path string) error
}

// TLSPassthrough 由自己处理 TLS 握手的 TCP 协议实现（例如 Reality）。
// 网关按 SNI 匹配后原样转发，不终结 TLS，也不为它的 SNI 申请证书
type TLSPassthrough interface {
	PassthroughTLS() bool
}

// LoopbackPorter 由经网关转发的协议实现，返回它的后端在回环地址上监听的固定端口。
// 每个协议的端口写死在适配器里且互不相同（builtin 包的测试会检查），
// 启用、停用、新增或删除其他协议都不会改变它，也就不会让它重启
type LoopbackPorter interface {
	LoopbackPort() int
}

// DedicatedPort 由没有 SNI、网关无法分流的协议实现（没有 TLS，例如 Shadowsocks）：
// 协议需要独占一个公网端口，网关在这个端口上不做识别，把全部连接转给它（TCP 和 UDP）
type DedicatedPort interface {
	NeedsDedicatedPort() bool
}

// SNIDefaulter 由默认 SNI 不是 <name>.<domain> 的协议实现，例如 Reality 使用伪装目标网站的域名
type SNIDefaulter interface {
	DefaultSNI() string
}

// CertConsumer 由需要读取证书文件的协议实现。
// 编排器会等证书签发后再启动它；续期后的重新加载由协议程序自己负责。
type CertConsumer interface {
	NeedsCertificate() bool
}

// ClientContext 是客户端连接所需的入口信息，由编排器根据端口规划提供
type ClientContext struct {
	Host     string // 客户端连接的服务器地址
	Port     int    // 公网端口
	SNI      string
	Insecure bool // 证书不被公共 CA 信任（例如 Caddy 内部 CA）
}

// Transport 表示协议使用的传输层
type Transport int

const (
	TransportTCP  Transport = iota // TCP，可共享入口端口，由 Caddy l4 按 SNI 转发
	TransportUDP                   // UDP/QUIC，单独占用端口，或同端口按 QUIC SNI 分流
	TransportBoth                  // 同时监听 TCP 和 UDP
)

func (t Transport) String() string {
	switch t {
	case TransportTCP:
		return "tcp"
	case TransportUDP:
		return "udp"
	case TransportBoth:
		return "tcp+udp"
	}
	return "unknown"
}

// RequirePassword 校验 config.password 已填写，且不是示例里的占位值
func RequirePassword(cfg *config.ProtocolConfig) error {
	switch StringOption(cfg, "password") {
	case "":
		return fmt.Errorf("config.password is required")
	case "change-me":
		return fmt.Errorf("config.password 仍是占位值 change-me")
	}
	return nil
}

// StringOption 读取协议配置中的字符串选项
func StringOption(cfg *config.ProtocolConfig, key string) string {
	s, _ := cfg.Config[key].(string)
	return s
}

// Registry 管理所有已注册的协议适配器
type Registry struct {
	adapters map[string]Adapter
}

func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

func (r *Registry) Register(a Adapter) {
	r.adapters[a.Name()] = a
}

func (r *Registry) Get(name string) (Adapter, bool) {
	a, ok := r.adapters[name]
	return a, ok
}

// Names 返回已注册的协议名，按字母序
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.adapters))
	for n := range r.adapters {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
