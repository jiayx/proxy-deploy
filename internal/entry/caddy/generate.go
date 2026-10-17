// Package caddy 生成 Caddy（含 caddy-l4 插件）的 JSON 配置，并负责安装二进制。
//
// 入口职责：
//   - TCP 端口  l4 按 TLS SNI 分流：协议后端由 Caddy 用统一证书终结 TLS 后转发，
//     其余流量原样交给内部 HTTPS 网站
//   - UDP 端口  多个 QUIC 协议共享端口时，l4 按 QUIC SNI 分流
//   - HTTP 端口 跳转到 HTTPS，同时承担 ACME HTTP-01 验证
//   - 证书由 Caddy 统一申请、续期，存放在安装目录下
package caddy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Issuer 描述证书签发方式
type Issuer struct {
	Kind        string // internal | acme
	Email       string
	CA          string // 空表示 Let's Encrypt
	DNSProvider string
	DNSConfig   map[string]string
}

const letsEncryptCA = "https://acme-v02.api.letsencrypt.org/directory"

// storageKey 与 certmagic 的 issuer key 一致，决定证书在存储目录中的子目录
func (i Issuer) storageKey() string {
	if i.Kind == "internal" {
		return "local"
	}
	ca := i.CA
	if ca == "" {
		ca = letsEncryptCA
	}
	ca = strings.TrimPrefix(strings.TrimPrefix(ca, "https://"), "http://")
	return strings.ReplaceAll(ca, "/", "-")
}

// CertPaths 返回 Caddy 为 name 管理的证书和私钥路径
func CertPaths(storageRoot string, iss Issuer, name string) (crt, key string) {
	dir := fmt.Sprintf("%s/certificates/%s/%s", storageRoot, iss.storageKey(), name)
	return dir + "/" + name + ".crt", dir + "/" + name + ".key"
}

// TCPRoute 是 TCP 入口上的一条 SNI 路由。Caddy 用统一证书终结 TLS 后转发到 Upstream
type TCPRoute struct {
	SNI      string
	Upstream string
	// ReencryptUpstream 表示后端自身要求 TLS（例如 anytls-go），Caddy 以 TLS 连接后端
	ReencryptUpstream bool
}

// TCPServer 是一个 TCP 入口端口。未匹配任何路由的流量交给内部网站
type TCPServer struct {
	Port   int
	Routes []TCPRoute
}

// UDPRoute 是共享 UDP 端口上的一条 QUIC SNI 路由
type UDPRoute struct {
	SNI      string
	Upstream string
}

// UDPServer 是一个由多个 QUIC 协议共享的 UDP 端口
type UDPServer struct {
	Port   int
	Routes []UDPRoute
}

// Site 是一个网站：静态目录或反向代理
type Site struct {
	Host     string // 空表示兜底
	Root     string
	Upstream string
}

// Spec 是生成 Caddy 配置所需的全部信息
type Spec struct {
	AdminSocket string
	StorageRoot string
	Issuer      Issuer
	CertNames   []string // 需要 Caddy 申请并维护的全部证书域名
	DefaultSNI  string   // 客户端不带 SNI 时使用的证书

	HTTPSPort int    // 主入口端口，用于 HTTP 跳转
	HTTPPort  int    // HTTP 入口端口
	SiteAddr  string // 内部 HTTPS 网站监听地址，如 127.0.0.1:20000

	TCPServers []TCPServer
	UDPServers []UDPServer
	Sites      []Site
}

type obj = map[string]any

// Generate 生成缩进格式的 Caddy JSON 配置
func Generate(s Spec) ([]byte, error) {
	apps := obj{
		"tls":    tlsApp(s),
		"layer4": layer4App(s),
		"http":   httpApp(s),
	}
	if s.Issuer.Kind == "internal" {
		// 不尝试把内部根证书装进系统信任库（需要 root，也不是部署工具该有的副作用）
		apps["pki"] = obj{"certificate_authorities": obj{"local": obj{"install_trust": false}}}
	}
	root := obj{
		"admin": obj{
			"listen": "unix/" + s.AdminSocket,
			"config": obj{"persist": false},
		},
		"storage": obj{"module": "file_system", "root": s.StorageRoot},
		"logging": obj{"logs": obj{"default": obj{"level": "INFO"}}},
		"apps":    apps,
	}
	return json.MarshalIndent(root, "", "  ")
}

func tlsApp(s Spec) obj {
	var issuer obj
	switch s.Issuer.Kind {
	case "internal":
		issuer = obj{"module": "internal"}
	default:
		issuer = obj{"module": "acme"}
		if s.Issuer.Email != "" {
			issuer["email"] = s.Issuer.Email
		}
		if s.Issuer.CA != "" {
			issuer["ca"] = s.Issuer.CA
		}
		if s.Issuer.DNSProvider != "" {
			provider := obj{"name": s.Issuer.DNSProvider}
			for k, v := range s.Issuer.DNSConfig {
				provider[k] = v
			}
			issuer["challenges"] = obj{"dns": obj{"provider": provider}}
		}
	}
	return obj{
		// automate 让 Caddy 主动申请并续期这些证书，不依赖 HTTP 站点推导
		"certificates": obj{"automate": s.CertNames},
		"automation": obj{
			"policies": []obj{{"subjects": s.CertNames, "issuers": []obj{issuer}}},
		},
	}
}

func layer4App(s Spec) obj {
	servers := obj{}

	for _, srv := range s.TCPServers {
		var routes []obj
		for _, r := range srv.Routes {
			upstream := obj{"dial": []string{r.Upstream}}
			if r.ReencryptUpstream {
				// 后端使用自签证书，只在回环地址上连接，跳过校验
				upstream["tls"] = obj{"insecure_skip_verify": true}
			}
			routes = append(routes, obj{
				"match": []obj{{"tls": obj{"sni": []string{r.SNI}}}},
				"handle": []obj{
					{"handler": "tls"},
					{"handler": "proxy", "upstreams": []obj{upstream}},
				},
			})
		}
		// 其余流量（网站、未知 SNI、ACME TLS-ALPN 验证）原样交给内部网站
		routes = append(routes, obj{
			"handle": []obj{{"handler": "proxy", "upstreams": []obj{{"dial": []string{s.SiteAddr}}}}},
		})
		servers[fmt.Sprintf("tcp_%d", srv.Port)] = obj{
			"listen": []string{fmt.Sprintf(":%d", srv.Port)},
			"routes": routes,
		}
	}

	for _, srv := range s.UDPServers {
		var routes []obj
		for _, r := range srv.Routes {
			routes = append(routes, obj{
				"match":  []obj{{"quic": obj{"sni": []string{r.SNI}}}},
				"handle": []obj{{"handler": "proxy", "upstreams": []obj{{"dial": []string{"udp/" + r.Upstream}}}}},
			})
		}
		servers[fmt.Sprintf("udp_%d", srv.Port)] = obj{
			"listen": []string{fmt.Sprintf("udp/:%d", srv.Port)},
			"routes": routes,
		}
	}

	return obj{"servers": servers}
}

func httpApp(s Spec) obj {
	var routes []obj
	var fallback obj
	for _, site := range s.Sites {
		var handler obj
		if site.Upstream != "" {
			handler = obj{"handler": "reverse_proxy", "upstreams": []obj{{"dial": site.Upstream}}}
		} else {
			handler = obj{"handler": "file_server", "root": site.Root}
		}
		route := obj{"handle": []obj{handler}, "terminal": true}
		if site.Host == "" {
			fallback = route
			continue
		}
		route["match"] = []obj{{"host": []string{site.Host}}}
		routes = append(routes, route)
	}
	if fallback != nil {
		routes = append(routes, fallback)
	}

	location := "https://{http.request.host}{http.request.uri}"
	if s.HTTPSPort != 443 {
		location = fmt.Sprintf("https://{http.request.host}:%d{http.request.uri}", s.HTTPSPort)
	}

	return obj{"servers": obj{
		// 内部 HTTPS 网站：只监听回环地址，由 l4 入口转发过来
		"site": obj{
			"listen":          []string{s.SiteAddr},
			"protocols":       []string{"h1", "h2"},
			"automatic_https": obj{"disable": true},
			// 存在连接策略即启用 TLS；不带 SNI 的连接使用 DefaultSNI 的证书
			"tls_connection_policies": []obj{{"fallback_sni": s.DefaultSNI}},
			"routes":                  routes,
		},
		"redirect": obj{
			"listen":          []string{fmt.Sprintf(":%d", s.HTTPPort)},
			"automatic_https": obj{"disable": true},
			"routes": []obj{{"handle": []obj{{
				"handler":     "static_response",
				"status_code": 308,
				"headers":     obj{"Location": []string{location}},
			}}}},
		},
	}}
}
