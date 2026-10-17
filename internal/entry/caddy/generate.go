// Package caddy 生成 Caddy（含本仓库的 proxy_gateway 网关）的 JSON 配置，并负责安装二进制。
//
// 入口职责：
//   - TCP 端口  网关按 TLS SNI 分流：协议后端由网关用统一证书终结 TLS 后转发，
//     其余流量原样交给内部 HTTPS 网站（附 PROXY protocol）
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

// TCPRoute 是 TCP 入口上的一条 SNI 路由。网关用统一证书终结 TLS 后把明文转发到 Upstream
type TCPRoute struct {
	Name     string // 路由名，用于网关日志和统计，即协议名
	SNI      string
	Upstream string
}

// TCPServer 是一个 TCP 入口端口。未匹配任何路由的流量交给内部网站
type TCPServer struct {
	Port   int
	Routes []TCPRoute
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
	// SitePlainAddr 是同一网站的明文 HTTP 监听地址（回环），供协议伪装反代使用，
	// 免去对内部 HTTPS 站点做证书校验
	SitePlainAddr string

	TCPServers []TCPServer
	Sites      []Site
}

type obj = map[string]any

// Generate 生成缩进格式的 Caddy JSON 配置
func Generate(s Spec) ([]byte, error) {
	apps := obj{
		"tls":           tlsApp(s),
		"proxy_gateway": gatewayApp(s),
		"http":          httpApp(s),
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

func gatewayApp(s Spec) obj {
	servers := obj{}
	for _, srv := range s.TCPServers {
		routes := []obj{}
		for _, r := range srv.Routes {
			routes = append(routes, obj{"name": r.Name, "sni": []string{r.SNI}, "tls": "terminate", "upstream": r.Upstream})
		}
		servers[fmt.Sprintf("tcp_%d", srv.Port)] = obj{
			"listen": []string{fmt.Sprintf(":%d", srv.Port)},
			"routes": routes,
			// 其余流量（网站、未知 SNI、非 TLS、ACME TLS-ALPN 验证）原样交给内部网站，
			// 用 PROXY protocol 带上客户端真实地址
			"fallback": obj{"name": "site", "tls": "passthrough", "upstream": s.SiteAddr, "proxy_protocol": true},
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
			// 先解析网关加上的 PROXY protocol 头再做 TLS，网站和反代后端看到的是客户端真实地址
			"listener_wrappers": []obj{
				{"wrapper": "proxy_protocol", "allow": []string{"127.0.0.1/32"}},
				{"wrapper": "tls"},
			},
			// 存在连接策略即启用 TLS；不带 SNI 的连接使用 DefaultSNI 的证书
			"tls_connection_policies": []obj{{"fallback_sni": s.DefaultSNI}},
			"routes":                  routes,
			"logs":                    obj{}, // 访问日志（含客户端真实地址）写入 Caddy 的 journal
		},
		"site_plain": obj{
			"listen":          []string{s.SitePlainAddr},
			"automatic_https": obj{"disable": true},
			"routes":          routes,
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
