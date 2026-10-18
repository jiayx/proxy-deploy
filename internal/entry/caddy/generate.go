// Package caddy 生成 Caddy（含本仓库的 proxy_gateway 网关）的 JSON 配置，并负责安装二进制。
//
// 入口职责：
//   - TCP 端口  网关按 TLS SNI 分流：协议后端由网关用统一证书终结 TLS 后转发，
//     其余流量原样交给内部 HTTPS 网站（附 PROXY protocol）
//   - UDP 端口  网关按 QUIC SNI 分流：协议的 QUIC 连接原样转给后端，
//     主入口端口上的其余 QUIC 连接交给内部网站的 HTTP/3
//   - HTTP 端口 跳转到 HTTPS，同时承担 ACME HTTP-01 验证
//   - 证书由 Caddy 统一申请、续期，存放在安装目录下
package caddy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
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

// TCPRoute 是 TCP 入口上的一条 SNI 路由。网关用统一证书终结 TLS 后把明文转发到 Upstream；
// Passthrough 时原样转发，由后端自己处理 TLS（例如 Reality）
type TCPRoute struct {
	Name        string // 路由名，用于网关日志和统计，即协议名
	SNI         string
	Upstream    string
	Passthrough bool
}

// TCPServer 是一个 TCP 入口端口。未匹配任何路由的流量交给内部网站
type TCPServer struct {
	Port   int
	Routes []TCPRoute
}

// UDPRoute 是 UDP 入口上的一条 QUIC SNI 路由，数据报原样转发（QUIC 由后端终结）
type UDPRoute struct {
	Name     string
	SNI      string
	Upstream string
}

// UDPServer 是一个 UDP 入口端口。HTTPSPort 上未匹配任何路由的连接交给内部网站的 HTTP/3，
// 其他端口上的直接丢弃
type UDPServer struct {
	Port   int
	Routes []UDPRoute
}

// RawServer 是专属于一个协议的入口端口：网关不做识别，全部连接转给 Upstream
type RawServer struct {
	Name     string // 路由名，即协议名
	Port     int
	Network  string // tcp | udp
	Upstream string
}

// UserPolicy 是一个用户的流量上限、到期和可用协议设置
type UserPolicy struct {
	Name         string
	TrafficLimit int64     // 每个周期的上限（字节），0 表示不限
	ResetDay     int       // 每月重置日，0 表示默认（1 号）
	Expire       time.Time // 到期时刻，零值表示不过期
	Protocols    []string  // 可以使用的协议，为空表示全部
}

// Backend 是由网关启动并监管的协议后端进程
type Backend struct {
	Name         string
	Command      []string
	RequireFiles []string // 都存在后才启动，例如协议读取的证书
	Revision     string   // 配置版本，变化时网关重启进程
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
	UsageFile   string // 网关按用户累计的流量
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
	UDPServers []UDPServer
	RawServers []RawServer
	Backends   []Backend
	Users      []UserPolicy
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
			mode := "terminate"
			if r.Passthrough {
				mode = "passthrough"
			}
			routes = append(routes, obj{"name": r.Name, "sni": []string{r.SNI}, "tls": mode, "upstream": r.Upstream})
		}
		servers[fmt.Sprintf("tcp_%d", srv.Port)] = obj{
			"listen": []string{fmt.Sprintf(":%d", srv.Port)},
			"routes": routes,
			// 其余流量（网站、未知 SNI、非 TLS、ACME TLS-ALPN 验证）原样交给内部网站，
			// 用 PROXY protocol 带上客户端真实地址
			"fallback": obj{"name": "site", "tls": "passthrough", "upstream": s.SiteAddr, "proxy_protocol": true},
		}
	}
	for _, srv := range s.UDPServers {
		routes := []obj{}
		for _, r := range srv.Routes {
			routes = append(routes, obj{"name": r.Name, "sni": []string{r.SNI}, "tls": "passthrough", "upstream": r.Upstream})
		}
		server := obj{"listen": []string{fmt.Sprintf("udp/:%d", srv.Port)}, "routes": routes}
		if srv.Port == s.HTTPSPort {
			// 其余 QUIC 连接（浏览器的 HTTP/3、未知 SNI）交给内部网站的 HTTP/3
			server["fallback"] = obj{"name": "site_h3", "tls": "passthrough", "upstream": s.SiteAddr}
		}
		servers[fmt.Sprintf("udp_%d", srv.Port)] = server
	}
	for _, srv := range s.RawServers {
		listen := fmt.Sprintf(":%d", srv.Port)
		if srv.Network == "udp" {
			listen = "udp/" + listen
		}
		servers[fmt.Sprintf("raw_%s_%d", srv.Network, srv.Port)] = obj{
			"listen":   []string{listen},
			"raw":      true,
			"fallback": obj{"name": srv.Name, "tls": "passthrough", "upstream": srv.Upstream},
		}
	}
	app := obj{"servers": servers}
	if s.UsageFile != "" {
		app["usage_file"] = s.UsageFile
	}
	if len(s.Users) > 0 {
		users := obj{}
		for _, u := range s.Users {
			policy := obj{}
			if u.TrafficLimit > 0 {
				policy["traffic_limit"] = u.TrafficLimit
			}
			if u.ResetDay > 0 {
				policy["reset_day"] = u.ResetDay
			}
			if !u.Expire.IsZero() {
				policy["expire"] = u.Expire.Format(time.RFC3339)
			}
			if len(u.Protocols) > 0 {
				policy["protocols"] = u.Protocols
			}
			users[u.Name] = policy
		}
		app["users"] = users
	}
	if len(s.Backends) > 0 {
		backends := obj{}
		for _, b := range s.Backends {
			backend := obj{"command": b.Command, "revision": b.Revision}
			if len(b.RequireFiles) > 0 {
				backend["require_files"] = b.RequireFiles
			}
			backends[b.Name] = backend
		}
		app["backends"] = backends
	}
	return app
}

// siteHTTP3 报告内部网站是否提供 HTTP/3（主入口端口上有 UDP 网关）
func siteHTTP3(s Spec) bool {
	for _, srv := range s.UDPServers {
		if srv.Port == s.HTTPSPort {
			return true
		}
	}
	return false
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
	protocols := []string{"h1", "h2"}
	if siteHTTP3(s) {
		protocols = append(protocols, "h3")
		// Caddy 默认按内部监听端口通告 HTTP/3，改成对外的入口端口
		altSvc := obj{"handle": []obj{{
			"handler":  "headers",
			"response": obj{"set": obj{"Alt-Svc": []string{fmt.Sprintf(`h3=":%d"; ma=86400`, s.HTTPSPort)}}},
		}}}
		routes = append([]obj{altSvc}, routes...)
	}

	location := "https://{http.request.host}{http.request.uri}"
	if s.HTTPSPort != 443 {
		location = fmt.Sprintf("https://{http.request.host}:%d{http.request.uri}", s.HTTPSPort)
	}

	return obj{"servers": obj{
		// 内部 HTTPS 网站：只监听回环地址，由网关转发过来
		"site": obj{
			"listen":          []string{s.SiteAddr},
			"protocols":       protocols,
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
