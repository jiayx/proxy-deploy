package caddy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCertPaths(t *testing.T) {
	crt, _ := CertPaths("/d", Issuer{Kind: "acme"}, "a.com")
	if crt != "/d/certificates/acme-v02.api.letsencrypt.org-directory/a.com/a.com.crt" {
		t.Fatalf("letsencrypt path: %s", crt)
	}
	crt, _ = CertPaths("/d", Issuer{Kind: "internal"}, "a.com")
	if crt != "/d/certificates/local/a.com/a.com.crt" {
		t.Fatalf("internal path: %s", crt)
	}
}

func TestGenerate(t *testing.T) {
	data, err := Generate(Spec{
		AdminSocket:   "/v/admin.sock",
		StorageRoot:   "/v/caddy",
		Issuer:        Issuer{Kind: "internal"},
		CertNames:     []string{"a.com", "t.a.com"},
		DefaultSNI:    "a.com",
		HTTPSPort:     8443,
		HTTPPort:      8080,
		SiteAddr:      "127.0.0.1:20000",
		SitePlainAddr: "127.0.0.1:20001",
		TCPServers: []TCPServer{{Port: 8443, Routes: []TCPRoute{
			{Name: "anytls", SNI: "t.a.com", Upstream: "127.0.0.1:20002"},
			{Name: "vless-reality", SNI: "www.example.org", Upstream: "127.0.0.1:20004", Passthrough: true},
		}}},
		UDPServers: []UDPServer{{Port: 8443, Routes: []UDPRoute{{Name: "hysteria2", SNI: "h.a.com", Upstream: "127.0.0.1:20003"}}}},
		RawServers: []RawServer{{Name: "ss2022", Port: 8388, Network: "udp", Upstream: "127.0.0.1:20006"}},
		Backends: []Backend{{Name: "hysteria2", Command: []string{"/opt/pd/bin/sing-box", "run", "-c", "/opt/pd/etc/hysteria2/config.json"},
			RequireFiles: []string{"/c.crt"}, Revision: "r1"}},
		Sites: []Site{{Root: "/www"}, {Host: "app.a.com", Upstream: "127.0.0.1:3000"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		`"listen": "unix//v/admin.sock"`,
		`"install_trust": false`,
		`https://{http.request.host}:8443{http.request.uri}`,
		`"fallback_sni": "a.com"`,
		`"proxy_protocol": true`,
		`"wrapper": "proxy_protocol"`,
		`"require_files": [`,
		`"raw": true`,
		`"udp/:8388"`,
		`"revision": "r1"`,
		`"/opt/pd/bin/sing-box"`,
		`"udp/:8443"`,
		`"upstream": "127.0.0.1:20003"`,
		`"h3"`,
		`h3=\":8443\"; ma=86400`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("generated config lacks %s", want)
		}
	}

	// 第一条路由设置 Alt-Svc；有 host 的站点必须排在兜底站点之前，否则永远匹配不到
	routes := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["site"].(map[string]any)["routes"].([]any)
	if len(routes) != 3 || routes[0].(map[string]any)["terminal"] != nil ||
		routes[1].(map[string]any)["match"] == nil || routes[2].(map[string]any)["match"] != nil {
		t.Fatalf("host-matched site should precede fallback: %v", routes)
	}

	// 网关：协议路由终结 TLS，其余流量透传给内部网站
	gw := cfg["apps"].(map[string]any)["proxy_gateway"].(map[string]any)["servers"].(map[string]any)["tcp_8443"].(map[string]any)
	route := gw["routes"].([]any)[0].(map[string]any)
	if route["name"] != "anytls" || route["tls"] != "terminate" || route["upstream"] != "127.0.0.1:20002" {
		t.Fatalf("unexpected gateway route: %v", route)
	}
	if r := gw["routes"].([]any)[1].(map[string]any); r["tls"] != "passthrough" || r["sni"].([]any)[0] != "www.example.org" {
		t.Fatalf("reality route should pass TLS through: %v", r)
	}
	if fb := gw["fallback"].(map[string]any); fb["tls"] != "passthrough" || fb["upstream"] != "127.0.0.1:20000" {
		t.Fatalf("unexpected gateway fallback: %v", fb)
	}
}
