package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deploy.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExampleLoads(t *testing.T) {
	cfg, err := Load(writeConfig(t, Example()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Address != "example.com" || cfg.Entry.HTTPSPort != 443 || cfg.Entry.HTTPPort != 80 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if strings.Join(cfg.Protocols.Names(), ",") != "hysteria2,anytls" {
		t.Fatalf("want hysteria2 and anytls enabled, got %+v", cfg.Protocols)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Name != "default" || len(cfg.Users[0].Secret) < 16 {
		t.Fatalf("example should have one default user with a generated secret: %+v", cfg.Users)
	}
	if other, _ := Load(writeConfig(t, Example())); other.Users[0].Secret == cfg.Users[0].Secret {
		t.Fatal("example secrets should be random")
	}
}

// users 是测试配置共用的用户块
const users = "users: [{name: alice, secret: alice-secret-0123456789}]\n"

func TestLoadErrors(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"no users":               {"domain: a.com\ncertificates: {provider: internal}\n", "at least one user"},
		"bad user name":          {"domain: a.com\ncertificates: {provider: internal}\nusers: [{name: 'a b', secret: 0123456789abcdef}]\n", "name"},
		"short secret":           {"domain: a.com\ncertificates: {provider: internal}\nusers: [{name: a, secret: short}]\n", "secret"},
		"duplicate user":         {"domain: a.com\ncertificates: {provider: internal}\nusers: [{name: a, secret: 0123456789abcdef}, {name: a, secret: fedcba9876543210}]\n", "duplicate"},
		"duplicate secret":       {"domain: a.com\ncertificates: {provider: internal}\nusers: [{name: a, secret: 0123456789abcdef}, {name: b, secret: 0123456789abcdef}]\n", "duplicate"},
		"unknown field":          {"domain: a.com\ncertificates: {provider: internal}\nentyr: {}\n", "entyr"},
		"duplicate protocol":     {"domain: a.com\ncertificates: {provider: internal}\n" + users + "protocols:\n  anytls:\n  anytls:\n", "duplicate"},
		"protocol list":          {"domain: a.com\ncertificates: {provider: internal}\n" + users + "protocols: [anytls]\n", "mapping"},
		"protocol bad port":      {"domain: a.com\ncertificates: {provider: internal}\n" + users + "protocols: {ss2022: {port: 0}}\n", "invalid port"},
		"alias duplicate":        {"domain: a.com\ncertificates: {provider: internal}\n" + users + "protocols: {hy2: , hysteria2: }\n", "duplicate"},
		"user unknown protocol":  {"domain: a.com\ncertificates: {provider: internal}\nusers: [{name: a, secret: 0123456789abcdef, protocols: [tuic]}]\nprotocols: {anytls: }\n", "not configured"},
		"bad port":               {"domain: a.com\ncertificates: {provider: internal}\nentry: {https_port: 70000}\n" + users, "invalid port"},
		"missing email":          {"domain: a.com\n", "email"},
		"missing domain":         {"certificates: {provider: internal}\n", "domain"},
		"acme without ca":        {"domain: a.com\ncertificates: {provider: acme, email: a@a.com}\n", "ca"},
		"proxy without upstream": {"domain: a.com\ncertificates: {provider: internal}\nweb: [{name: x, type: reverse_proxy}]\n" + users, "upstream"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeConfig(t, c.yaml))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestLoadProtocols(t *testing.T) {
	cfg, err := Load(writeConfig(t, `domain: a.com
certificates: {provider: internal}
`+users+`protocols:
  tuic:
  anytls: {sni: proxy.a.com}
  ss2022:
    port: 8388
    password: abc
`))
	if err != nil {
		t.Fatal(err)
	}
	ps := cfg.Protocols
	if strings.Join(ps.Names(), ",") != "tuic,anytls,ss2022" {
		t.Fatalf("protocols should keep their order: %v", ps.Names())
	}
	if ps[1].SNI != "proxy.a.com" || len(ps[1].Options) != 0 {
		t.Fatalf("sni should not stay in options: %+v", ps[1])
	}
	if ps[2].Port != 8388 || ps[2].Options["password"] != "abc" || len(ps[2].Options) != 1 {
		t.Fatalf("unexpected ss2022: %+v", ps[2])
	}
}

func TestProtocolAliases(t *testing.T) {
	cfg, err := Load(writeConfig(t, `domain: a.com
certificates: {provider: internal}
users: [{name: a, secret: 0123456789abcdef, protocols: [hy2, ss]}]
protocols:
  hy2:
  reality: {private_key: k}
  ss: {port: 8388}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Protocols.Names(), ","); got != "hysteria2,vless-reality,ss2022" {
		t.Fatalf("aliases should become full names: %s", got)
	}
	if got := strings.Join(cfg.Users[0].Protocols, ","); got != "hysteria2,ss2022" || !cfg.Users[0].Allows("ss2022") {
		t.Fatalf("user protocols should use full names: %s", got)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{
		"": 0, "1024": 1024, "500GB": 500e9, "200GiB": 200 << 30, "1.5TiB": 3 << 39, "10 MiB": 10 << 20, "1KB": 1000,
	} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%q: got %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"lots", "10XB", "-1GB", "GB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestUserExpireAt(t *testing.T) {
	u := UserConfig{Expire: "2027-01-31"}
	if got := u.ExpireAt(); !got.Equal(time.Date(2027, 2, 1, 0, 0, 0, 0, time.Local)) {
		t.Fatalf("expire date should last until the end of that day, got %s", got)
	}
	if !(UserConfig{}).ExpireAt().IsZero() {
		t.Fatal("no expire means never")
	}
}
