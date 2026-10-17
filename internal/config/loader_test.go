package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if len(cfg.Protocols) != 2 {
		t.Fatalf("want 2 protocols, got %d", len(cfg.Protocols))
	}
	p0, p1 := cfg.Protocols[0].Config["password"], cfg.Protocols[1].Config["password"]
	if p0 == "" || p0 == "change-me" || p0 == p1 {
		t.Fatalf("example passwords should be random and distinct: %v %v", p0, p1)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"unknown field": {"domain: a.com\ncertificates: {provider: internal}\nentyr: {}\n", "entyr"},
		"duplicate protocol": {`domain: a.com
certificates: {provider: internal}
protocols:
  - {name: anytls}
  - {name: anytls}
`, "duplicate"},
		"bad port":               {"domain: a.com\ncertificates: {provider: internal}\nentry: {https_port: 70000}\n", "invalid port"},
		"missing email":          {"domain: a.com\n", "email"},
		"missing domain":         {"certificates: {provider: internal}\n", "domain"},
		"acme without ca":        {"domain: a.com\ncertificates: {provider: acme, email: a@a.com}\n", "ca"},
		"proxy without upstream": {"domain: a.com\ncertificates: {provider: internal}\nweb: [{name: x, type: reverse_proxy}]\n", "upstream"},
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
