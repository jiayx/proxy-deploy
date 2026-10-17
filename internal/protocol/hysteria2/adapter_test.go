package hysteria2

import (
	"encoding/json"
	"testing"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/paths"
)

func TestGenerateConfig(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cfg := &config.ProtocolConfig{Name: name, Config: map[string]any{"password": "secret"}}
	rt := protocol.Runtime{
		ListenAddr: ":443",
		SiteURL:    "http://127.0.0.1:20001",
		Cert:       &config.Certificate{Name: "h.a.com", CertPath: "/c.crt", KeyPath: "/c.key"},
	}
	data, err := a.GenerateConfig(cfg, rt)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Inbounds []struct {
			Type       string              `json:"type"`
			Listen     string              `json:"listen"`
			ListenPort int                 `json:"listen_port"`
			Users      []map[string]string `json:"users"`
			TLS        struct {
				Enabled         bool   `json:"enabled"`
				CertificatePath string `json:"certificate_path"`
				KeyPath         string `json:"key_path"`
			} `json:"tls"`
			Masquerade map[string]any `json:"masquerade"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	in := out.Inbounds[0]
	if in.Type != "hysteria2" || in.Listen != "::" || in.ListenPort != 443 || in.Users[0]["password"] != "secret" {
		t.Fatalf("unexpected inbound: %s", data)
	}
	if !in.TLS.Enabled || in.TLS.CertificatePath != "/c.crt" || in.TLS.KeyPath != "/c.key" {
		t.Fatalf("unexpected tls: %s", data)
	}
	if in.Masquerade["url"] != "http://127.0.0.1:20001" || in.Masquerade["rewrite_host"] != nil {
		t.Fatalf("default masquerade should proxy the local site keeping Host: %s", data)
	}

	cfg.Config["masquerade_url"] = "https://www.bing.com"
	data, _ = a.GenerateConfig(cfg, rt)
	json.Unmarshal(data, &out)
	if m := out.Inbounds[0].Masquerade; m["url"] != "https://www.bing.com" || m["rewrite_host"] != true {
		t.Fatalf("custom masquerade should rewrite Host: %s", data)
	}

	if _, err := a.GenerateConfig(cfg, protocol.Runtime{ListenAddr: ":443"}); err == nil {
		t.Fatal("missing certificate should fail")
	}
}
