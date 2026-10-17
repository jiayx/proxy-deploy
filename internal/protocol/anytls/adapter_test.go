package anytls

import (
	"encoding/json"
	"testing"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/paths"
)

func TestGenerateConfig(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cfg := &config.ProtocolConfig{Name: name, Config: map[string]any{
		"password":       "secret",
		"padding_scheme": "stop=8\n0=30-30\n",
	}}
	if err := a.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := a.GenerateConfig(cfg, protocol.Runtime{ListenAddr: "127.0.0.1:20001"})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Inbounds []struct {
			Type          string              `json:"type"`
			Users         []map[string]string `json:"users"`
			PaddingScheme []string            `json:"padding_scheme"`
			TLS           any                 `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	in := out.Inbounds[0]
	if in.Type != "anytls" || in.Users[0]["password"] != "secret" || len(in.PaddingScheme) != 2 || in.TLS != nil {
		t.Fatalf("unexpected config: %s", data)
	}
	if svc, _ := a.Service(cfg, protocol.Runtime{}); svc.Args[0] != "/opt/pd/bin/sing-box" || svc.Args[len(svc.Args)-1] != "/opt/pd/etc/anytls/config.json" {
		t.Fatalf("unexpected service args: %v", svc.Args)
	}

	cfg.Config["padding_scheme"] = 42
	if a.Validate(cfg) == nil {
		t.Fatal("non-string padding_scheme should be rejected")
	}
}
