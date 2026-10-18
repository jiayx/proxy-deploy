package anytls

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/jiayx/proxy-gateway/internal/config"
	"github.com/jiayx/proxy-gateway/internal/protocol"
	"github.com/jiayx/proxy-gateway/pkg/paths"
)

var (
	alice = protocol.User{Name: "alice", Secret: "alice-secret-0123456789"}
	bob   = protocol.User{Name: "bob", Secret: "bob-secret-0123456789"}
)

func TestGenerateConfig(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cfg := &config.ProtocolConfig{Name: name, Options: map[string]any{"padding_scheme": "stop=8\n0=30-30\n"}}
	if err := a.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := a.GenerateConfig(cfg, protocol.Runtime{ListenAddr: "127.0.0.1:20003", Users: []protocol.User{alice, bob}})
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
	if in.Type != "anytls" || len(in.Users) != 2 || in.Users[1]["name"] != "bob" || in.Users[1]["password"] != bob.Password(name) ||
		len(in.PaddingScheme) != 2 || in.TLS != nil {
		t.Fatalf("unexpected config: %s", data)
	}
	if svc, _ := a.Service(cfg, protocol.Runtime{}); svc.Args[0] != "/opt/pd/bin/sing-box" || svc.Args[len(svc.Args)-1] != "/opt/pd/etc/anytls/config.json" {
		t.Fatalf("unexpected service args: %v", svc.Args)
	}

	cfg.Options["padding_scheme"] = 42
	if a.Validate(cfg) == nil {
		t.Fatal("non-string padding_scheme should be rejected")
	}
}

func TestClientConfig(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cc, _ := a.ClientConfig(&config.ProtocolConfig{}, protocol.ClientContext{User: alice, Host: "1.2.3.4", Port: 443, SNI: "anytls.a.com"})
	u, _ := url.Parse(cc.URI)
	if u.User.Username() != alice.Password(name) || u.Fragment != "anytls-alice" || u.Query().Get("sni") != "anytls.a.com" {
		t.Fatalf("unexpected URI %s", cc.URI)
	}
}
