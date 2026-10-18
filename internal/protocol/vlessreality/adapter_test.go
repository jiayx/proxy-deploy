package vlessreality

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/secrets"
)

var (
	alice = protocol.User{Name: "alice", Secret: "alice-secret-0123456789"}
	bob   = protocol.User{Name: "bob", Secret: "bob-secret-0123456789"}
)

func newConfig() (*config.ProtocolConfig, string) {
	priv, pub := secrets.RealityKeyPair()
	return &config.ProtocolConfig{Name: name, Options: map[string]any{
		"private_key": priv, "short_id": secrets.ShortID(),
	}}, pub
}

func TestValidate(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cfg, _ := newConfig()
	if err := a.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	for field, bad := range map[string]string{
		"private_key": "short",
		"short_id":    "XYZ",
		"handshake":   "no-port",
	} {
		c, _ := newConfig()
		c.Options[field] = bad
		if a.Validate(c) == nil {
			t.Errorf("%s=%q should be rejected", field, bad)
		}
	}
}

func TestGenerateConfig(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cfg, _ := newConfig()
	rt := protocol.Runtime{ListenAddr: "127.0.0.1:20004", SNI: "www.example.org", Users: []protocol.User{alice, bob}}

	parse := func() map[string]any {
		data, err := a.GenerateConfig(cfg, rt)
		if err != nil {
			t.Fatal(err)
		}
		var out struct{ Inbounds []map[string]any }
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		return out.Inbounds[0]
	}
	in := parse()
	user := in["users"].([]any)[1].(map[string]any)
	tls := in["tls"].(map[string]any)
	reality := tls["reality"].(map[string]any)
	hs := reality["handshake"].(map[string]any)
	if in["type"] != "vless" || user["flow"] != "xtls-rprx-vision" || user["name"] != "bob" || user["uuid"] != bob.UUID(name) || tls["server_name"] != "www.example.org" ||
		reality["private_key"] != cfg.Options["private_key"] || hs["server"] != "www.example.org" || hs["server_port"] != 443.0 {
		t.Fatalf("unexpected inbound: %v", in)
	}

	cfg.Options["handshake"] = "origin.example.org:8443"
	hs = parse()["tls"].(map[string]any)["reality"].(map[string]any)["handshake"].(map[string]any)
	if hs["server"] != "origin.example.org" || hs["server_port"] != 8443.0 {
		t.Fatalf("custom handshake not applied: %v", hs)
	}
}

func TestClientConfig(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cfg, pub := newConfig()
	cc, err := a.ClientConfig(cfg, protocol.ClientContext{User: alice, Host: "1.2.3.4", Port: 443, SNI: "www.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(cc.URI)
	q := u.Query()
	if u.Scheme != "vless" || u.User.Username() != alice.UUID(name) || u.Fragment != "vless-reality-alice" || u.Host != "1.2.3.4:443" ||
		q.Get("security") != "reality" || q.Get("pbk") != pub || q.Get("sid") != cfg.Options["short_id"] ||
		q.Get("sni") != "www.example.org" || q.Get("flow") != "xtls-rprx-vision" {
		t.Fatalf("unexpected URI %s", cc.URI)
	}
}
