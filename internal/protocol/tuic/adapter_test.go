package tuic

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

func newConfig() *config.ProtocolConfig {
	return &config.ProtocolConfig{Name: name, Options: map[string]any{}}
}

func TestValidate(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	if err := a.Validate(newConfig()); err != nil {
		t.Fatal(err)
	}
	c := newConfig()
	c.Options["congestion_control"] = "vegas"
	if a.Validate(c) == nil {
		t.Error("unknown congestion control should be rejected")
	}
}

func TestGenerateConfig(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cfg := newConfig()
	rt := protocol.Runtime{ListenAddr: "127.0.0.1:20005", Users: []protocol.User{alice, bob}, Cert: &config.Certificate{CertPath: "/c.crt", KeyPath: "/c.key"}}
	data, err := a.GenerateConfig(cfg, rt)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Inbounds []map[string]any }
	json.Unmarshal(data, &out)
	in := out.Inbounds[0]
	users := in["users"].([]any)
	user := users[1].(map[string]any)
	tls := in["tls"].(map[string]any)
	if in["type"] != "tuic" || in["congestion_control"] != "bbr" || len(users) != 2 || user["name"] != "bob" ||
		user["uuid"] != bob.UUID(name) || user["password"] != bob.Password(name) ||
		tls["certificate_path"] != "/c.crt" || tls["alpn"].([]any)[0] != "h3" {
		t.Fatalf("unexpected inbound: %s", data)
	}
	if _, err := a.GenerateConfig(cfg, protocol.Runtime{ListenAddr: ":443"}); err == nil {
		t.Fatal("missing certificate should fail")
	}
}

func TestClientConfig(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cfg := newConfig()
	cc, _ := a.ClientConfig(cfg, protocol.ClientContext{User: alice, Host: "1.2.3.4", Port: 443, SNI: "tuic.a.com", Insecure: true})
	u, _ := url.Parse(cc.URI)
	pass, _ := u.User.Password()
	q := u.Query()
	if u.Scheme != "tuic" || u.User.Username() != alice.UUID(name) || pass != alice.Password(name) || u.Fragment != "tuic-alice" ||
		q.Get("sni") != "tuic.a.com" || q.Get("alpn") != "h3" || q.Get("allow_insecure") != "1" {
		t.Fatalf("unexpected URI %s", cc.URI)
	}
}
