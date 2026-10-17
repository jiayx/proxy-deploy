package tuic

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/secrets"
)

func newConfig() *config.ProtocolConfig {
	return &config.ProtocolConfig{Name: name, Config: map[string]any{"uuid": secrets.UUID(), "password": "p@ss/word"}}
}

func TestValidate(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	if err := a.Validate(newConfig()); err != nil {
		t.Fatal(err)
	}
	for field, bad := range map[string]string{"uuid": "x", "password": "", "congestion_control": "vegas"} {
		c := newConfig()
		c.Config[field] = bad
		if a.Validate(c) == nil {
			t.Errorf("%s=%q should be rejected", field, bad)
		}
	}
}

func TestGenerateConfig(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cfg := newConfig()
	rt := protocol.Runtime{ListenAddr: "127.0.0.1:20005", Cert: &config.Certificate{CertPath: "/c.crt", KeyPath: "/c.key"}}
	data, err := a.GenerateConfig(cfg, rt)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Inbounds []map[string]any }
	json.Unmarshal(data, &out)
	in := out.Inbounds[0]
	user := in["users"].([]any)[0].(map[string]any)
	tls := in["tls"].(map[string]any)
	if in["type"] != "tuic" || in["congestion_control"] != "bbr" || user["uuid"] != cfg.Config["uuid"] ||
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
	cc, _ := a.ClientConfig(cfg, protocol.ClientContext{Host: "1.2.3.4", Port: 443, SNI: "tuic.a.com", Insecure: true})
	u, _ := url.Parse(cc.URI)
	pass, _ := u.User.Password()
	q := u.Query()
	if u.Scheme != "tuic" || u.User.Username() != cfg.Config["uuid"] || pass != "p@ss/word" ||
		q.Get("sni") != "tuic.a.com" || q.Get("alpn") != "h3" || q.Get("allow_insecure") != "1" {
		t.Fatalf("unexpected URI %s", cc.URI)
	}
}
