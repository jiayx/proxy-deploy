package ss2022

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/secrets"
)

func TestValidate(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	cases := []struct {
		method, password string
		ok               bool
	}{
		{"", secrets.Key(16), true},
		{"2022-blake3-aes-256-gcm", secrets.Key(32), true},
		{"2022-blake3-chacha20-poly1305", secrets.Key(32), false}, // 多用户不支持
		{"2022-blake3-aes-256-gcm", secrets.Key(16), false},       // 长度不符
		{"", "not base64!", false},
		{"aes-256-gcm", "anything", false}, // 只支持 2022 加密方式
	}
	for _, c := range cases {
		cfg := &config.ProtocolConfig{Options: map[string]any{"method": c.method, "password": c.password}}
		if err := a.Validate(cfg); (err == nil) != c.ok {
			t.Errorf("method=%q: got err=%v, want ok=%v", c.method, err, c.ok)
		}
	}
}

var (
	alice = protocol.User{Name: "alice", Secret: "alice-secret-0123456789"}
	bob   = protocol.User{Name: "bob", Secret: "bob-secret-0123456789"}
)

func TestConfigs(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	key := secrets.Key(16)
	cfg := &config.ProtocolConfig{Options: map[string]any{"password": key}}

	data, _ := a.GenerateConfig(cfg, protocol.Runtime{ListenAddr: "127.0.0.1:20006", Users: []protocol.User{alice, bob}})
	var out struct{ Inbounds []map[string]any }
	json.Unmarshal(data, &out)
	in := out.Inbounds[0]
	users := in["users"].([]any)
	if in["type"] != "shadowsocks" || in["method"] != "2022-blake3-aes-128-gcm" || in["password"] != key || len(users) != 2 ||
		users[1].(map[string]any)["password"] != bob.Key(name, 16) {
		t.Fatalf("unexpected inbound: %s", data)
	}

	cc, _ := a.ClientConfig(cfg, protocol.ClientContext{User: alice, Host: "1.2.3.4", Port: 8388})
	u, err := url.Parse(cc.URI)
	pass, _ := u.User.Password()
	if err != nil || u.Scheme != "ss" || u.User.Username() != "2022-blake3-aes-128-gcm" || pass != key+":"+alice.Key(name, 16) ||
		u.Host != "1.2.3.4:8388" || u.Fragment != "ss2022-alice" {
		t.Fatalf("unexpected URI %s", cc.URI)
	}
}
