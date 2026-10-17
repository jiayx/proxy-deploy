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
		{"2022-blake3-chacha20-poly1305", secrets.Key(32), true},
		{"2022-blake3-aes-256-gcm", secrets.Key(16), false}, // 长度不符
		{"", "not base64!", false},
		{"aes-256-gcm", "anything", false}, // 只支持 2022 加密方式
	}
	for _, c := range cases {
		cfg := &config.ProtocolConfig{Config: map[string]any{"method": c.method, "password": c.password}}
		if err := a.Validate(cfg); (err == nil) != c.ok {
			t.Errorf("method=%q: got err=%v, want ok=%v", c.method, err, c.ok)
		}
	}
}

func TestConfigs(t *testing.T) {
	a := New(paths.New("/opt/pd", false))
	key := secrets.Key(16)
	cfg := &config.ProtocolConfig{Config: map[string]any{"password": key}}

	data, _ := a.GenerateConfig(cfg, protocol.Runtime{ListenAddr: ":8388"})
	var out struct{ Inbounds []map[string]any }
	json.Unmarshal(data, &out)
	in := out.Inbounds[0]
	if in["type"] != "shadowsocks" || in["method"] != "2022-blake3-aes-128-gcm" || in["password"] != key ||
		in["listen"] != "::" || in["listen_port"] != 8388.0 {
		t.Fatalf("unexpected inbound: %s", data)
	}

	cc, _ := a.ClientConfig(cfg, protocol.ClientContext{Host: "1.2.3.4", Port: 8388})
	u, err := url.Parse(cc.URI)
	pass, _ := u.User.Password()
	if err != nil || u.Scheme != "ss" || u.User.Username() != "2022-blake3-aes-128-gcm" || pass != key || u.Host != "1.2.3.4:8388" {
		t.Fatalf("unexpected URI %s", cc.URI)
	}
}
