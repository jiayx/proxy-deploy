package singbox

import (
	"encoding/json"
	"testing"
)

func TestConfig(t *testing.T) {
	data, err := Config("127.0.0.1:20001", map[string]any{"type": "anytls"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []struct {
			Type       string `json:"type"`
			Listen     string `json:"listen"`
			ListenPort int    `json:"listen_port"`
		} `json:"inbounds"`
		Outbounds []struct{ Type string } `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	in := cfg.Inbounds[0]
	if in.Type != "anytls" || in.Listen != "127.0.0.1" || in.ListenPort != 20001 || cfg.Outbounds[0].Type != "direct" {
		t.Fatalf("unexpected config: %s", data)
	}

	data, _ = Config(":443", map[string]any{"type": "tuic"})
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.Inbounds[0].Listen != "::" {
		t.Fatalf("empty host should listen on all addresses: %s", data)
	}
}
