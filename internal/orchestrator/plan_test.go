package orchestrator

import (
	"strings"
	"testing"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/internal/protocol/anytls"
	"github.com/jiayx/proxy-deploy/internal/protocol/hysteria2"
	"github.com/jiayx/proxy-deploy/pkg/paths"
)

func newOrch(t *testing.T, cfg *config.DeployConfig) *Orchestrator {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	layout := paths.New("/opt/pd", false)
	reg := protocol.NewRegistry()
	reg.Register(hysteria2.New(layout))
	reg.Register(anytls.New(layout))
	return New(reg, cfg, layout)
}

func proto(name string, extra ...func(*config.ProtocolConfig)) config.ProtocolConfig {
	p := config.ProtocolConfig{Name: name, Enabled: true, Config: map[string]any{"password": "secret"}}
	for _, f := range extra {
		f(&p)
	}
	return p
}

func baseConfig(protocols ...config.ProtocolConfig) *config.DeployConfig {
	return &config.DeployConfig{
		Domain:       "example.com",
		Certificates: config.CertificateConfig{Provider: "internal"},
		Protocols:    protocols,
	}
}

func TestPlanDefault(t *testing.T) {
	p := newOrch(t, baseConfig(proto("hysteria2"), proto("anytls"))).Plan()
	if len(p.Conflicts) > 0 {
		t.Fatalf("unexpected conflicts: %+v", p.Conflicts)
	}

	if len(p.Caddy.TCPServers) != 1 || p.Caddy.TCPServers[0].Port != 443 {
		t.Fatalf("want one TCP server on 443, got %+v", p.Caddy.TCPServers)
	}
	routes := p.Caddy.TCPServers[0].Routes
	if len(routes) != 1 || routes[0].Name != "anytls" || routes[0].SNI != "anytls.example.com" || routes[0].Upstream != "127.0.0.1:20002" {
		t.Fatalf("unexpected anytls route: %+v", routes)
	}

	byName := map[string]*Service{}
	for _, s := range p.Services {
		byName[s.Cfg.Name] = s
	}
	hy := byName["hysteria2"]
	if hy.ViaEntry || hy.Runtime.ListenAddr != ":443" || hy.Runtime.SiteURL != "http://127.0.0.1:20001" || hy.Runtime.Cert == nil || hy.Runtime.Cert.Name != "hysteria2.example.com" {
		t.Fatalf("unexpected hysteria2 plan: %+v %+v", hy, hy.Runtime)
	}
	if byName["anytls"].Runtime.Cert != nil {
		t.Fatal("anytls TLS is terminated by Caddy and should not get a certificate")
	}

	var certs []string
	for _, c := range p.Certs {
		certs = append(certs, c.Name)
	}
	if got := strings.Join(certs, ","); got != "example.com,hysteria2.example.com,anytls.example.com" {
		t.Fatalf("unexpected certs %s", got)
	}

	var ports []string
	for _, port := range p.Ports {
		ports = append(ports, port.Network+port.Addr)
	}
	want := "tcp127.0.0.1:20000,tcp127.0.0.1:20001,tcp127.0.0.1:20002,tcp:443,tcp:80,udp:443"
	if got := strings.Join(ports, ","); got != want {
		t.Fatalf("ports:\n got %s\nwant %s", got, want)
	}
}

func TestPlanConflicts(t *testing.T) {
	cases := map[string]struct {
		cfg  *config.DeployConfig
		want string
	}{
		"unknown protocol": {baseConfig(proto("vless")), "未知协议"},
		"placeholder password": {baseConfig(proto("anytls", func(p *config.ProtocolConfig) {
			p.Config["password"] = "change-me"
		})), "change-me"},
		"tcp on http port":  {baseConfig(proto("anytls", func(p *config.ProtocolConfig) { p.Port = 80 })), "HTTP 入口端口"},
		"sni equals domain": {baseConfig(proto("anytls", func(p *config.ProtocolConfig) { p.SNI = "example.com" })), "网站域名"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := newOrch(t, c.cfg).Plan()
			if len(p.Conflicts) != 1 || !strings.Contains(p.Conflicts[0].Reason, c.want) {
				t.Fatalf("want one conflict containing %q, got %+v", c.want, p.Conflicts)
			}
		})
	}
}

// fakeUDP 是测试用的第二个 UDP 协议
type fakeUDP struct{ protocol.Adapter }

func (fakeUDP) Name() string                  { return "tuic" }
func (fakeUDP) Transport() protocol.Transport { return protocol.TransportUDP }

func TestPlanSharedUDPPortNotSupportedYet(t *testing.T) {
	cfg := baseConfig(proto("hysteria2"), proto("tuic"))
	o := newOrch(t, cfg)
	o.registry.Register(fakeUDP{})
	p := o.Plan()
	if len(p.Conflicts) != 1 || !strings.Contains(p.Conflicts[0].Reason, "UDP/443") {
		t.Fatalf("want shared UDP port conflict, got %+v", p.Conflicts)
	}

	cfg.Protocols[1].Port = 8443
	if p := o.Plan(); len(p.Conflicts) != 0 {
		t.Fatalf("separate UDP ports should be fine, got %+v", p.Conflicts)
	}
}

func TestPlanDisabledProtocolIgnored(t *testing.T) {
	p := newOrch(t, baseConfig(proto("anytls", func(p *config.ProtocolConfig) { p.Enabled = false }))).Plan()
	if len(p.Services) != 0 || len(p.Caddy.TCPServers[0].Routes) != 0 {
		t.Fatalf("disabled protocol should not be planned: %+v", p.Services)
	}
}

func TestPlanTCPOnSeparatePort(t *testing.T) {
	p := newOrch(t, baseConfig(proto("anytls", func(p *config.ProtocolConfig) { p.Port = 8443 }))).Plan()
	if len(p.Caddy.TCPServers) != 2 {
		t.Fatalf("want main entry plus 8443, got %+v", p.Caddy.TCPServers)
	}
	if s := p.Caddy.TCPServers[1]; s.Port != 8443 || len(s.Routes) != 1 {
		t.Fatalf("unexpected 8443 server: %+v", s)
	}
}

func TestClientConfigsInsecureForInternalCA(t *testing.T) {
	o := newOrch(t, baseConfig(proto("anytls")))
	ccs, err := o.ClientConfigs(o.Plan())
	if err != nil {
		t.Fatal(err)
	}
	want := "anytls://secret@example.com:443/?insecure=1&sni=anytls.example.com#anytls"
	if len(ccs) != 1 || ccs[0].URI != want {
		t.Fatalf("got %+v, want %s", ccs, want)
	}
}
