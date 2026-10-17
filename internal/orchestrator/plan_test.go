package orchestrator

import (
	"strings"
	"testing"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/internal/protocol/anytls"
	"github.com/jiayx/proxy-deploy/internal/protocol/hysteria2"
	"github.com/jiayx/proxy-deploy/internal/protocol/vlessreality"
	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/secrets"
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
	reg.Register(vlessreality.New(layout))
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
	if !hy.ViaEntry || hy.Runtime.ListenAddr != "127.0.0.1:20003" || hy.Runtime.SiteURL != "http://127.0.0.1:20001" || hy.Runtime.Cert == nil || hy.Runtime.Cert.Name != "hysteria2.example.com" {
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
	want := "tcp127.0.0.1:20000,tcp127.0.0.1:20001,tcp127.0.0.1:20002,tcp:443,tcp:80,udp127.0.0.1:20000,udp127.0.0.1:20003,udp:443"
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

func TestPlanUDPThroughGateway(t *testing.T) {
	o := newOrch(t, baseConfig(proto("hysteria2"), proto("tuic")))
	o.registry.Register(fakeUDP{})
	p := o.Plan()
	if len(p.Conflicts) != 0 {
		t.Fatalf("UDP protocols should share the entry port, got %+v", p.Conflicts)
	}
	if len(p.Caddy.UDPServers) != 1 || p.Caddy.UDPServers[0].Port != 443 {
		t.Fatalf("want one UDP gateway on 443, got %+v", p.Caddy.UDPServers)
	}
	var routes []string
	for _, r := range p.Caddy.UDPServers[0].Routes {
		routes = append(routes, r.Name+"="+r.SNI+"→"+r.Upstream)
	}
	want := "hysteria2=hysteria2.example.com→127.0.0.1:20003,tuic=tuic.example.com→127.0.0.1:20004"
	if got := strings.Join(routes, ","); got != want {
		t.Fatalf("routes:\n got %s\nwant %s", got, want)
	}
}

func TestPlanUDPGatewayWithoutUDPProtocols(t *testing.T) {
	p := newOrch(t, baseConfig(proto("anytls"))).Plan()
	if len(p.Caddy.UDPServers) != 1 || p.Caddy.UDPServers[0].Port != 443 || len(p.Caddy.UDPServers[0].Routes) != 0 {
		t.Fatalf("entry port should always have a UDP gateway for the site's HTTP/3, got %+v", p.Caddy.UDPServers)
	}
}

func realityProto(extra ...func(*config.ProtocolConfig)) config.ProtocolConfig {
	priv, _ := secrets.RealityKeyPair()
	p := config.ProtocolConfig{Name: "vless-reality", Enabled: true, Config: map[string]any{
		"uuid": secrets.UUID(), "private_key": priv, "short_id": secrets.ShortID()}}
	for _, f := range extra {
		f(&p)
	}
	return p
}

func TestPlanRealityPassthrough(t *testing.T) {
	p := newOrch(t, baseConfig(proto("anytls"), realityProto())).Plan()
	if len(p.Conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %+v", p.Conflicts)
	}
	routes := p.Caddy.TCPServers[0].Routes
	if len(routes) != 2 || routes[0].Passthrough || !routes[1].Passthrough || routes[1].SNI != "www.microsoft.com" {
		t.Fatalf("reality should be a passthrough route on the default SNI: %+v", routes)
	}
	for _, c := range p.Certs {
		if c.Name == "www.microsoft.com" {
			t.Fatal("must not request a certificate for the passthrough SNI")
		}
	}
	if svc := p.Services[1]; svc.Runtime.SNI != "www.microsoft.com" || svc.Runtime.Cert != nil {
		t.Fatalf("unexpected reality runtime: %+v", svc.Runtime)
	}

	p = newOrch(t, baseConfig(realityProto(func(c *config.ProtocolConfig) { c.SNI = "example.com" }))).Plan()
	if len(p.Conflicts) != 1 || !strings.Contains(p.Conflicts[0].Reason, "网站域名") {
		t.Fatalf("reality SNI equal to the site domain should conflict: %+v", p.Conflicts)
	}
}

func TestPlanLoopbackPortsStable(t *testing.T) {
	ports := func(cfg *config.DeployConfig) map[string]string {
		out := map[string]string{}
		for _, s := range newOrch(t, cfg).Plan().Services {
			out[s.Cfg.Name] = s.Runtime.ListenAddr
		}
		return out
	}
	before := ports(baseConfig(proto("hysteria2"), proto("anytls")))
	after := ports(baseConfig(proto("hysteria2"), proto("anytls"), realityProto()))
	for name, addr := range before {
		if after[name] != addr {
			t.Fatalf("enabling another protocol moved %s from %s to %s", name, addr, after[name])
		}
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
