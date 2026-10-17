// Package orchestrator 把协议适配器、入口和证书组合成一套部署：
// 规划端口与路由、生成配置、管理 systemd 服务。
package orchestrator

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/entry/caddy"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

const (
	unitPrefix   = "proxy-deploy-"
	caddyUnit    = unitPrefix + "caddy.service"
	loopbackBase = 20000 // 内部网站和各协议后端从这里开始占用回环端口
)

type Orchestrator struct {
	registry *protocol.Registry
	cfg      *config.DeployConfig
	layout   *paths.Layout
	systemd  system.Systemd
}

// New 创建编排器；只做 status/logs/uninstall 时 reg 和 cfg 可以为 nil
func New(reg *protocol.Registry, cfg *config.DeployConfig, layout *paths.Layout) *Orchestrator {
	return &Orchestrator{registry: reg, cfg: cfg, layout: layout, systemd: system.Systemd{User: layout.User}}
}

// Conflict 描述一个无法按要求部署的组合，以及原因和建议
type Conflict struct {
	Subject    string
	Reason     string
	Suggestion string
}

// Port 是部署会占用的一个监听地址
type Port struct {
	Network string `json:"network"` // tcp | udp
	Addr    string `json:"addr"`
}

// Service 是规划后的一个协议服务
type Service struct {
	Cfg        *config.ProtocolConfig
	Adapter    protocol.Adapter
	SNI        string
	Network    string // tcp | udp
	PublicPort int
	ViaEntry   bool // 流量经过 Caddy 入口转发
	Runtime    protocol.Runtime
}

// Plan 是一次部署的完整规划，不包含任何副作用
type Plan struct {
	Caddy     caddy.Spec
	Services  []*Service
	Ports     []Port
	Certs     []config.Certificate
	Conflicts []Conflict
}

func loopback(n int) string { return fmt.Sprintf("127.0.0.1:%d", loopbackBase+n) }

func issuerFrom(c config.CertificateConfig) caddy.Issuer {
	iss := caddy.Issuer{Kind: "acme", Email: c.Email, DNSProvider: c.DNSProvider, DNSConfig: c.DNSConfig}
	switch c.Provider {
	case "internal":
		iss.Kind = "internal"
	case "acme":
		iss.CA = c.CA
	}
	return iss
}

// Plan 根据配置规划入口、路由、端口和证书，并说明无法满足的组合
func (o *Orchestrator) Plan() *Plan {
	c := o.cfg
	p := &Plan{}
	conflict := func(subject, reason, suggestion string) {
		p.Conflicts = append(p.Conflicts, Conflict{subject, reason, suggestion})
	}
	if c.Entry.HTTPSPort == c.Entry.HTTPPort {
		conflict("entry", fmt.Sprintf("https_port 和 http_port 都是 %d", c.Entry.HTTPPort), "为两者使用不同端口")
	}

	issuer := issuerFrom(c.Certificates)
	certNames := []string{c.Domain}
	seenCert := map[string]bool{c.Domain: true}
	addCert := func(name string) {
		if !seenCert[name] {
			seenCert[name] = true
			certNames = append(certNames, name)
		}
	}

	siteAddr, sitePlainAddr := loopback(0), loopback(1)
	nextLoopback := 2
	webHosts := map[string]bool{c.Domain: true}

	// 网站：未配置时提供一个默认静态站，同时作为协议的伪装和回落
	var sites []caddy.Site
	if len(c.Web) == 0 {
		sites = append(sites, caddy.Site{Root: o.layout.WWWDir()})
	}
	for _, w := range c.Web {
		site := caddy.Site{Host: w.Host, Root: w.Root, Upstream: w.Upstream}
		if w.Type == "static" && site.Root == "" {
			site.Root = o.layout.WWWDir()
		}
		if w.Host != "" {
			webHosts[w.Host] = true
			addCert(w.Host)
		}
		sites = append(sites, site)
	}

	tcpServers := map[int]*caddy.TCPServer{}
	var tcpOrder []int
	tcpServer := func(port int) *caddy.TCPServer {
		if s, ok := tcpServers[port]; ok {
			return s
		}
		s := &caddy.TCPServer{Port: port}
		tcpServers[port] = s
		tcpOrder = append(tcpOrder, port)
		return s
	}
	tcpServer(c.Entry.HTTPSPort) // 主入口总是存在，承载网站

	sniOwner := map[string]string{}
	udpByPort := map[int][]*Service{}
	var udpOrder []int

	for i := range c.Protocols {
		pc := &c.Protocols[i]
		if !pc.Enabled {
			continue
		}
		a, ok := o.registry.Get(pc.Name)
		if !ok {
			conflict(pc.Name, "未知协议", "目前支持 "+strings.Join(o.registry.Names(), ", "))
			continue
		}
		if v, ok := a.(protocol.Validator); ok {
			if err := v.Validate(pc); err != nil {
				conflict(pc.Name, err.Error(), "")
				continue
			}
		}
		sni := pc.SNI
		if sni == "" {
			sni = pc.Name + "." + c.Domain
		}
		port := pc.Port
		if port == 0 {
			port = c.Entry.HTTPSPort
		}
		svc := &Service{Cfg: pc, Adapter: a, SNI: sni, PublicPort: port}

		switch a.Transport() {
		case protocol.TransportTCP:
			svc.Network = "tcp"
			if port == c.Entry.HTTPPort {
				conflict(pc.Name, fmt.Sprintf("TCP/%d 是 HTTP 入口端口", port), "使用其他端口，或省略 port 与网站共享 HTTPS 入口")
				continue
			}
			if webHosts[sni] {
				conflict(pc.Name, fmt.Sprintf("SNI %s 与网站域名相同，入口无法区分网站和代理流量", sni),
					"为协议使用单独的子域名（sni 字段）")
				continue
			}
		case protocol.TransportUDP:
			svc.Network = "udp"
		default:
			conflict(pc.Name, "暂不支持同时监听 TCP 和 UDP 的协议", "")
			continue
		}

		key := fmt.Sprintf("%s/%d/%s", svc.Network, port, sni)
		if owner, dup := sniOwner[key]; dup {
			conflict(pc.Name, fmt.Sprintf("与 %s 在 %s/%d 上使用了相同的 SNI %s，入口无法区分", owner, svc.Network, port, sni),
				"为其中一个协议设置不同的 sni")
			continue
		}
		sniOwner[key] = pc.Name

		if svc.Network == "tcp" {
			svc.ViaEntry = true
			svc.Runtime.ListenAddr = loopback(nextLoopback)
			nextLoopback++
			srv := tcpServer(port)
			srv.Routes = append(srv.Routes, caddy.TCPRoute{Name: pc.Name, SNI: sni, Upstream: svc.Runtime.ListenAddr})
		} else {
			if _, ok := udpByPort[port]; !ok {
				udpOrder = append(udpOrder, port)
			}
			udpByPort[port] = append(udpByPort[port], svc)
		}

		addCert(sni)
		p.Services = append(p.Services, svc)
	}

	// UDP：网关按 QUIC SNI 把连接转给回环地址上的协议后端。
	// 主入口端口总有 UDP 网关，未匹配的 QUIC 连接交给内部网站的 HTTP/3
	if _, ok := udpByPort[c.Entry.HTTPSPort]; !ok {
		udpOrder = append([]int{c.Entry.HTTPSPort}, udpOrder...)
	}
	var udpServers []caddy.UDPServer
	for _, port := range udpOrder {
		srv := caddy.UDPServer{Port: port}
		for _, svc := range udpByPort[port] {
			svc.ViaEntry = true
			svc.Runtime.ListenAddr = loopback(nextLoopback)
			nextLoopback++
			srv.Routes = append(srv.Routes, caddy.UDPRoute{Name: svc.Cfg.Name, SNI: svc.SNI, Upstream: svc.Runtime.ListenAddr})
		}
		udpServers = append(udpServers, srv)
	}

	for _, name := range certNames {
		crt, key := caddy.CertPaths(o.layout.CaddyDataDir(), issuer, name)
		p.Certs = append(p.Certs, config.Certificate{Name: name, CertPath: crt, KeyPath: key})
	}
	for _, svc := range p.Services {
		svc.Runtime.SiteURL = "http://" + sitePlainAddr
		if cc, ok := svc.Adapter.(protocol.CertConsumer); ok && cc.NeedsCertificate() {
			for i := range p.Certs {
				if p.Certs[i].Name == svc.SNI {
					svc.Runtime.Cert = &p.Certs[i]
				}
			}
		}
	}

	var tcp []caddy.TCPServer
	for _, port := range tcpOrder {
		tcp = append(tcp, *tcpServers[port])
	}
	p.Caddy = caddy.Spec{
		AdminSocket:   o.layout.CaddyAdminSocket(),
		StorageRoot:   o.layout.CaddyDataDir(),
		Issuer:        issuer,
		CertNames:     certNames,
		DefaultSNI:    c.Domain,
		HTTPSPort:     c.Entry.HTTPSPort,
		HTTPPort:      c.Entry.HTTPPort,
		SiteAddr:      siteAddr,
		SitePlainAddr: sitePlainAddr,
		TCPServers:    tcp,
		UDPServers:    udpServers,
		Sites:         sites,
	}

	// 记录部署会占用的全部端口，用于部署前检查和后续重新部署
	add := func(network, addr string) { p.Ports = append(p.Ports, Port{network, addr}) }
	add("tcp", fmt.Sprintf(":%d", c.Entry.HTTPPort))
	add("tcp", siteAddr)
	add("udp", siteAddr) // 内部网站的 HTTP/3
	add("tcp", sitePlainAddr)
	for _, s := range tcp {
		add("tcp", fmt.Sprintf(":%d", s.Port))
	}
	for _, s := range udpServers {
		add("udp", fmt.Sprintf(":%d", s.Port))
	}
	for _, svc := range p.Services {
		add(svc.Network, svc.Runtime.ListenAddr)
	}
	sort.Slice(p.Ports, func(i, j int) bool {
		if p.Ports[i].Network != p.Ports[j].Network {
			return p.Ports[i].Network < p.Ports[j].Network
		}
		return p.Ports[i].Addr < p.Ports[j].Addr
	})
	return p
}

// ClientConfigs 返回各协议的客户端连接信息
func (o *Orchestrator) ClientConfigs(p *Plan) ([]*config.ClientConfig, error) {
	insecure := p.Caddy.Issuer.Kind == "internal"
	var out []*config.ClientConfig
	for _, s := range p.Services {
		cc, err := s.Adapter.ClientConfig(s.Cfg, protocol.ClientContext{
			Host:     o.cfg.Server.Address,
			Port:     s.PublicPort,
			SNI:      s.SNI,
			Insecure: insecure,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.Cfg.Name, err)
		}
		cc.Notes = append(cc.Notes, fmt.Sprintf("%s/%d，SNI %s", strings.ToUpper(s.Network), s.PublicPort, s.SNI))
		if insecure {
			cc.Notes = append(cc.Notes, "证书由内部 CA 签发，客户端需要跳过证书校验")
		}
		out = append(out, cc)
	}
	return out, nil
}

// checkPortFree 尝试绑定地址，判断是否被其他进程占用
func checkPortFree(port Port) error {
	switch port.Network {
	case "udp":
		l, err := net.ListenPacket("udp", port.Addr)
		if err != nil {
			return err
		}
		return l.Close()
	default:
		l, err := net.Listen("tcp", port.Addr)
		if err != nil {
			return err
		}
		return l.Close()
	}
}
