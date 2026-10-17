package gateway

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// quicEchoServer 启动一个 QUIC 服务器，把每条流的数据原样写回
func quicEchoServer(t *testing.T, names ...string) string {
	t.Helper()
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t, names...)},
		NextProtos:   []string{"echo"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					str, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() { io.Copy(str, str); str.Close() }()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func startUDPGateway(t *testing.T, s *Server) string {
	t.Helper()
	for _, r := range append(append([]*Route{}, s.Routes...), s.Fallback) {
		if r != nil {
			r.stats = new(routeStats)
		}
	}
	s.HandshakeTimeout = caddy.Duration(2 * time.Second)
	s.IdleTimeout = caddy.Duration(time.Minute)
	s.logger = zap.NewNop()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	table := &udpTable{sessions: map[string]*udpSession{}}
	table.attach(s, pc)
	go s.serveUDP(pc, table)
	t.Cleanup(func() { pc.Close(); table.detach(pc) })
	return pc.LocalAddr().String()
}

func dialQUIC(addr, sni string) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return quic.DialAddr(ctx, addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"echo"}}, nil)
}

func TestUDPRouteBySNI(t *testing.T) {
	hy2 := &Route{Name: "hysteria2", SNI: []string{"hy2.example.com"}, TLS: TLSPassthrough, Upstream: quicEchoServer(t, "hy2.example.com")}
	site := &Route{Name: "site", TLS: TLSPassthrough, Upstream: quicEchoServer(t, "www.example.com")}
	addr := startUDPGateway(t, &Server{Routes: []*Route{hy2}, Fallback: site})

	for sni, want := range map[string]*Route{"hy2.example.com": hy2, "www.example.com": site} {
		conn, err := dialQUIC(addr, sni)
		if err != nil {
			t.Fatalf("%s: %v", sni, err)
		}
		if got := conn.ConnectionState().TLS.PeerCertificates[0].DNSNames[0]; got != sni {
			t.Fatalf("%s routed to backend with certificate %s", sni, got)
		}
		str, _ := conn.OpenStreamSync(context.Background())
		str.Write([]byte("ping"))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(str, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("%s: echo failed: %q %v", sni, buf, err)
		}
		if want.stats.Active.Load() != 1 || want.stats.BytesUp.Load() == 0 || want.stats.BytesDown.Load() == 0 {
			t.Fatalf("%s: unexpected stats active=%d up=%d down=%d", sni, want.stats.Active.Load(), want.stats.BytesUp.Load(), want.stats.BytesDown.Load())
		}
		conn.CloseWithError(0, "")
	}
}

func TestUDPNoRoute(t *testing.T) {
	hy2 := &Route{Name: "hysteria2", SNI: []string{"hy2.example.com"}, TLS: TLSPassthrough, Upstream: quicEchoServer(t, "hy2.example.com")}
	addr := startUDPGateway(t, &Server{Routes: []*Route{hy2}})
	if _, err := dialQUIC(addr, "other.example.com"); err == nil {
		t.Fatal("connection without a matching route should not be established")
	}
	if hy2.stats.Total.Load() != 0 {
		t.Fatal("unmatched connection must not reach the backend")
	}
}
