package gateway

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
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
	table := newUDPTable()
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

// rebindingRelay 在客户端和网关之间转发数据报，rebind 后改用新的本地端口发往网关，
// 模拟 NAT 重新映射：客户端毫无感知，网关看到的客户端地址变了
type rebindingRelay struct {
	front  net.PacketConn // 面向客户端
	target *net.UDPAddr
	client atomic.Pointer[net.UDPAddr]
	back   atomic.Pointer[net.UDPConn] // 面向网关，rebind 时替换
}

func newRebindingRelay(t *testing.T, target string) *rebindingRelay {
	t.Helper()
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &rebindingRelay{front: front}
	r.target, _ = net.ResolveUDPAddr("udp", target)
	t.Cleanup(func() { front.Close(); r.back.Load().Close() })
	r.rebind(t)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			r.client.Store(addr.(*net.UDPAddr))
			r.back.Load().WriteTo(buf[:n], r.target)
		}
	}()
	return r
}

func (r *rebindingRelay) rebind(t *testing.T) {
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if old := r.back.Swap(back); old != nil {
		go func() { time.Sleep(time.Second); old.Close() }() // 旧端口上迟到的回包仍转回客户端
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			if c := r.client.Load(); c != nil {
				r.front.WriteTo(buf[:n], c)
			}
		}
	}()
}

func echo(t *testing.T, str *quic.Stream, msg string) {
	t.Helper()
	str.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := str.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(str, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo %q failed: %q %v", msg, buf, err)
	}
}

func TestUDPClientAddressChange(t *testing.T) {
	hy2 := &Route{Name: "hysteria2", SNI: []string{"hy2.example.com"}, TLS: TLSPassthrough, Upstream: quicEchoServer(t, "hy2.example.com")}
	gw := startUDPGateway(t, &Server{Routes: []*Route{hy2}})
	relay := newRebindingRelay(t, gw)

	conn, err := dialQUIC(relay.front.LocalAddr().String(), "hy2.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	str, _ := conn.OpenStreamSync(context.Background())
	echo(t, str, "before")

	time.Sleep(migrateQuiet + 200*time.Millisecond) // 原地址静默，模拟切换网络的间隙
	relay.rebind(t)
	echo(t, str, "after")

	if got := hy2.stats.Total.Load(); got != 1 {
		t.Fatalf("address change should keep the same session, got %d sessions", got)
	}
}

func TestUDPMigrationRequiresQuietOldAddress(t *testing.T) {
	table := newUDPTable()
	upstream, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer upstream.Close()
	sess := &udpSession{key: "1.1.1.1:1000", route: &Route{stats: new(routeStats)}, log: zap.NewNop()}
	sess.upstream, _ = net.DialUDP("udp", nil, upstream.LocalAddr().(*net.UDPAddr))
	defer sess.upstream.Close()
	old := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1000}
	sess.client.Store(old)
	sess.established.Store(true)
	table.sessions[sess.key] = sess
	table.addCID(sess, "\x01\x02\x03\x04")

	shortHeader := []byte{0x40, 1, 2, 3, 4, 0xaa, 0xbb}
	spoofed := &net.UDPAddr{IP: net.IPv4(6, 6, 6, 6), Port: 6666}

	sess.lastFromClient.Store(time.Now().UnixNano()) // 原地址刚刚还在通信
	table.handle(spoofed, shortHeader)
	if sess.client.Load() != old || table.sessions["6.6.6.6:6666"] != nil {
		t.Fatal("must not move an active session to a new address")
	}

	sess.lastFromClient.Store(time.Now().Add(-2 * migrateQuiet).UnixNano()) // 原地址已静默
	table.handle(spoofed, shortHeader)
	if sess.client.Load().String() != "6.6.6.6:6666" || table.sessions["6.6.6.6:6666"] != sess || table.sessions["1.1.1.1:1000"] != nil {
		t.Fatal("session should follow the client to its new address")
	}
}

func TestUDPConnectionIDsKeepMostRecent(t *testing.T) {
	table := newUDPTable()
	sess := &udpSession{}
	for i := 0; i < maxSessionCIDs+2; i++ {
		table.addCID(sess, string(rune('a'+i)))
	}
	if len(sess.cids) != maxSessionCIDs || len(table.cids) != maxSessionCIDs {
		t.Fatalf("want %d connection IDs, got session=%d table=%d", maxSessionCIDs, len(sess.cids), len(table.cids))
	}
	if table.cids["a"] != nil || table.cids["b"] != nil || table.cids[string(rune('a'+maxSessionCIDs+1))] != sess {
		t.Fatal("oldest connection IDs should be evicted first")
	}
}

// udpEchoServer 把收到的数据报原样发回
func udpEchoServer(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestUDPRawServer(t *testing.T) {
	ss := &Route{Name: "ss2022", TLS: TLSPassthrough, Upstream: udpEchoServer(t)}
	gw := startUDPGateway(t, &Server{Fallback: ss, Raw: true})
	c, err := net.Dial("udp", gw)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, msg := range []string{"random bytes, not QUIC", "\xc0\x00\x00\x00\x01 looks like a QUIC long header"} {
		c.Write([]byte(msg))
		c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 100)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != msg {
			t.Fatalf("raw UDP should forward any datagram: %q %v", buf[:n], err)
		}
	}
	if ss.stats.Total.Load() != 1 || ss.stats.Active.Load() != 1 {
		t.Fatalf("want one session, got total=%d active=%d", ss.stats.Total.Load(), ss.stats.Active.Load())
	}
}
