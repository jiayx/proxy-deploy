package gateway

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

func selfSigned(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// startGateway 在随机端口启动一个只含 server 的网关，返回监听地址
func startGateway(t *testing.T, s *Server, cert tls.Certificate) string {
	t.Helper()
	for _, r := range append(append([]*Route{}, s.Routes...), s.Fallback) {
		if r != nil {
			r.stats = new(routeStats)
		}
	}
	s.HandshakeTimeout = caddy.Duration(2 * time.Second)
	s.DialTimeout = caddy.Duration(2 * time.Second)
	s.logger = zap.NewNop()
	s.tlsConfig = func() *tls.Config { return &tls.Config{Certificates: []tls.Certificate{cert}} }
	ln := listen(t)
	go s.serve(ln)
	return ln.Addr().String()
}

// echoServer 把收到的数据原样写回
func echoServer(t *testing.T) string {
	ln := listen(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func TestPeekClientHello(t *testing.T) {
	a, b := net.Pipe()
	go tls.Client(a, &tls.Config{ServerName: "x.example.com", InsecureSkipVerify: true, NextProtos: []string{"h2"}}).Handshake()
	hello, peeked := peekClientHello(b)
	if hello == nil || hello.ServerName != "x.example.com" || len(hello.SupportedProtos) != 1 {
		t.Fatalf("unexpected hello: %+v", hello)
	}
	if len(peeked) == 0 || peeked[0] != 0x16 {
		t.Fatalf("peeked bytes should start with a TLS handshake record, got %x", peeked[:1])
	}

	a, b = net.Pipe()
	go a.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	hello, peeked = peekClientHello(b)
	if hello != nil || !strings.HasPrefix(string(peeked), "GET") {
		t.Fatalf("plain text should not parse as TLS: %+v %q", hello, peeked)
	}
}

func TestTerminateRoute(t *testing.T) {
	route := &Route{Name: "anytls", SNI: []string{"Proxy.Example.com"}, TLS: TLSTerminate, Upstream: echoServer(t)}
	addr := startGateway(t, &Server{Routes: []*Route{route}}, selfSigned(t, "proxy.example.com"))

	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "proxy.example.com", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo through terminated TLS failed: %q %v", buf, err)
	}
	if got := route.stats.Active.Load(); got != 1 {
		t.Fatalf("active connections = %d, want 1", got)
	}
	if got := route.stats.BytesUp.Load(); got != 5 {
		t.Fatalf("bytes up should be counted while the connection is open, got %d", got)
	}
	c.Close()
	waitFor(t, func() bool { return route.stats.Active.Load() == 0 && route.stats.Total.Load() == 1 })
}

func TestPassthroughWithProxyProtocol(t *testing.T) {
	// 后端是一个真正的 TLS 服务器，先读 PROXY 头，再完成 TLS 握手
	cert := selfSigned(t, "www.example.com")
	backend := listen(t)
	source := make(chan net.Addr, 1)
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		h, err := proxyproto.Read(br)
		if err != nil {
			t.Error(err)
			c.Close()
			return
		}
		source <- h.SourceAddr
		tc := tls.Server(&bufConn{Conn: c, r: br}, &tls.Config{Certificates: []tls.Certificate{cert}})
		io.Copy(tc, tc)
		tc.Close()
	}()

	fallback := &Route{Name: "site", TLS: TLSPassthrough, Upstream: backend.Addr().String(), ProxyProtocol: true}
	addr := startGateway(t, &Server{Fallback: fallback}, selfSigned(t, "unused"))

	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.ConnectionState().PeerCertificates[0].DNSNames[0]; got != "www.example.com" {
		t.Fatalf("passthrough should reach the backend certificate, got %s", got)
	}
	if src := <-source; src.String() != c.LocalAddr().String() {
		t.Fatalf("proxy protocol source = %s, want client address %s", src, c.LocalAddr())
	}
}

func TestNonTLSFallsBack(t *testing.T) {
	fallback := &Route{Name: "site", TLS: TLSPassthrough, Upstream: echoServer(t)}
	terminate := &Route{Name: "anytls", SNI: []string{"p.example.com"}, TLS: TLSTerminate, Upstream: echoServer(t)}
	addr := startGateway(t, &Server{Routes: []*Route{terminate}, Fallback: fallback}, selfSigned(t, "p.example.com"))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("PING\r\n"))
	buf := make([]byte, 6)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "PING\r\n" {
		t.Fatalf("plain traffic should reach fallback unchanged: %q %v", buf, err)
	}
}

func TestNoRouteCloses(t *testing.T) {
	route := &Route{Name: "anytls", SNI: []string{"p.example.com"}, TLS: TLSTerminate, Upstream: echoServer(t)}
	addr := startGateway(t, &Server{Routes: []*Route{route}}, selfSigned(t, "p.example.com"))

	_, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "other.example.com", InsecureSkipVerify: true})
	if err == nil {
		t.Fatal("connection without a matching route should be closed")
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

// 专用端口：首包像 TLS 记录头（声称后面还有 16KB）的随机字节也必须立即转发，不能等待识别
func TestRawServerForwardsWithoutInspection(t *testing.T) {
	fallback := &Route{Name: "ss2022", TLS: TLSPassthrough, Upstream: echoServer(t)}
	addr := startGateway(t, &Server{Fallback: fallback, Raw: true}, selfSigned(t, "unused"))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := []byte{0x16, 0x03, 0x01, 0x40, 0x00, 0xde, 0xad, 0xbe, 0xef}
	c.Write(msg)
	c.SetReadDeadline(time.Now().Add(time.Second)) // 小于握手超时（2 秒）
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != string(msg) {
		t.Fatalf("raw server should forward immediately: %x %v", buf, err)
	}
}
