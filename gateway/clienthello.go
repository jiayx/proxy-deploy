package gateway

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
)

var errHelloCaptured = errors.New("client hello captured")

// peekClientHello 从 conn 读取并解析 TLS ClientHello，返回解析结果和读取过的全部字节。
// 不是 TLS 流量时 hello 为 nil。读到的字节需要原样回放给后续处理（终结或透传）。
//
// 借用 crypto/tls 的握手解析：GetConfigForClient 拿到 ClientHello 后立即中止握手，
// 期间写往客户端的数据（告警）全部丢弃，所以对客户端没有任何副作用。
func peekClientHello(conn net.Conn) (*tls.ClientHelloInfo, []byte) {
	var buf bytes.Buffer
	var hello *tls.ClientHelloInfo
	rc := readOnlyConn{Conn: conn, r: io.TeeReader(conn, &buf)}
	_ = tls.Server(rc, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			info := *h
			info.Conn = nil
			hello = &info
			return nil, errHelloCaptured
		},
	}).Handshake()
	return hello, buf.Bytes()
}

// readOnlyConn 从 r 读取，丢弃所有写入
type readOnlyConn struct {
	net.Conn
	r io.Reader
}

func (c readOnlyConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error) { return len(p), nil }

// prefixConn 先回放已经读取过的字节，再继续从底层连接读取
type prefixConn struct {
	net.Conn
	r io.Reader
}

func newPrefixConn(conn net.Conn, prefix []byte) net.Conn {
	if len(prefix) == 0 {
		return conn
	}
	return &prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(prefix), conn)}
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite 透传给底层连接，保证半关闭语义
func (c *prefixConn) CloseWrite() error { return closeWrite(c.Conn) }
