package gateway

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

func (s *Server) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Warn("accept", zap.Error(err))
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handle(conn)
	}
}

// match 按 SNI 选择路由（不区分大小写），都不匹配时返回 fallback（可能为 nil）
func (s *Server) match(sni string) *Route {
	if sni != "" {
		for _, r := range s.Routes {
			for _, name := range r.SNI {
				if strings.EqualFold(name, sni) {
					return r
				}
			}
		}
	}
	return s.Fallback
}

func (s *Server) handle(conn net.Conn) {
	start := time.Now()
	_ = conn.SetReadDeadline(start.Add(time.Duration(s.HandshakeTimeout)))
	hello, peeked := peekClientHello(conn)
	sni := ""
	if hello != nil {
		sni = hello.ServerName
	}
	route := s.match(sni)
	log := s.logger.With(zap.String("remote", conn.RemoteAddr().String()), zap.String("sni", sni))
	if route == nil {
		log.Debug("no route")
		conn.Close()
		return
	}
	log = log.With(zap.String("route", route.Name))

	client := newPrefixConn(conn, peeked)
	if route.TLS == TLSTerminate {
		if hello == nil {
			log.Debug("not a TLS connection")
			conn.Close()
			return
		}
		tc := tls.Server(client, s.tlsConfig())
		if err := tc.Handshake(); err != nil {
			log.Debug("tls handshake", zap.Error(err))
			conn.Close()
			return
		}
		client = tc
	}
	_ = conn.SetReadDeadline(time.Time{})

	upstream, err := net.DialTimeout("tcp", route.Upstream, time.Duration(s.DialTimeout))
	if err != nil {
		log.Warn("dial upstream", zap.String("upstream", route.Upstream), zap.Error(err))
		client.Close()
		return
	}
	if route.ProxyProtocol {
		header := proxyproto.HeaderProxyFromAddrs(2, conn.RemoteAddr(), conn.LocalAddr())
		if _, err := header.WriteTo(upstream); err != nil {
			log.Warn("write proxy protocol header", zap.Error(err))
			client.Close()
			upstream.Close()
			return
		}
	}

	st := route.stats
	st.Active.Add(1)
	st.Total.Add(1)
	var up, down atomic.Int64
	relay(client, upstream, []*atomic.Int64{&up, &st.BytesUp}, []*atomic.Int64{&down, &st.BytesDown})
	st.Active.Add(-1)

	// 后端本地地址对应 sing-box 日志里的 "inbound connection from 127.0.0.1:<端口>"，
	// 用它可以把客户端真实地址和后端看到的连接对应起来
	log.Info("connection closed",
		zap.String("upstream", route.Upstream),
		zap.String("upstream_local", upstream.LocalAddr().String()),
		zap.Int64("bytes_up", up.Load()),
		zap.Int64("bytes_down", down.Load()),
		zap.Duration("duration", time.Since(start)),
	)
}
