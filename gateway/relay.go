package gateway

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// relay 在 client 和 upstream 之间双向复制数据，直到两个方向都结束。
// 一个方向结束时半关闭对端的写方向，让对端知道不会再有数据（例如 HTTP/1.0 依赖它）。
// 每复制一段就累计到 up（client→upstream）和 down（upstream→client）中的每个计数器，
// 长连接的流量也能实时反映在统计里。
func relay(client, upstream net.Conn, up, down []*atomic.Int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyCounting(upstream, client, up)
		_ = closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		copyCounting(client, upstream, down)
		_ = closeWrite(client)
	}()
	wg.Wait()
	client.Close()
	upstream.Close()
}

func copyCounting(dst io.Writer, src io.Reader, counters []*atomic.Int64) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			for _, c := range counters {
				c.Add(int64(n))
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// closeWrite 半关闭连接的写方向；不支持半关闭的连接直接关闭
func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
