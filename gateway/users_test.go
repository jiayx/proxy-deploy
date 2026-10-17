package gateway

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
)

var runID atomic.Int64

// uniqueUser 返回本次运行专用的用户名；用户统计是进程级的，go test -count 重复运行时不能共用
func uniqueUser(base string) string { return fmt.Sprintf("%s-%d", base, runID.Add(1)) }

func userTotals(name string) (active, total, up, down int64) {
	s := statsForUser(name)
	return s.Active.Load(), s.Total.Load(), s.BytesUp.Load(), s.BytesDown.Load()
}

func TestLogAccounting(t *testing.T) {
	var tcpUp, tcpDown, udpUp, udpDown, anonUp, anonDown atomic.Int64
	tcpRec, tcpKey := trackConn("acct-test", "tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41001}, &tcpUp, &tcpDown)
	udpRec, udpKey := trackConn("acct-test", "udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41001}, &udpUp, &udpDown)
	anonRec, anonKey := trackConn("acct-test", "tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41002}, &anonUp, &anonDown)

	alice, bob := uniqueUser("alice"), uniqueUser("bob")
	a := logAccounting{backend: "acct-test", ports: map[string]int{}}
	for _, line := range []string{
		"INFO[0001] [11 0ms] inbound/anytls[acct-test]: inbound connection from 127.0.0.1:41001",
		"INFO[0001] [11 3ms] inbound/anytls[acct-test]: [" + alice + "] inbound connection to www.example.com:443",
		"INFO[0002] [12 0ms] inbound/shadowsocks[acct-test]: [" + bob + "] inbound packet connection from 127.0.0.1:41001",
		"INFO[0003] [13 0ms] inbound/anytls[acct-test]: inbound connection from 127.0.0.1:41002",   // 认证失败，没有后续行
		"INFO[0004] [14 0ms] inbound/anytls[acct-test]: inbound connection from 203.0.113.9:41003", // 不是经网关来的
		"ERROR[0005] [13 1ms] inbound/anytls[acct-test]: process connection from 127.0.0.1:41002: unknown user password",
	} {
		a.line(line)
	}
	if tcpRec.userName() != alice || udpRec.userName() != bob || anonRec.userName() != "" {
		t.Fatalf("attribution: tcp=%q udp=%q anon=%q", tcpRec.userName(), udpRec.userName(), anonRec.userName())
	}

	tcpUp.Add(100)
	tcpDown.Add(1000)
	anonUp.Add(7)
	flushAccounting()
	tcpUp.Add(5)
	untrackConn(tcpRec, tcpKey)
	untrackConn(udpRec, udpKey)
	untrackConn(anonRec, anonKey)
	if active, total, up, down := userTotals(alice); active != 0 || total != 1 || up != 105 || down != 1000 {
		t.Fatalf("alice: active=%d total=%d up=%d down=%d", active, total, up, down)
	}
	if _, total, _, _ := userTotals(bob); total != 1 {
		t.Fatalf("bob should have one connection, got %d", total)
	}
}

// 经网关的真实 TCP 连接：后端看到的来源端口出现在模拟的 sing-box 日志里，流量计入对应用户
func TestUserAccountingThroughGateway(t *testing.T) {
	backend := listen(t)
	ports := make(chan int, 1)
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		ports <- c.RemoteAddr().(*net.TCPAddr).Port
		io.Copy(c, c)
		c.Close()
	}()
	route := &Route{Name: "acct-route", TLS: TLSPassthrough, Upstream: backend.Addr().String()}
	addr := startGateway(t, &Server{Fallback: route, Raw: true}, selfSigned(t, "unused"))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	port := <-ports
	a := logAccounting{backend: "acct-route", ports: map[string]int{}}
	a.line(fmt.Sprintf("INFO[0001] [21 0ms] inbound/vless[acct-route]: inbound connection from 127.0.0.1:%d", port))
	carol := uniqueUser("carol")
	a.line("INFO[0001] [21 5ms] inbound/vless[acct-route]: [" + carol + "] inbound connection to example.com:443")

	c.Write([]byte("hello"))
	io.ReadFull(c, make([]byte, 5))
	flushAccounting()
	if active, total, up, down := userTotals(carol); active != 1 || total != 1 || up != 5 || down != 5 {
		t.Fatalf("while open: active=%d total=%d up=%d down=%d", active, total, up, down)
	}
	c.Close()
	waitFor(t, func() bool { active, _, _, _ := userTotals(carol); return active == 0 })
}

func TestUsagePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	usage.path, usage.loaded = "", false
	defer func() { usage.path, usage.loaded = "", false }()

	setUsageFile(path, zap.NewNop())
	dave := uniqueUser("dave")
	s := statsForUser(dave)
	s.BytesUp.Store(123)
	s.BytesDown.Store(456)
	s.Total.Store(3)
	if err := saveUsage(); err != nil {
		t.Fatal(err)
	}

	s.BytesUp.Store(0)
	s.BytesDown.Store(0)
	usage.loaded = false
	setUsageFile(path, zap.NewNop())
	if _, total, up, down := userTotals(dave); total != 3 || up != 123 || down != 456 {
		t.Fatalf("restored total=%d up=%d down=%d", total, up, down)
	}
}
