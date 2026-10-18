package builtin

import (
	"testing"

	"github.com/jiayx/proxy-gateway/internal/protocol"
	"github.com/jiayx/proxy-gateway/pkg/paths"
)

// 每个协议都经网关转发，必须声明固定的回环端口，且互不相同、不占用内部网站的端口（20000、20001）
func TestLoopbackPorts(t *testing.T) {
	reg := Registry(paths.New("/opt/pd", false))
	owner := map[int]string{20000: "内部网站 HTTPS", 20001: "内部网站 HTTP"}
	for _, name := range reg.Names() {
		a, _ := reg.Get(name)
		lp, ok := a.(protocol.LoopbackPorter)
		if !ok {
			t.Errorf("%s is routed through the gateway but declares no loopback port", name)
			continue
		}
		port := lp.LoopbackPort()
		if other, dup := owner[port]; dup {
			t.Errorf("%s and %s both use loopback port %d", name, other, port)
		}
		owner[port] = name
	}
}
