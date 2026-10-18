// Command proxy-gateway 是整个项目唯一的程序：
//   - 部署和运维命令（deploy、status、logs……），见 internal/cli
//   - 服务器上运行的网关：官方 Caddy 的标准模块加上本仓库的网关模块，服务里执行 proxy-gateway run
//
// 依赖版本由仓库的 go.mod 固定，直接 go build 即可构建。
package main

import (
	"os"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	// Cloudflare DNS 验证：配置 dns_provider: cloudflare 时用来申请通配符证书
	_ "github.com/caddy-dns/cloudflare"
	_ "github.com/jiayx/proxy-gateway/gateway"
	"github.com/jiayx/proxy-gateway/internal/cli"
)

func main() {
	if cli.Handles(os.Args[1:]) {
		cli.Main(os.Args[1:])
		return
	}
	caddycmd.Main() // run、reload、validate、build-info 等 Caddy 命令
}
