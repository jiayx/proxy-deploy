// Command proxy-gateway 是 proxy-deploy 的网关程序：官方 Caddy 的标准模块加上本仓库的入口网关模块 proxy_gateway。
// 依赖版本由仓库的 go.mod 固定，直接 go build 即可构建。
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/jiayx/proxy-deploy/gateway"
)

func main() {
	caddycmd.Main()
}
