package orchestrator

import (
	"fmt"
	"strings"
)

// unitFile 是一个待写入的 systemd unit 文件
type unitFile struct {
	Name    string
	Content string
}

func (o *Orchestrator) wantedBy() string {
	if o.layout.User {
		return "default.target"
	}
	return "multi-user.target"
}

// gatewayEnv 让网关（Caddy）的全部运行时文件都落在安装目录下
func (o *Orchestrator) gatewayEnv() []string {
	v := o.layout.VarDir()
	return []string{"XDG_DATA_HOME=" + v + "/xdg/data", "XDG_CONFIG_HOME=" + v + "/xdg/config"}
}

func (o *Orchestrator) gatewayUnit() unitFile {
	bin, cfg := o.layout.GatewayBin(), o.layout.GatewayConfig()
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=proxy-gateway (proxy-deploy entry gateway, website and protocol backends)\nAfter=network-online.target\nWants=network-online.target\n\n")
	fmt.Fprintf(&b, "[Service]\nType=notify\n")
	fmt.Fprintf(&b, "ExecStart=%s\n", execLine([]string{bin, "run", "--config", cfg}))
	fmt.Fprintf(&b, "ExecReload=%s\n", execLine([]string{bin, "reload", "--config", cfg, "--address", "unix/" + o.layout.GatewayAdminSocket()}))
	for _, e := range o.gatewayEnv() {
		fmt.Fprintf(&b, "Environment=%s\n", quoteArg(e))
	}
	b.WriteString("Restart=on-failure\nRestartSec=5\nTimeoutStopSec=10\n")
	if !o.layout.User {
		b.WriteString("LimitNOFILE=1048576\n")
	}
	fmt.Fprintf(&b, "\n[Install]\nWantedBy=%s\n", o.wantedBy())
	return unitFile{gatewayUnit, b.String()}
}

// execLine 把参数拼成 ExecStart 行：转义 systemd 的 % 说明符和 $ 变量，按需加引号
func execLine(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		a = strings.NewReplacer("%", "%%", "$", "$$").Replace(a)
		out[i] = quoteArg(a)
	}
	return strings.Join(out, " ")
}

func quoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\"'\\;") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}
