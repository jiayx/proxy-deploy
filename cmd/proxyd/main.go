package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/entry/caddy"
	"github.com/jiayx/proxy-deploy/internal/orchestrator"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/internal/protocol/anytls"
	"github.com/jiayx/proxy-deploy/internal/protocol/hysteria2"
	"github.com/jiayx/proxy-deploy/internal/protocol/vlessreality"
	"github.com/jiayx/proxy-deploy/pkg/paths"
)

const usage = `用法: proxyd [选项] <命令>

命令:
  init-config      输出示例 deploy.yaml
  plan             检查配置，显示入口规划（不做任何变更）
  deploy           安装并启动全部服务（可重复执行以更新）
  client-config    输出客户端连接 URI
  status           查看服务状态和证书有效期
  logs <服务>      查看日志（caddy 或协议名）
  restart [服务]   重启全部或指定服务
  uninstall        停止并删除全部服务和安装目录

选项:
`

func main() {
	fs := flag.NewFlagSet("proxyd", flag.ExitOnError)
	cfgPath := fs.String("c", "deploy.yaml", "配置文件路径")
	prefix := fs.String("prefix", "", "安装目录（默认 /opt/proxy-deploy，--user 时 ~/.local/proxy-deploy）")
	user := fs.Bool("user", false, "rootless 模式：使用 systemd --user，无需 root（只能使用 1024 以上端口）")
	caddyBin := fs.String("caddy-binary", "", "使用本地已构建的 caddy（需含 caddy-l4）")
	showCaddy := fs.Bool("show-caddy", false, "plan 时输出生成的 Caddy 配置")
	lines := fs.Int("n", 50, "logs 显示的行数")
	follow := fs.Bool("f", false, "logs 持续输出")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	_ = fs.Parse(os.Args[1:])

	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]
	// 允许把选项放在命令后面，例如 proxyd logs anytls -f
	_ = fs.Parse(rest)
	rest = fs.Args()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	layout := paths.New(*prefix, *user)
	if err := run(ctx, cmd, rest, layout, *cfgPath, *caddyBin, *showCaddy, *lines, *follow); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd string, rest []string, layout *paths.Layout,
	cfgPath, caddyBin string, showCaddy bool, lines int, follow bool) error {

	logf := func(format string, a ...any) { fmt.Printf("==> "+format+"\n", a...) }

	switch cmd {
	case "init-config":
		fmt.Print(config.Example())
		return nil

	// 以下命令只依赖安装清单，不需要配置文件
	case "status":
		orch := orchestrator.New(nil, nil, layout)
		units, certs, err := orch.Status(ctx)
		if err != nil {
			return err
		}
		fmt.Println("服务:")
		for _, u := range units {
			mark := "✓"
			if u.State != "active" {
				mark = "✗"
			}
			fmt.Printf("  %s %-40s %s\n", mark, u.Unit, u.State)
		}
		fmt.Println("协议后端:")
		if backends, err := orch.Backends(ctx); err != nil {
			fmt.Printf("  ✗ 读取状态失败：%v\n", err)
		} else {
			for _, b := range backends {
				mark, detail := "✓", fmt.Sprintf("pid %d，已运行 %s", b.PID, (time.Duration(b.Uptime)*time.Second).String())
				if b.State != "running" {
					mark, detail = "✗", b.LastExit
				}
				if b.Restarts > 0 {
					detail += fmt.Sprintf("，重启过 %d 次", b.Restarts)
				}
				fmt.Printf("  %s %-40s %s（%s）\n", mark, b.Name, b.State, detail)
			}
		}
		fmt.Println("证书:")
		for _, c := range certs {
			if c.Err != nil {
				fmt.Printf("  ✗ %-40s %v\n", c.Name, c.Err)
				continue
			}
			mark := "✓"
			if !time.Now().Before(c.NotAfter) {
				mark = "✗"
			}
			fmt.Printf("  %s %-40s 到期 %s（%s）\n", mark, c.Name, c.NotAfter.Local().Format("2006-01-02 15:04"), remaining(time.Until(c.NotAfter)))
		}
		fmt.Println("网关:")
		if stats, err := orch.GatewayStats(ctx); err != nil {
			fmt.Printf("  ✗ 读取统计失败：%v\n", err)
		} else {
			for _, s := range stats {
				fmt.Printf("  %-14s 活动 %-4d 累计 %-8d ↑ %-10s ↓ %s\n", s.Route, s.Active, s.Total, humanBytes(s.BytesUp), humanBytes(s.BytesDown))
			}
		}
		if layout.User && !orch.Lingering(ctx) {
			fmt.Printf("\n警告：当前用户未开启 linger，注销后服务会被停止。执行 sudo loginctl enable-linger $USER 开启\n")
		}
		return nil
	case "logs":
		if len(rest) == 0 {
			return errors.New("用法: proxyd logs <caddy|协议名> [-n 行数] [-f]")
		}
		return orchestrator.New(nil, nil, layout).Logs(ctx, rest[0], lines, follow)
	case "restart":
		name := ""
		if len(rest) > 0 {
			name = rest[0]
		}
		return orchestrator.New(nil, nil, layout).Restart(ctx, name)
	case "uninstall":
		if err := orchestrator.New(nil, nil, layout).Uninstall(ctx, logf); err != nil {
			return err
		}
		fmt.Println("已卸载")
		return nil
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	reg := protocol.NewRegistry()
	reg.Register(hysteria2.New(layout))
	reg.Register(anytls.New(layout))
	reg.Register(vlessreality.New(layout))
	orch := orchestrator.New(reg, cfg, layout)
	plan := orch.Plan()

	switch cmd {
	case "plan":
		printPlan(plan)
		if showCaddy {
			data, err := caddy.Generate(plan.Caddy)
			if err != nil {
				return err
			}
			fmt.Printf("\nCaddy 配置:\n%s\n", data)
		}
		if len(plan.Conflicts) > 0 {
			return errors.New("规划存在冲突")
		}
		return nil
	case "deploy":
		printPlan(plan)
		fmt.Println()
		if err := orch.Deploy(ctx, plan, caddyBin, logf); err != nil {
			return err
		}
		fmt.Println("\n部署完成。客户端配置:")
		return printClients(orch, plan)
	case "client-config":
		return printClients(orch, plan)
	}
	return fmt.Errorf("未知命令 %q", cmd)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// remaining 把证书剩余有效期格式化为天或小时（内部 CA 的证书只有 12 小时）
func remaining(d time.Duration) string {
	switch {
	case d <= 0:
		return "已过期"
	case d >= 48*time.Hour:
		return fmt.Sprintf("剩余 %d 天", int(d.Hours()/24))
	default:
		return fmt.Sprintf("剩余 %d 小时", int(d.Hours()))
	}
}

func printPlan(p *orchestrator.Plan) {
	fmt.Println("入口:")
	for _, s := range p.Caddy.TCPServers {
		fmt.Printf("  TCP/%-5d 网关", s.Port)
		var parts []string
		for _, r := range s.Routes {
			mode := ""
			if r.Passthrough {
				mode = "（透传）"
			}
			parts = append(parts, fmt.Sprintf("%s → %s%s", r.SNI, r.Upstream, mode))
		}
		parts = append(parts, "其他 → 网站 "+p.Caddy.SiteAddr)
		fmt.Printf("  %s\n", strings.Join(parts, "；"))
	}
	for _, s := range p.Caddy.UDPServers {
		var parts []string
		for _, r := range s.Routes {
			parts = append(parts, fmt.Sprintf("%s → %s", r.SNI, r.Upstream))
		}
		if s.Port == p.Caddy.HTTPSPort {
			parts = append(parts, "其他 → 网站 HTTP/3 "+p.Caddy.SiteAddr)
		}
		fmt.Printf("  UDP/%-5d 网关  %s\n", s.Port, strings.Join(parts, "；"))
	}
	fmt.Printf("  TCP/%-5d HTTP 跳转 HTTPS / ACME 验证\n", p.Caddy.HTTPPort)

	fmt.Println("协议:")
	for _, s := range p.Services {
		cert := "由网关终结 TLS"
		switch {
		case s.Runtime.Cert != nil:
			cert = "读取证书 " + s.Runtime.Cert.Name
		case s.Passthrough:
			cert = "自行处理 TLS（网关透传）"
		}
		fmt.Printf("  %-14s %s/%d  SNI %-28s 监听 %-16s %s\n",
			s.Cfg.Name, s.Network, s.PublicPort, s.SNI, s.Runtime.ListenAddr, cert)
	}

	fmt.Printf("证书（%s）:\n", p.Caddy.Issuer.Kind)
	for _, c := range p.Certs {
		fmt.Printf("  %s\n", c.Name)
	}

	if len(p.Conflicts) > 0 {
		fmt.Println("冲突:")
		for _, c := range p.Conflicts {
			fmt.Printf("  ✗ %s：%s\n", c.Subject, c.Reason)
			if c.Suggestion != "" {
				fmt.Printf("    建议：%s\n", c.Suggestion)
			}
		}
	}
}

func printClients(orch *orchestrator.Orchestrator, p *orchestrator.Plan) error {
	ccs, err := orch.ClientConfigs(p)
	if err != nil {
		return err
	}
	for _, cc := range ccs {
		fmt.Printf("[%s]\n  %s\n", cc.Protocol, cc.URI)
		for _, n := range cc.Notes {
			fmt.Printf("  · %s\n", n)
		}
	}
	return nil
}
