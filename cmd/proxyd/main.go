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
	"github.com/jiayx/proxy-deploy/internal/protocol/builtin"
	"github.com/jiayx/proxy-deploy/pkg/paths"
)

const usage = `用法: proxyd [选项] <命令>

命令:
  init-config      输出示例 deploy.yaml
  plan             检查配置，显示入口规划（不做任何变更）
  deploy           安装并启动全部服务（可重复执行以更新）
  client-config [用户]  输出客户端连接 URI（默认全部用户）
  status           查看服务状态和证书有效期
  version          查看 proxyd、网关、sing-box 的版本，检查是否有新版本
  logs <服务>      查看日志（gateway 或协议名）
  restart [服务]   重启全部或指定服务
  uninstall        停止并删除全部服务和安装目录

选项:
`

func main() {
	fs := flag.NewFlagSet("proxyd", flag.ExitOnError)
	cfgPath := fs.String("c", "deploy.yaml", "配置文件路径")
	prefix := fs.String("prefix", "", "安装目录（默认 /opt/proxy-deploy，--user 时 ~/.local/proxy-deploy）")
	user := fs.Bool("user", false, "rootless 模式：使用 systemd --user，无需 root（只能使用 1024 以上端口）")
	gatewayBin := fs.String("gateway-binary", "", "使用本地构建的网关（go build ./cmd/proxy-gateway）代替发布的预构建版本")
	showConfig := fs.Bool("show-config", false, "plan 时输出生成的网关配置（Caddy JSON）")
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
	if err := run(ctx, cmd, rest, layout, *cfgPath, *gatewayBin, *showConfig, *lines, *follow); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd string, rest []string, layout *paths.Layout,
	cfgPath, gatewayBin string, showConfig bool, lines int, follow bool) error {

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
		fmt.Println("用户:")
		if list, err := orch.UserStats(ctx); err != nil {
			fmt.Printf("  ✗ 读取统计失败：%v\n", err)
		} else {
			for _, u := range list {
				printUser(u)
			}
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
	case "version":
		vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		printVersions(orchestrator.New(nil, nil, layout).Versions(vctx))
		return nil
	case "logs":
		if len(rest) == 0 {
			return errors.New("用法: proxyd logs <gateway|协议名> [-n 行数] [-f]")
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
	reg := builtin.Registry(layout)
	orch := orchestrator.New(reg, cfg, layout)
	plan := orch.Plan()

	switch cmd {
	case "plan":
		printPlan(plan)
		if showConfig {
			data, err := caddy.Generate(plan.Caddy)
			if err != nil {
				return err
			}
			fmt.Printf("\n网关配置（Caddy JSON）:\n%s\n", data)
		}
		if len(plan.Conflicts) > 0 {
			return errors.New("规划存在冲突")
		}
		return nil
	case "deploy":
		printPlan(plan)
		fmt.Println()
		if err := orch.Deploy(ctx, plan, gatewayBin, logf); err != nil {
			return err
		}
		fmt.Println("\n部署完成。客户端配置:")
		return printClients(orch, plan, "")
	case "client-config":
		user := ""
		if len(rest) > 0 {
			user = rest[0]
		}
		return printClients(orch, plan, user)
	}
	return fmt.Errorf("未知命令 %q", cmd)
}

var userStates = map[string]string{"active": "正常", "over_limit": "已超额", "expired": "已到期"}

func printUser(u orchestrator.UserStats) {
	mark := "✓"
	if u.State != "active" {
		mark = "✗"
	}
	usage := humanBytes(u.PeriodUp + u.PeriodDown)
	if u.TrafficLimit > 0 {
		usage += " / " + humanBytes(u.TrafficLimit)
	}
	since := ""
	if t, err := time.Parse(time.RFC3339, u.PeriodStart); err == nil {
		since = "（" + t.Format("01-02") + " 起）"
	}
	expire := ""
	if t, err := time.Parse(time.RFC3339, u.Expire); err == nil {
		expire = "，" + t.Add(-time.Second).Format("2006-01-02") + " 到期"
	}
	protocols := ""
	if len(u.Protocols) > 0 {
		protocols = "，仅限 " + strings.Join(u.Protocols, "、")
	}
	fmt.Printf("  %s %-12s %-6s 本周期 %s%s，活动连接 %d%s%s\n", mark, u.User, userStates[u.State], usage, since, u.Active, expire, protocols)
	fmt.Printf("    累计 ↑ %s ↓ %s，%d 个连接\n", humanBytes(u.BytesUp), humanBytes(u.BytesDown), u.Total)
}

// short 返回提交哈希的前 7 位和提交日期
func short(b caddy.Build) string {
	rev := b.Revision
	if len(rev) > 7 {
		rev = rev[:7]
	}
	s := rev
	if !b.Time.IsZero() {
		s += "（" + b.Time.Local().Format("2006-01-02") + "）"
	}
	if b.Modified {
		s += "，含未提交的修改"
	}
	return s
}

func printVersions(v *orchestrator.Versions) {
	// proxyd 本身：与仓库 main 分支比较
	switch {
	case v.ProxydErr != nil:
		fmt.Printf("proxyd    未知：%v\n", v.ProxydErr)
	default:
		fmt.Printf("proxyd    %s\n", short(v.Proxyd))
	}
	switch {
	case v.MainErr != nil:
		fmt.Printf("          无法检查新版本：%v\n", v.MainErr)
	case v.ProxydErr != nil:
		fmt.Printf("          仓库 main 最新提交 %s\n", short(v.Main))
	case v.Main.Revision == v.Proxyd.Revision:
		fmt.Println("          ✓ 与仓库 main 一致")
	case v.Proxyd.Time.After(v.Main.Time):
		fmt.Printf("          本地提交，比仓库 main %s 新\n", short(v.Main))
	default:
		fmt.Printf("          ↑ 仓库 main 已更新到 %s，拉取后重新构建 proxyd\n", short(v.Main))
	}

	// 网关：与发布的预构建版本比较，deploy 总是安装发布版本（除非指定 --gateway-binary）
	if v.GatewayErr != nil {
		fmt.Println("网关      未安装")
	} else {
		fmt.Printf("网关      proxy-gateway %s，基于 Caddy %s\n", short(*v.Gateway), v.Gateway.Caddy)
		if v.LocalGateway {
			fmt.Println("          用 --gateway-binary 安装的本地构建，deploy 不会自动更新")
		}
	}
	switch {
	case v.ReleaseErr != nil:
		fmt.Printf("          无法检查发布版本：%v\n", v.ReleaseErr)
	case v.GatewayErr != nil:
		fmt.Printf("          发布版本 %s，deploy 时安装\n", short(*v.GatewayRelease))
	case v.Gateway.Revision == v.GatewayRelease.Revision && !v.Gateway.Modified:
		fmt.Println("          ✓ 与发布版本一致")
	case v.Gateway.Modified || v.Gateway.Time.After(v.GatewayRelease.Time):
		fmt.Printf("          本地构建；发布版本是 %s\n", short(*v.GatewayRelease))
	default:
		fmt.Printf("          ↑ 发布版本已更新到 %s，执行 deploy 升级（网关会重启）\n", short(*v.GatewayRelease))
	}

	// sing-box：版本固定在 proxyd 中
	if v.SingBoxErr != nil {
		fmt.Printf("sing-box  未安装（proxyd 使用 %s）\n", orchestrator.SingBoxPinned)
	} else {
		fmt.Printf("sing-box  %s\n", v.SingBox)
		if v.SingBox != orchestrator.SingBoxPinned {
			fmt.Printf("          当前 proxyd 使用 %s，执行 deploy 更换\n", orchestrator.SingBoxPinned)
		}
	}
	switch {
	case v.SingBoxUpErr != nil:
		fmt.Printf("          无法检查上游版本：%v\n", v.SingBoxUpErr)
	case v.SingBoxLatest == orchestrator.SingBoxPinned:
		fmt.Println("          ✓ 已是上游最新正式版")
	default:
		fmt.Printf("          上游最新正式版是 %s；proxyd 固定使用 %s，升级需要更新 proxyd\n", v.SingBoxLatest, orchestrator.SingBoxPinned)
	}
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
	for _, s := range p.Services {
		if s.Dedicated {
			fmt.Printf("  %s/%d 网关（专用端口，不识别直接转发）→ %s %s\n", strings.ToUpper(s.Network), s.PublicPort, s.Cfg.Name, s.Runtime.ListenAddr)
		}
	}

	fmt.Println("协议:")
	for _, s := range p.Services {
		cert, sni := "由网关终结 TLS", s.SNI
		switch {
		case s.Dedicated:
			cert, sni = "无 TLS，网关专用端口转发", "—"
		case s.Runtime.Cert != nil:
			cert = "读取证书 " + s.Runtime.Cert.Name
		case s.Passthrough:
			cert = "自行处理 TLS（网关透传）"
		}
		users := ""
		if len(s.Runtime.Users) < len(p.Caddy.Users) {
			var names []string
			for _, u := range s.Runtime.Users {
				names = append(names, u.Name)
			}
			users = "，仅限用户 " + strings.Join(names, "、")
		}
		fmt.Printf("  %-14s %s/%d  SNI %-28s 监听 %-16s %s%s\n",
			s.Cfg.Name, s.Network, s.PublicPort, sni, s.Runtime.ListenAddr, cert, users)
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

func printClients(orch *orchestrator.Orchestrator, p *orchestrator.Plan, user string) error {
	ccs, err := orch.ClientConfigs(p, user)
	if err != nil {
		return err
	}
	last := ""
	for _, cc := range ccs {
		if cc.User != last {
			fmt.Printf("== 用户 %s\n", cc.User)
			last = cc.User
		}
		fmt.Printf("[%s]\n  %s\n", cc.Protocol, cc.URI)
		for _, n := range cc.Notes {
			fmt.Printf("  · %s\n", n)
		}
	}
	return nil
}
