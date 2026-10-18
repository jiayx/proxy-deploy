package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/jiayx/proxy-gateway/internal/entry/caddy"
	"github.com/jiayx/proxy-gateway/pkg/system"
)

// Deploy 以 systemd 方式完成安装、配置和启动。可重复执行：已有部署会被更新为新的规划。
//
// 当前程序被复制到安装目录，systemd 只管理网关这一个服务；协议后端进程由网关启动和监管。
// 配置没有变化的协议在网关重载配置后沿用原进程，连接不断。
func (o *Orchestrator) Deploy(ctx context.Context, p *Plan, logf Logf) error {
	if len(p.Conflicts) > 0 {
		return errors.New("规划存在冲突，未做任何变更")
	}
	prev, err := LoadManifest(o.layout)
	if err != nil && !errors.Is(err, ErrNotInstalled) {
		return err
	}
	if prev != nil && prev.Container {
		return errors.New("这个安装目录属于容器部署，请在容器内执行 deploy")
	}
	if err := o.preflight(p, prev); err != nil {
		return err
	}

	logf("安装 %s", o.layout.GatewayBin())
	gatewayChanged, err := caddy.Install(o.layout)
	if err != nil {
		return err
	}
	m, bins, err := o.prepare(ctx, p, logf)
	if err != nil {
		return err
	}
	unit := o.gatewayUnit()
	m.Services, m.Units = []string{gatewayUnit}, []string{unit.Name}

	// 移除上次部署有、这次不再需要的 unit
	if prev != nil {
		for _, u := range prev.Units {
			if u != unit.Name {
				logf("移除不再使用的 %s", u)
				_ = o.systemd.DisableNow(ctx, u)
				_ = os.Remove(o.layout.UnitPath(u))
			}
		}
	}
	// 网关的 unit 或二进制变化后 reload 不会生效，需要重启
	restartGateway := gatewayChanged
	unitPath := o.layout.UnitPath(unit.Name)
	if old, err := os.ReadFile(unitPath); err != nil || string(old) != unit.Content {
		restartGateway = true
	}
	if err := system.WriteFile(unitPath, []byte(unit.Content), 0644); err != nil {
		return err
	}
	// 启动前写入清单，即使后面失败也能完整卸载
	if err := saveManifest(o.layout, m); err != nil {
		return err
	}
	if err := o.systemd.DaemonReload(ctx); err != nil {
		return err
	}
	if err := o.systemd.Enable(ctx, gatewayUnit); err != nil {
		return err
	}

	start := o.systemd.ReloadOrRestart
	switch {
	case o.systemd.ActiveState(ctx, gatewayUnit) != "active":
		logf("启动 %s", gatewayUnit)
	case restartGateway:
		logf("重启 %s（程序或 unit 有变化，现有连接会断开）", gatewayUnit)
		start = o.systemd.Restart
	default:
		logf("重载 %s 的配置（现有连接不受影响）", gatewayUnit)
	}
	if err := start(ctx, gatewayUnit); err != nil {
		return o.withJournal(ctx, gatewayUnit, err)
	}
	if err := o.waitBackends(ctx, m.Backends, logf); err != nil {
		return o.withJournal(ctx, gatewayUnit, err)
	}

	// 部署成功后再清理，失败时保留旧程序
	removed, err := system.PruneBinaries(o.layout.BinDir(), append(bins, o.layout.GatewayBin()))
	for _, r := range removed {
		logf("清理不再使用的 %s", r)
	}
	if err != nil {
		return fmt.Errorf("清理旧程序: %w", err)
	}

	if o.layout.User && !o.Lingering(ctx) {
		logf("警告：当前用户未开启 linger，注销后服务会被停止、开机后也不会自动启动。请执行：sudo loginctl enable-linger %s", currentUser())
	}
	return nil
}

// Lingering 报告当前用户是否开启了 linger（用户服务不随登录会话启停）；仅对 --user 有意义
func (o *Orchestrator) Lingering(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "loginctl", "show-user", currentUser(), "-p", "Linger", "--value").Output()
	return err == nil && strings.TrimSpace(string(out)) == "yes"
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

// preflight 检查部署需要的端口是否被其他进程占用；本部署已占用的端口跳过
func (o *Orchestrator) preflight(p *Plan, prev *Manifest) error {
	owned := map[Port]bool{}
	if prev != nil {
		for _, port := range prev.Ports {
			owned[port] = true
		}
	}
	var busy []string
	for _, port := range p.Ports {
		if owned[port] {
			continue
		}
		if err := checkPortFree(port); err != nil {
			busy = append(busy, fmt.Sprintf("  %s %s：%v", strings.ToUpper(port.Network), port.Addr, err))
		}
	}
	if len(busy) > 0 {
		return fmt.Errorf("以下端口已被其他进程占用，请释放或在配置中改用其他端口：\n%s", strings.Join(busy, "\n"))
	}
	return nil
}

func (o *Orchestrator) withJournal(ctx context.Context, unit string, err error) error {
	return fmt.Errorf("%w\n--- %s 最近日志 ---\n%s", err, unit, o.journal(ctx, unit, 20))
}

func (o *Orchestrator) journal(ctx context.Context, unit string, lines int) string {
	args := o.journalArgs(unit, lines, false)
	out, _ := exec.CommandContext(ctx, "journalctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func (o *Orchestrator) journalArgs(unit string, lines int, follow bool) []string {
	var args []string
	if o.layout.User {
		args = append(args, "--user")
	}
	args = append(args, "-u", unit, "-n", fmt.Sprint(lines), "--no-pager")
	if follow {
		args = append(args, "-f")
	}
	return args
}
