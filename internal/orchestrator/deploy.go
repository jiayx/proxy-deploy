package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/jiayx/proxy-deploy/internal/entry/caddy"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

// Logf 输出部署进度
type Logf func(format string, args ...any)

const certTimeout = 3 * time.Minute

// Deploy 按规划完成安装、配置和启动。可重复执行：已有部署会被更新为新的规划
func (o *Orchestrator) Deploy(ctx context.Context, p *Plan, caddyBinary string, logf Logf) error {
	if len(p.Conflicts) > 0 {
		return errors.New("规划存在冲突，未做任何变更")
	}
	prev, err := LoadManifest(o.layout)
	if err != nil && !errors.Is(err, ErrNotInstalled) {
		return err
	}
	if err := o.preflight(p, prev); err != nil {
		return err
	}

	logf("安装 Caddy（网关）")
	if err := caddy.Install(ctx, o.layout, caddyBinary); err != nil {
		return err
	}
	for _, s := range p.Services {
		logf("安装 %s", s.Cfg.Name)
		if err := s.Adapter.Install(ctx); err != nil {
			return fmt.Errorf("install %s: %w", s.Cfg.Name, err)
		}
	}

	if err := o.writeCaddyConfig(ctx, p); err != nil {
		return err
	}

	units := []unitFile{o.caddyUnit()}
	usedBins := []string{o.layout.CaddyBin()}
	m := &Manifest{Prefix: o.layout.Prefix, User: o.layout.User, Services: []string{caddyUnit}, Ports: p.Ports}
	for _, c := range p.Certs {
		m.Certs = append(m.Certs, CertFile{c.Name, c.CertPath})
	}
	for _, s := range p.Services {
		data, err := s.Adapter.GenerateConfig(s.Cfg, s.Runtime)
		if err != nil {
			return fmt.Errorf("%s config: %w", s.Cfg.Name, err)
		}
		if data != nil {
			check := func(string) error { return nil }
			if c, ok := s.Adapter.(protocol.ConfigChecker); ok {
				check = func(path string) error { return c.CheckConfig(ctx, path) }
			}
			if err := system.WriteFileChecked(s.Adapter.ConfigPath(), data, 0600, check); err != nil {
				return fmt.Errorf("%s config: %w", s.Cfg.Name, err)
			}
		}
		svc, err := s.Adapter.Service(s.Cfg, s.Runtime)
		if err != nil {
			return fmt.Errorf("%s service: %w", s.Cfg.Name, err)
		}
		units = append(units, o.serviceUnit(s, svc))
		usedBins = append(usedBins, svc.Args[0])
		m.Services = append(m.Services, s.Unit)
	}
	for _, u := range units {
		m.Units = append(m.Units, u.Name)
	}

	// 先移除上次部署有、这次不再需要的 unit
	if prev != nil {
		keep := map[string]bool{}
		for _, u := range m.Units {
			keep[u] = true
		}
		for _, u := range prev.Units {
			if !keep[u] {
				logf("移除不再使用的 %s", u)
				_ = o.systemd.DisableNow(ctx, u)
				_ = os.Remove(o.layout.UnitPath(u))
			}
		}
	}
	// Caddy 的 unit 或二进制变化后 reload 不会生效，需要重启
	restartCaddy := caddyBinary != ""
	for _, u := range units {
		path := o.layout.UnitPath(u.Name)
		if old, err := os.ReadFile(path); u.Name == caddyUnit && (err != nil || string(old) != u.Content) {
			restartCaddy = true
		}
		if err := system.WriteFile(path, []byte(u.Content), 0644); err != nil {
			return err
		}
	}
	// 启动前写入清单，即使后面失败也能完整卸载
	if err := saveManifest(o.layout, m); err != nil {
		return err
	}

	if err := o.systemd.DaemonReload(ctx); err != nil {
		return err
	}
	for _, u := range m.Services {
		if err := o.systemd.Enable(ctx, u); err != nil {
			return err
		}
	}

	// 协议服务随后都会重启；先停掉，避免旧进程占着本次重新分配给 Caddy 的回环端口
	for _, s := range p.Services {
		if err := o.systemd.Stop(ctx, s.Unit); err != nil {
			return err
		}
	}

	logf("启动入口 %s", caddyUnit)
	start := o.systemd.ReloadOrRestart
	if restartCaddy {
		start = o.systemd.Restart
	}
	if err := start(ctx, caddyUnit); err != nil {
		return o.withJournal(ctx, caddyUnit, err)
	}

	if err := o.waitCerts(ctx, p, logf); err != nil {
		return err
	}

	for _, s := range p.Services {
		logf("启动 %s", s.Unit)
		if err := o.systemd.Restart(ctx, s.Unit); err != nil {
			return o.withJournal(ctx, s.Unit, err)
		}
	}

	// 留出时间让启动即退出的服务暴露出来
	time.Sleep(2 * time.Second)
	for _, u := range m.Services {
		if state := o.systemd.ActiveState(ctx, u); state != "active" {
			return o.withJournal(ctx, u, fmt.Errorf("%s 状态为 %s", u, state))
		}
	}
	// 部署成功后再清理，失败时保留旧程序
	removed, err := system.PruneBinaries(o.layout.BinDir(), usedBins)
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

func (o *Orchestrator) writeCaddyConfig(ctx context.Context, p *Plan) error {
	for _, site := range p.Caddy.Sites {
		if site.Upstream == "" && site.Root == o.layout.WWWDir() {
			if err := ensureDefaultSite(site.Root); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(o.layout.CaddyDataDir(), 0700); err != nil {
		return err
	}
	data, err := caddy.Generate(p.Caddy)
	if err != nil {
		return err
	}
	// 配置里可能包含 DNS API 凭据
	return system.WriteFileChecked(o.layout.CaddyConfig(), data, 0600, func(path string) error {
		cmd := exec.CommandContext(ctx, o.layout.CaddyBin(), "validate", "--config", path)
		cmd.Env = append(os.Environ(), o.caddyEnv()...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("caddy validate: %s: %w", lastLines(string(out), 10), err)
		}
		return nil
	})
}

func ensureDefaultSite(root string) error {
	if _, err := os.Stat(root); err == nil {
		return nil
	}
	page := "<!doctype html><html><head><meta charset=\"utf-8\"><title>Welcome</title></head><body><h1>It works.</h1></body></html>\n"
	return system.WriteFile(filepath.Join(root, "index.html"), []byte(page), 0644)
}

// waitCerts 等待需要读取证书文件的协议所用证书签发完成
func (o *Orchestrator) waitCerts(ctx context.Context, p *Plan, logf Logf) error {
	var pending []string
	for _, s := range p.Services {
		if s.Runtime.Cert != nil {
			pending = append(pending, s.Runtime.Cert.CertPath)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	logf("等待证书签发")
	deadline := time.Now().Add(certTimeout)
	for {
		var missing []string
		for _, path := range pending {
			if _, err := os.Stat(path); err != nil {
				missing = append(missing, path)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return o.withJournal(ctx, caddyUnit, fmt.Errorf("%s 内证书未签发：%s", certTimeout, strings.Join(missing, ", ")))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
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

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
