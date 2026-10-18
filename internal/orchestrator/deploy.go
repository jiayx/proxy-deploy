package orchestrator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/jiayx/proxy-deploy/internal/config"
	"github.com/jiayx/proxy-deploy/internal/entry/caddy"
	"github.com/jiayx/proxy-deploy/internal/protocol"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

// Logf 输出部署进度
type Logf func(format string, args ...any)

// backendTimeout 限制等待协议后端就绪的时间，包括首次部署时的证书签发
const backendTimeout = 3 * time.Minute

// Deploy 按规划完成安装、配置和启动。可重复执行：已有部署会被更新为新的规划。
//
// systemd 只管理 Caddy；协议后端进程由 Caddy 中的网关启动和监管。配置没有变化的协议
// 在 Caddy 重载配置后沿用原进程，连接不断。
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
	keepLocal := caddyBinary == "" && prev != nil && prev.LocalCaddy
	caddyChanged, warning, err := caddy.Install(ctx, o.layout, caddyBinary, keepLocal)
	if err != nil {
		return err
	}
	if warning != "" {
		logf("警告：%s", warning)
	}
	for _, s := range p.Services {
		logf("安装 %s", s.Cfg.Name)
		if err := s.Adapter.Install(ctx); err != nil {
			return fmt.Errorf("install %s: %w", s.Cfg.Name, err)
		}
	}

	// 协议配置先校验再写入；正在运行的旧进程直到 Caddy 重载后才会被替换
	usedBins := []string{o.layout.CaddyBin()}
	p.Caddy.Backends = nil
	for _, s := range p.Services {
		b, err := o.writeProtocolConfig(ctx, s)
		if err != nil {
			return err
		}
		p.Caddy.Backends = append(p.Caddy.Backends, *b)
		usedBins = append(usedBins, b.Command[0])
	}
	if err := o.writeCaddyConfig(ctx, p); err != nil {
		return err
	}

	unit := o.caddyUnit()
	m := &Manifest{Prefix: o.layout.Prefix, User: o.layout.User, Services: []string{caddyUnit}, Units: []string{unit.Name}, Ports: p.Ports,
		LocalCaddy: caddyBinary != "" || keepLocal}
	for _, c := range p.Certs {
		m.Certs = append(m.Certs, CertFile{c.Name, c.CertPath})
	}
	for _, b := range p.Caddy.Backends {
		m.Backends = append(m.Backends, b.Name)
	}

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
	// Caddy 的 unit 或二进制变化后 reload 不会生效，需要重启
	restartCaddy := caddyChanged
	unitPath := o.layout.UnitPath(unit.Name)
	if old, err := os.ReadFile(unitPath); err != nil || string(old) != unit.Content {
		restartCaddy = true
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
	if err := o.systemd.Enable(ctx, caddyUnit); err != nil {
		return err
	}

	logf("启动 %s", caddyUnit)
	start := o.systemd.ReloadOrRestart
	if restartCaddy {
		start = o.systemd.Restart
	}
	if err := start(ctx, caddyUnit); err != nil {
		return o.withJournal(ctx, caddyUnit, err)
	}
	if err := o.waitBackends(ctx, m.Backends, logf); err != nil {
		return err
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

// writeProtocolConfig 生成、校验并写入一个协议的配置，返回交给网关监管的后端描述。
// 证书尚未签发（首次部署）时，用临时自签证书生成一份同样的配置来校验
func (o *Orchestrator) writeProtocolConfig(ctx context.Context, s *Service) (*caddy.Backend, error) {
	svc, err := s.Adapter.Service(s.Cfg, s.Runtime)
	if err != nil {
		return nil, fmt.Errorf("%s service: %w", s.Cfg.Name, err)
	}
	b := &caddy.Backend{Name: s.Cfg.Name, Command: svc.Args}
	if s.Runtime.Cert != nil {
		b.RequireFiles = []string{s.Runtime.Cert.CertPath, s.Runtime.Cert.KeyPath}
	}

	data, err := s.Adapter.GenerateConfig(s.Cfg, s.Runtime)
	if err != nil {
		return nil, fmt.Errorf("%s config: %w", s.Cfg.Name, err)
	}
	if data != nil {
		check := func(string) error { return nil }
		if c, ok := s.Adapter.(protocol.ConfigChecker); ok {
			check = func(path string) error { return c.CheckConfig(ctx, path) }
			if s.Runtime.Cert != nil && !fileExists(s.Runtime.Cert.CertPath) {
				if err := o.checkWithTempCert(s, check); err != nil {
					return nil, fmt.Errorf("%s config: %w", s.Cfg.Name, err)
				}
				check = func(string) error { return nil }
			}
		}
		if err := system.WriteFileChecked(s.Adapter.ConfigPath(), data, 0600, check); err != nil {
			return nil, fmt.Errorf("%s config: %w", s.Cfg.Name, err)
		}
	}

	// revision 覆盖配置内容和实际的程序版本（bin/ 下是指向版本文件的链接），任一变化网关都会重启进程
	h := sha256.New()
	h.Write(data)
	if real, err := filepath.EvalSymlinks(b.Command[0]); err == nil {
		h.Write([]byte(real))
	}
	b.Revision = hex.EncodeToString(h.Sum(nil))[:16]
	return b, nil
}

// checkWithTempCert 用临时自签证书代替尚未签发的证书生成配置并校验，只校验不写入
func (o *Orchestrator) checkWithTempCert(s *Service, check func(string) error) error {
	dir, err := os.MkdirTemp("", "proxyd-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cert, err := writeTempCert(dir, s.Runtime.Cert.Name)
	if err != nil {
		return err
	}
	rt := s.Runtime
	rt.Cert = cert
	data, err := s.Adapter.GenerateConfig(s.Cfg, rt)
	if err != nil {
		return err
	}
	return system.CheckFile(s.Adapter.ConfigPath(), data, 0600, check)
}

func writeTempCert(dir, name string) (*config.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	c := &config.Certificate{Name: name, CertPath: filepath.Join(dir, "cert.pem"), KeyPath: filepath.Join(dir, "key.pem")}
	if err := os.WriteFile(c.CertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	return c, os.WriteFile(c.KeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

// waitBackends 等待网关把所有协议后端启动并稳定运行；首次部署时包括等待证书签发
func (o *Orchestrator) waitBackends(ctx context.Context, names []string, logf Logf) error {
	if len(names) == 0 {
		return nil
	}
	logf("等待协议后端就绪")
	deadline := time.Now().Add(backendTimeout)
	for {
		statuses, err := o.Backends(ctx)
		pending := map[string]BackendStatus{}
		for _, n := range names {
			pending[n] = BackendStatus{Name: n, State: "unknown"}
		}
		if err == nil {
			for _, st := range statuses {
				// 运行满 3 秒才算就绪，启动即退出的配置错误会在此期间暴露
				if _, ok := pending[st.Name]; ok && (st.State != "running" || st.Uptime < 3) {
					pending[st.Name] = st
				} else {
					delete(pending, st.Name)
				}
			}
		}
		if len(pending) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			var b strings.Builder
			fmt.Fprintf(&b, "%s 内协议后端未就绪：", backendTimeout)
			for _, st := range pending {
				fmt.Fprintf(&b, "\n--- %s：%s", st.Name, st.State)
				if st.LastExit != "" {
					fmt.Fprintf(&b, "（%s，已重启 %d 次）", st.LastExit, st.Restarts)
				}
				for _, line := range st.Tail {
					fmt.Fprintf(&b, "\n  %s", line)
				}
			}
			if err != nil {
				fmt.Fprintf(&b, "\n读取网关状态失败：%v", err)
			}
			return o.withJournal(ctx, caddyUnit, errors.New(b.String()))
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
