package orchestrator

import (
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/jiayx/proxy-deploy/internal/protocol"
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

// caddyEnv 让 Caddy 的全部运行时文件都落在安装目录下
func (o *Orchestrator) caddyEnv() []string {
	v := o.layout.VarDir()
	return []string{"XDG_DATA_HOME=" + v + "/xdg/data", "XDG_CONFIG_HOME=" + v + "/xdg/config"}
}

func (o *Orchestrator) caddyUnit() unitFile {
	bin, cfg := o.layout.CaddyBin(), o.layout.CaddyConfig()
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=proxy-deploy entry (Caddy + layer4)\nAfter=network-online.target\nWants=network-online.target\n\n")
	fmt.Fprintf(&b, "[Service]\nType=notify\n")
	fmt.Fprintf(&b, "ExecStart=%s\n", execLine([]string{bin, "run", "--config", cfg}))
	fmt.Fprintf(&b, "ExecReload=%s\n", execLine([]string{bin, "reload", "--config", cfg, "--address", "unix/" + o.layout.CaddyAdminSocket()}))
	for _, e := range o.caddyEnv() {
		fmt.Fprintf(&b, "Environment=%s\n", quoteArg(e))
	}
	b.WriteString("Restart=on-failure\nRestartSec=5\nTimeoutStopSec=10\n")
	if !o.layout.User {
		b.WriteString("LimitNOFILE=1048576\n")
	}
	fmt.Fprintf(&b, "\n[Install]\nWantedBy=%s\n", o.wantedBy())
	return unitFile{caddyUnit, b.String()}
}

func (o *Orchestrator) serviceUnit(s *Service, svc *protocol.Service) unitFile {
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=proxy-deploy %s\nAfter=network-online.target %s\nWants=network-online.target\n\n", s.Cfg.Name, caddyUnit)
	fmt.Fprintf(&b, "[Service]\nEnvironmentFile=%s\n", o.layout.EnvFile(s.Unit))
	fmt.Fprintf(&b, "ExecStart=%s\n", execLine(svc.Args))
	b.WriteString("Restart=on-failure\nRestartSec=5\n")
	if !o.layout.User {
		b.WriteString("LimitNOFILE=1048576\n")
	}
	fmt.Fprintf(&b, "\n[Install]\nWantedBy=%s\n", o.wantedBy())
	return unitFile{s.Unit, b.String()}
}

// certWatchUnits 生成一对 unit：证书文件变化（续期）时重启使用它的服务
func (o *Orchestrator) certWatchUnits(s *Service) ([]unitFile, error) {
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(s.Unit, ".service") + "-cert"
	args := append([]string{systemctl}, o.systemd.Args("try-restart", s.Unit)...)
	path := fmt.Sprintf("[Unit]\nDescription=Watch certificate of %s\n\n[Path]\nPathChanged=%s\nUnit=%s.service\n\n[Install]\nWantedBy=%s\n",
		s.Unit, s.Runtime.Cert.CertPath, base, o.wantedBy())
	restart := fmt.Sprintf("[Unit]\nDescription=Restart %s after certificate renewal\n\n[Service]\nType=oneshot\nExecStart=%s\n",
		s.Unit, execLine(args))
	return []unitFile{{base + ".path", path}, {base + ".service", restart}}, nil
}

var envRefPattern = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)

// execLine 把参数拼成 ExecStart 行：转义 systemd 的 % 说明符和 $ 变量，按需加引号。
// 形如 ${NAME} 的参数保留，由 systemd 从 EnvironmentFile 展开
func execLine(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if envRefPattern.MatchString(a) {
			out[i] = a
			continue
		}
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

// envFile 生成 EnvironmentFile 内容，值使用双引号并转义 shell 特殊字符
func envFile(env map[string]string) []byte {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=\"%s\"\n", k, esc.Replace(env[k]))
	}
	return []byte(b.String())
}
