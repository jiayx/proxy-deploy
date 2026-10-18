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
	"path/filepath"
	"strings"
	"time"

	"github.com/jiayx/proxy-gateway/internal/config"
	"github.com/jiayx/proxy-gateway/internal/entry/caddy"
	"github.com/jiayx/proxy-gateway/internal/protocol"
	"github.com/jiayx/proxy-gateway/pkg/system"
)

// Logf 输出部署进度
type Logf func(format string, args ...any)

// backendTimeout 限制等待协议后端就绪的时间，包括首次部署时的证书签发
const backendTimeout = 3 * time.Minute

// FetchPrograms 下载全部已注册协议用到的程序（构建镜像时把它们放进镜像）
func (o *Orchestrator) FetchPrograms(ctx context.Context, logf Logf) error {
	for _, name := range o.registry.Names() {
		a, _ := o.registry.Get(name)
		logf("安装 %s 使用的程序", name)
		if err := a.Install(ctx); err != nil {
			return fmt.Errorf("install %s: %w", name, err)
		}
	}
	return nil
}

// prepare 是两种运行方式（systemd、容器）共用的部署准备：安装协议程序，生成并校验协议配置和网关配置。
// 正在运行的网关不受影响，直到调用方让它加载新配置。返回本次部署的清单（不含 systemd unit）和用到的程序
func (o *Orchestrator) prepare(ctx context.Context, p *Plan, logf Logf) (*Manifest, []string, error) {
	if len(p.Conflicts) > 0 {
		return nil, nil, errors.New("规划存在冲突，未做任何变更")
	}
	for _, s := range p.Services {
		logf("安装 %s", s.Cfg.Name)
		if err := s.Adapter.Install(ctx); err != nil {
			return nil, nil, fmt.Errorf("install %s: %w", s.Cfg.Name, err)
		}
	}

	// 协议配置先校验再写入；正在运行的旧进程直到网关重载后才会被替换
	var bins []string
	p.Caddy.Backends = nil
	for _, s := range p.Services {
		b, err := o.writeProtocolConfig(ctx, s)
		if err != nil {
			return nil, nil, err
		}
		p.Caddy.Backends = append(p.Caddy.Backends, *b)
		bins = append(bins, b.Command[0])
	}
	if err := o.writeGatewayConfig(ctx, p); err != nil {
		return nil, nil, err
	}

	m := &Manifest{Prefix: o.layout.Prefix, User: o.layout.User, Ports: p.Ports}
	for _, c := range p.Certs {
		m.Certs = append(m.Certs, CertFile{c.Name, c.CertPath})
	}
	for _, b := range p.Caddy.Backends {
		m.Backends = append(m.Backends, b.Name)
	}
	return m, bins, nil
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
	dir, err := os.MkdirTemp("", "proxy-gateway-check-")
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

// writeGatewayConfig 生成、校验并写入网关配置（用当前程序的 validate 命令校验，即 Caddy 的 validate）
func (o *Orchestrator) writeGatewayConfig(ctx context.Context, p *Plan) error {
	for _, site := range p.Caddy.Sites {
		if site.Upstream == "" && site.Root == o.layout.WWWDir() {
			if err := ensureDefaultSite(site.Root); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(o.layout.GatewayDataDir(), 0700); err != nil {
		return err
	}
	data, err := caddy.Generate(p.Caddy)
	if err != nil {
		return err
	}
	// 配置里可能包含 DNS API 凭据
	return system.WriteFileChecked(o.layout.GatewayConfig(), data, 0600, func(path string) error {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, self, "validate", "--config", path)
		cmd.Env = append(os.Environ(), o.gatewayEnv()...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("proxy-gateway validate: %s: %w", lastLines(string(out), 10), err)
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
			return o.withJournal(ctx, gatewayUnit, errors.New(b.String()))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
