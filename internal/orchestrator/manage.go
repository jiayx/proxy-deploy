package orchestrator

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type UnitStatus struct {
	Unit  string
	State string
}

type CertStatus struct {
	Name     string
	Path     string
	NotAfter time.Time
	Err      error
}

// Status 返回各服务的运行状态和证书有效期
func (o *Orchestrator) Status(ctx context.Context) ([]UnitStatus, []CertStatus, error) {
	m, err := LoadManifest(o.layout)
	if err != nil {
		return nil, nil, err
	}
	var units []UnitStatus
	for _, u := range m.Services {
		units = append(units, UnitStatus{u, o.systemd.ActiveState(ctx, u)})
	}
	var certs []CertStatus
	for _, c := range m.Certs {
		cs := CertStatus{Name: c.Name, Path: c.Path}
		cs.NotAfter, cs.Err = certNotAfter(c.Path)
		certs = append(certs, cs)
	}
	return units, certs, nil
}

func certNotAfter(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("不是 PEM 证书")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// Logs 输出某个服务的日志；name 可以是 caddy、协议名或完整 unit 名
func (o *Orchestrator) Logs(ctx context.Context, name string, lines int, follow bool) error {
	m, err := LoadManifest(o.layout)
	if err != nil {
		return err
	}
	unit := name
	if !strings.HasSuffix(unit, ".service") {
		unit = unitPrefix + name + ".service"
	}
	known := false
	for _, u := range m.Services {
		known = known || u == unit
	}
	if !known {
		return fmt.Errorf("未知服务 %q，可选：%s", name, strings.Join(m.Services, ", "))
	}
	cmd := exec.CommandContext(ctx, "journalctl", o.journalArgs(unit, lines, follow)...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// Restart 重启全部服务或指定服务
func (o *Orchestrator) Restart(ctx context.Context, name string) error {
	m, err := LoadManifest(o.layout)
	if err != nil {
		return err
	}
	matched := false
	for _, u := range m.Services {
		if name == "" || u == unitPrefix+name+".service" || u == name {
			matched = true
			if err := o.systemd.Restart(ctx, u); err != nil {
				return o.withJournal(ctx, u, err)
			}
		}
	}
	if !matched {
		return fmt.Errorf("未知服务 %q，可选：%s", name, strings.Join(m.Services, ", "))
	}
	return nil
}

// Uninstall 停止并移除全部服务和 unit 文件，然后删除安装目录。
// 只依据安装清单操作，不会删除清单之外的东西
func (o *Orchestrator) Uninstall(ctx context.Context, logf Logf) error {
	m, err := LoadManifest(o.layout)
	if err != nil {
		return err
	}
	prefix := filepath.Clean(o.layout.Prefix)
	home, _ := os.UserHomeDir()
	if prefix == "/" || prefix == filepath.Clean(home) || prefix != filepath.Clean(m.Prefix) {
		return fmt.Errorf("拒绝删除 %s：与安装清单不符或路径不安全", prefix)
	}
	for _, u := range m.Units {
		logf("移除 %s", u)
		_ = o.systemd.DisableNow(ctx, u)
		if err := os.Remove(o.layout.UnitPath(u)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	_ = o.systemd.DaemonReload(ctx)
	_ = o.systemd.ResetFailed(ctx, m.Units...)
	logf("删除 %s", prefix)
	return os.RemoveAll(prefix)
}
