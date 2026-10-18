package orchestrator

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// RouteStats 是网关上一条路由的统计，对应 gateway.RouteSnapshot
type RouteStats struct {
	Route     string `json:"route"`
	Active    int64  `json:"active"`
	Total     int64  `json:"total"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
}

// BackendStatus 是网关监管的一个协议后端进程的状态，对应 gateway.BackendStatus
type BackendStatus struct {
	Name     string   `json:"name"`
	State    string   `json:"state"`
	PID      int      `json:"pid"`
	Uptime   float64  `json:"uptime_seconds"`
	Restarts int      `json:"restarts"`
	LastExit string   `json:"last_exit"`
	Tail     []string `json:"tail"`
}

// UserStats 是一个用户的统计，对应 gateway.UserSnapshot
type UserStats struct {
	User         string   `json:"user"`
	State        string   `json:"state"`
	Active       int64    `json:"active"`
	Total        int64    `json:"total"`
	BytesUp      int64    `json:"bytes_up"`
	BytesDown    int64    `json:"bytes_down"`
	PeriodUp     int64    `json:"period_up"`
	PeriodDown   int64    `json:"period_down"`
	PeriodStart  string   `json:"period_start"`
	TrafficLimit int64    `json:"traffic_limit"`
	Expire       string   `json:"expire"`
	Protocols    []string `json:"protocols"`
}

// UserStats 读取网关按用户累计的统计
func (o *Orchestrator) UserStats(ctx context.Context) ([]UserStats, error) {
	var list []UserStats
	return list, o.admin(ctx, http.MethodGet, "/proxy_gateway/users", &list)
}

// GatewayStats 读取网关各路由的统计
func (o *Orchestrator) GatewayStats(ctx context.Context) ([]RouteStats, error) {
	var stats []RouteStats
	return stats, o.admin(ctx, http.MethodGet, "/proxy_gateway/stats", &stats)
}

// Backends 读取网关监管的各协议后端进程的状态
func (o *Orchestrator) Backends(ctx context.Context) ([]BackendStatus, error) {
	var list []BackendStatus
	return list, o.admin(ctx, http.MethodGet, "/proxy_gateway/backends", &list)
}

// admin 调用网关的管理接口（Caddy admin API，unix socket），out 非空时解析 JSON 响应
func (o *Orchestrator) admin(ctx context.Context, method, path string, out any) error {
	return o.adminBody(ctx, method, path, nil, out)
}

func (o *Orchestrator) adminBody(ctx context.Context, method, path string, body []byte, out any) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", o.layout.GatewayAdminSocket())
		}},
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
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

// containerLogs 是容器部署的日志：整个服务的日志在容器的标准输出里；协议的最近输出从网关管理接口读取
func (o *Orchestrator) containerLogs(ctx context.Context, m *Manifest, name string) error {
	if name == "" {
		return errors.New("容器部署的日志请用 docker logs 查看；proxy-gateway logs <协议> 可以查看某个协议最近的输出")
	}
	if !slices.Contains(m.Backends, name) {
		return fmt.Errorf("未知协议 %q，可选：%s", name, strings.Join(m.Backends, ", "))
	}
	list, err := o.Backends(ctx)
	if err != nil {
		return err
	}
	for _, b := range list {
		if b.Name == name {
			for _, line := range b.Tail {
				fmt.Println(line)
			}
		}
	}
	return nil
}

// Logs 输出日志：name 为空时输出整个服务的日志（含网关连接日志和全部后端输出），协议名只输出该协议后端进程的日志
func (o *Orchestrator) Logs(ctx context.Context, name string, lines int, follow bool) error {
	m, err := LoadManifest(o.layout)
	if err != nil {
		return err
	}
	if m.Container {
		return o.containerLogs(ctx, m, name)
	}
	if name == "" || name == gatewayUnit {
		cmd := exec.CommandContext(ctx, "journalctl", o.journalArgs(gatewayUnit, lines, follow)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	if !slices.Contains(m.Backends, name) {
		return fmt.Errorf("未知协议 %q，可选：%s", name, strings.Join(m.Backends, ", "))
	}

	// 后端输出由网关写入自己的日志，带 "backend" 字段；从中筛出该后端的行
	var recent []string
	if err := o.scanJournal(ctx, false, func(line string) {
		if l, ok := backendLine(line, name); ok {
			recent = append(recent, l)
			if len(recent) > lines {
				recent = recent[1:]
			}
		}
	}); err != nil {
		return err
	}
	for _, l := range recent {
		fmt.Println(l)
	}
	if !follow {
		return nil
	}
	return o.scanJournal(ctx, true, func(line string) {
		if l, ok := backendLine(line, name); ok {
			fmt.Println(l)
		}
	})
}

// scanJournal 逐行读取网关的日志（只含消息本身）。follow 时只读新产生的日志并持续等待
func (o *Orchestrator) scanJournal(ctx context.Context, follow bool, fn func(string)) error {
	var args []string
	if o.layout.User {
		args = append(args, "--user")
	}
	args = append(args, "-u", gatewayUnit, "-o", "cat", "--no-pager")
	if follow {
		args = append(args, "-f", "-n", "0")
	} else {
		args = append(args, "-n", "100000")
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fn(sc.Text())
	}
	return cmd.Wait()
}

// backendLine 解析网关的 JSON 日志行，属于该后端时返回 "时间 输出内容"
func backendLine(line, backend string) (string, bool) {
	if !strings.Contains(line, `"backend":"`+backend+`"`) {
		return "", false
	}
	var entry struct {
		TS      float64 `json:"ts"`
		Msg     string  `json:"msg"`
		Backend string  `json:"backend"`
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil || entry.Backend != backend {
		return "", false
	}
	ts := time.Unix(0, int64(entry.TS*float64(time.Second))).Format("01-02 15:04:05")
	return ts + "  " + entry.Msg, true
}

// Restart 重启服务：不指定时重启整个服务（含全部协议后端），指定协议名时只重启该协议的后端进程
func (o *Orchestrator) Restart(ctx context.Context, name string) error {
	m, err := LoadManifest(o.layout)
	if err != nil {
		return err
	}
	if name == "" && m.Container {
		return errors.New("容器部署请用 docker restart 重启整个服务")
	}
	if name == "" || name == gatewayUnit {
		if err := o.systemd.Restart(ctx, gatewayUnit); err != nil {
			return o.withJournal(ctx, gatewayUnit, err)
		}
		return o.waitBackends(ctx, m.Backends, func(string, ...any) {})
	}
	if !slices.Contains(m.Backends, name) {
		return fmt.Errorf("未知协议 %q，可选：%s", name, strings.Join(m.Backends, ", "))
	}
	if err := o.admin(ctx, http.MethodPost, "/proxy_gateway/backends/"+name+"/restart", nil); err != nil {
		return err
	}
	time.Sleep(time.Second) // 等旧进程退出后再检查新进程
	return o.waitBackends(ctx, []string{name}, func(string, ...any) {})
}

// Uninstall 停止并移除全部服务和 unit 文件，然后删除安装目录。
// 只依据安装清单操作，不会删除清单之外的东西
func (o *Orchestrator) Uninstall(ctx context.Context, logf Logf) error {
	m, err := LoadManifest(o.layout)
	if err != nil {
		return err
	}
	if m.Container {
		return errors.New("容器部署的卸载在宿主机上进行：docker compose down。证书和用户流量统计保存在数据卷里，会保留；确定不再需要时，再加上 -v 一并删除")
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
