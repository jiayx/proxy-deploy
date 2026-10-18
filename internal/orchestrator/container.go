package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	caddyv2 "github.com/caddyserver/caddy/v2"
)

// Serve 以容器方式运行：生成配置后在当前进程里启动网关，直到 ctx 结束（容器停止）。
// 容器里由 Docker 管理进程，没有 systemd unit；程序和 sing-box 都在镜像里，不需要复制或清理
func (o *Orchestrator) Serve(ctx context.Context, p *Plan, logf Logf) error {
	for _, e := range o.gatewayEnv() {
		k, v, _ := strings.Cut(e, "=")
		os.Setenv(k, v)
	}
	m, _, err := o.prepare(ctx, p, logf)
	if err != nil {
		return err
	}
	m.Container = true
	if err := saveManifest(o.layout, m); err != nil {
		return err
	}
	data, err := os.ReadFile(o.layout.GatewayConfig())
	if err != nil {
		return err
	}
	logf("启动网关")
	if err := caddyv2.Load(data, true); err != nil {
		return fmt.Errorf("start gateway: %w", err)
	}
	go func() {
		if err := o.waitBackends(ctx, m.Backends, logf); err != nil {
			logf("警告：%v", err)
		} else if len(m.Backends) > 0 {
			logf("协议后端已就绪")
		}
	}()
	<-ctx.Done()
	logf("停止网关")
	return caddyv2.Stop()
}

// Apply 在容器里应用修改后的配置：重新生成配置，交给正在运行的网关热加载。
// 配置没有变化的协议沿用原进程，连接不断
func (o *Orchestrator) Apply(ctx context.Context, p *Plan, logf Logf) error {
	prev, err := LoadManifest(o.layout)
	if err != nil {
		return err
	}
	if !prev.Container {
		return errors.New("这个安装目录不是容器部署")
	}
	m, _, err := o.prepare(ctx, p, logf)
	if err != nil {
		return err
	}
	m.Container = true
	data, err := os.ReadFile(o.layout.GatewayConfig())
	if err != nil {
		return err
	}
	logf("重载网关配置（现有连接不受影响）")
	if err := o.adminBody(ctx, http.MethodPost, "/load", data, nil); err != nil {
		return fmt.Errorf("reload gateway: %w", err)
	}
	if err := saveManifest(o.layout, m); err != nil {
		return err
	}
	return o.waitBackends(ctx, m.Backends, logf)
}
