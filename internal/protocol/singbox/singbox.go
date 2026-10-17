// Package singbox 安装 sing-box 并生成单个 inbound 的配置，供基于 sing-box 的协议适配器共用。
//
// 每个协议运行一个独立的 sing-box 进程（独立的配置和 systemd unit），
// 二进制只安装一份，多个协议共用。
package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

const (
	binName = "sing-box"
	version = "1.14.3"
)

// checksums 是上游发布包的 sha256，按 GOOS/GOARCH 固定；升级版本时一并更新
var checksums = map[string]string{
	"linux/amd64": "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
	"linux/arm64": "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
}

// Bin 返回 sing-box 可执行文件路径
func Bin(layout *paths.Layout) string { return layout.ProtocolBin(binName) }

// Install 下载并安装 sing-box，幂等
func Install(ctx context.Context, layout *paths.Layout) error {
	sum, ok := checksums[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return fmt.Errorf("sing-box %s 不支持 %s/%s", version, runtime.GOOS, runtime.GOARCH)
	}
	u := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-%s-%s.tar.gz",
		version, version, runtime.GOOS, runtime.GOARCH)
	return system.InstallVersioned(layout.VersionedBin(binName, version), Bin(layout),
		func(dest string) error { return system.DownloadAndExtract(ctx, u, sum, binName, dest, 0755) })
}

// Args 返回运行 sing-box 的命令行；日志写入 journald，关闭终端颜色
func Args(layout *paths.Layout, configPath string) []string {
	return []string{Bin(layout), "run", "--disable-color", "-c", configPath}
}

// Check 用 sing-box check 校验配置文件
func Check(ctx context.Context, layout *paths.Layout, configPath string) error {
	out, err := exec.CommandContext(ctx, Bin(layout), "check", "--disable-color", "-c", configPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box check %s: %s", configPath, strings.TrimSpace(string(out)))
	}
	return nil
}

// Config 生成只包含一个 inbound 的 sing-box 配置。
// inbound 只需填协议字段，监听地址由 listenAddr（host:port）填入
func Config(listenAddr string, inbound map[string]any) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen address %q: %w", listenAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("listen port %q: %w", portStr, err)
	}
	if host == "" {
		host = "::"
	}
	inbound["listen"] = host
	inbound["listen_port"] = port
	cfg := map[string]any{
		// journald 已带时间戳
		"log":       map[string]any{"level": "info", "timestamp": false},
		"inbounds":  []any{inbound},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
