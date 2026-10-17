package caddy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

const (
	// releaseBase 是预构建二进制（caddy-l4-{os}-{arch}）的下载地址前缀，由本项目 CI 发布
	releaseBase = "https://github.com/jiayx/proxy-deploy/releases/latest/download"
	l4Plugin    = "github.com/mholt/caddy-l4"
)

// requiredModules 是生成的配置依赖的 l4 模块，安装后逐一校验
var requiredModules = []string{"layer4.matchers.tls", "layer4.matchers.quic", "layer4.handlers.tls", "layer4.handlers.proxy"}

// Install 安装带 caddy-l4 的 Caddy，按优先级：
//  1. localBinary 非空：复制调用方提供的二进制
//  2. 安装目录中已有二进制：直接复用
//  3. 下载本项目发布的预构建二进制
//  4. 用 xcaddy 在本机构建
//
// 无论哪种来源，最后都校验所需的 l4 模块是否存在。
func Install(ctx context.Context, layout *paths.Layout, localBinary string) error {
	dest := layout.CaddyBin()

	switch {
	case localBinary != "":
		if err := system.CopyFile(localBinary, dest, 0755); err != nil {
			return fmt.Errorf("copy caddy binary: %w", err)
		}
	case fileExists(dest):
	default:
		url := fmt.Sprintf("%s/caddy-l4-%s-%s", releaseBase, runtime.GOOS, runtime.GOARCH)
		if err := system.Download(ctx, url, dest, 0755); err != nil {
			if berr := buildWithXcaddy(ctx, dest); berr != nil {
				return fmt.Errorf("download prebuilt caddy (%v); %w", err, berr)
			}
		}
	}
	return verifyModules(ctx, dest)
}

func verifyModules(ctx context.Context, bin string) error {
	out, err := exec.CommandContext(ctx, bin, "list-modules").Output()
	if err != nil {
		return fmt.Errorf("%s list-modules: %w", bin, err)
	}
	have := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		have[strings.TrimSpace(line)] = true
	}
	var missing []string
	for _, m := range requiredModules {
		if !have[m] {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("caddy binary %s lacks modules %v; build it with: xcaddy build --with %s", bin, missing, l4Plugin)
	}
	return nil
}

func buildWithXcaddy(ctx context.Context, dest string) error {
	xcaddy, err := exec.LookPath("xcaddy")
	if err != nil {
		return fmt.Errorf("xcaddy not found; pass --caddy-binary or install xcaddy")
	}
	out, err := exec.CommandContext(ctx, xcaddy, "build", "--with", l4Plugin, "--output", dest).CombinedOutput()
	if err != nil {
		return fmt.Errorf("xcaddy build: %s: %w", out, err)
	}
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
