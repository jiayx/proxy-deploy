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

// releaseBase 是预构建二进制（caddy-gateway-{os}-{arch}）的下载地址前缀，由 .github/workflows/caddy.yml 发布
const releaseBase = "https://github.com/jiayx/proxy-deploy/releases/download/caddy"

// requiredModules 是生成的配置依赖的模块，安装后逐一校验
var requiredModules = []string{"proxy_gateway", "admin.api.proxy_gateway"}

// Install 安装带 proxy_gateway 网关的 Caddy（本仓库 cmd/caddy），按优先级：
//  1. localBinary 非空：复制调用方提供的二进制
//  2. 安装目录中已有二进制且包含所需模块：直接复用
//  3. 下载本项目发布的预构建二进制（同时替换缺少模块的旧版本）
//
// 无论哪种来源，最后都校验所需模块是否存在。
func Install(ctx context.Context, layout *paths.Layout, localBinary string) error {
	dest := layout.CaddyBin()

	switch {
	case localBinary != "":
		if err := system.CopyFile(localBinary, dest, 0755); err != nil {
			return fmt.Errorf("copy caddy binary: %w", err)
		}
	case fileExists(dest) && verifyModules(ctx, dest) == nil:
	default:
		if err := downloadPrebuilt(ctx, dest); err != nil {
			return fmt.Errorf("download prebuilt caddy: %w; 也可以用 go build ./cmd/caddy 构建后通过 --caddy-binary 指定", err)
		}
	}
	return verifyModules(ctx, dest)
}

// downloadPrebuilt 下载 CI 发布的预构建二进制，用同时发布的 .sha256 文件校验，覆盖已有文件
func downloadPrebuilt(ctx context.Context, dest string) error {
	url := fmt.Sprintf("%s/caddy-gateway-%s-%s", releaseBase, runtime.GOOS, runtime.GOARCH)
	sum, err := system.FetchChecksum(ctx, url+".sha256")
	if err != nil {
		return err
	}
	tmp := dest + ".download"
	_ = os.Remove(tmp)
	if err := system.Download(ctx, url, sum, tmp, 0755); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
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
		return fmt.Errorf("caddy binary %s lacks modules %v; build it with: go build ./cmd/caddy", bin, missing)
	}
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
