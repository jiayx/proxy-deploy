package caddy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

// releaseBase 是预构建网关（proxy-gateway-{os}-{arch}）的下载地址前缀，由 .github/workflows/proxy-gateway.yml 发布
const releaseBase = "https://github.com/jiayx/proxy-deploy/releases/download/proxy-gateway"

// requiredModules 是生成的配置依赖的模块，安装后逐一校验
var requiredModules = []string{"proxy_gateway", "admin.api.proxy_gateway"}

// Install 安装网关程序 proxy-gateway（本仓库 cmd/proxy-gateway：Caddy 加上 proxy_gateway 模块）：
//   - localBinary 非空：复制调用方提供的二进制
//   - keepLocal：已安装的是之前的本地构建，沿用它，不换成发布版本
//   - 否则使用本项目发布的最新预构建二进制：已安装的与之相同时不动，不同时下载替换；
//     无法连接发布地址但已安装过时，沿用已安装的并在 warning 中说明
//
// 无论哪种来源，最后都校验所需模块是否存在。changed 表示二进制被替换，
// 正在运行的网关需要重启（reload 不会换掉进程）。
func Install(ctx context.Context, layout *paths.Layout, localBinary string, keepLocal bool) (changed bool, warning string, err error) {
	dest := layout.GatewayBin()
	if localBinary != "" {
		if err := system.CopyFile(localBinary, dest, 0755); err != nil {
			return false, "", fmt.Errorf("copy gateway binary: %w", err)
		}
		return true, "", verifyModules(ctx, dest)
	}
	if keepLocal {
		return false, fmt.Sprintf("网关是之前用 --gateway-binary 安装的本地构建，不会自动更新；要换成发布版本，删除 %s 后重新部署", dest), verifyModules(ctx, dest)
	}

	url := releaseURL()
	sum, err := system.FetchChecksum(ctx, url+".sha256")
	if err != nil {
		if !fileExists(dest) {
			return false, "", fmt.Errorf("download prebuilt proxy-gateway: %w; 也可以用 go build ./cmd/proxy-gateway 构建后通过 --gateway-binary 指定", err)
		}
		return false, fmt.Sprintf("无法检查网关的发布版本，沿用已安装的：%v", err), verifyModules(ctx, dest)
	}
	if have, err := system.FileSHA256(dest); err == nil && strings.EqualFold(have, sum) {
		return false, "", verifyModules(ctx, dest)
	}
	data, err := system.Fetch(ctx, url)
	if err != nil {
		return false, "", fmt.Errorf("download prebuilt proxy-gateway: %w", err)
	}
	if got := sha256.Sum256(data); !strings.EqualFold(hex.EncodeToString(got[:]), sum) {
		return false, "", fmt.Errorf("download %s: sha256 不匹配", url)
	}
	if err := system.WriteFile(dest, data, 0755); err != nil {
		return false, "", err
	}
	return true, "", verifyModules(ctx, dest)
}

func releaseURL() string {
	return fmt.Sprintf("%s/proxy-gateway-%s-%s", releaseBase, runtime.GOOS, runtime.GOARCH)
}

// Build 描述一个网关二进制的版本
type Build struct {
	Caddy    string    // 其中的 Caddy 版本，如 v2.11.7
	Revision string    // 构建所用的本仓库提交
	Time     time.Time // 该提交的时间
	Modified bool      // 构建时有未提交的修改
}

// InstalledBuild 读取已安装的网关的版本（version 与 build-info 子命令，与 Caddy 相同）
func InstalledBuild(ctx context.Context, layout *paths.Layout) (*Build, error) {
	bin := layout.GatewayBin()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return nil, fmt.Errorf("%s version: %w", bin, err)
	}
	b := &Build{Caddy: firstField(string(out))}
	if out, err = exec.CommandContext(ctx, bin, "build-info").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			k, v, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(line), "build\t"), "=")
			switch k {
			case "vcs.revision":
				b.Revision = v
			case "vcs.time":
				b.Time, _ = time.Parse(time.RFC3339, v)
			case "vcs.modified":
				b.Modified = v == "true"
			}
		}
	}
	return b, nil
}

// ReleaseBuild 读取最新发布的预构建网关的提交（proxy-gateway.revision：提交哈希与提交时间）
func ReleaseBuild(ctx context.Context) (*Build, error) {
	data, err := system.Fetch(ctx, releaseBase+"/proxy-gateway.revision")
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return nil, fmt.Errorf("proxy-gateway.revision 格式不正确")
	}
	t, _ := time.Parse(time.RFC3339, fields[1])
	return &Build{Revision: fields[0], Time: t}, nil
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
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
		return fmt.Errorf("gateway binary %s lacks modules %v; build it with: go build ./cmd/proxy-gateway", bin, missing)
	}
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
