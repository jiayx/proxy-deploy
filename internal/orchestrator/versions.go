package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"github.com/jiayx/proxy-gateway/internal/protocol/singbox"
	"github.com/jiayx/proxy-gateway/pkg/system"
)

// repoAPI 是本仓库的 GitHub API 地址，用来查看 main 分支的最新提交
const repoAPI = "https://api.github.com/repos/jiayx/proxy-gateway"

// Build 描述一个 proxy-gateway 程序的版本
type Build struct {
	Revision string    // 构建所用的提交
	Time     time.Time // 该提交的时间
	Modified bool      // 构建时有未提交的修改
	Caddy    string    // 其中的 Caddy 版本
}

// Versions 是当前程序、已安装程序、sing-box 的版本和可用的新版本；
// 每一项单独查询，失败时记在对应的 Err 字段，不影响其他项
type Versions struct {
	Self, Main               Build // 当前运行的程序、仓库 main 分支的最新提交
	SelfErr, MainErr         error
	Installed                Build // 安装目录中的程序（服务运行的就是它）
	InstalledErr             error
	InstalledSame            bool   // 已安装的与当前程序完全相同
	SingBox, SingBoxLatest   string // 已安装的、上游最新的正式版本
	SingBoxErr, SingBoxUpErr error
}

// SingBoxPinned 是当前程序安装的 sing-box 版本
const SingBoxPinned = singbox.Version

// Versions 查询各项版本；需要访问 GitHub
func (o *Orchestrator) Versions(ctx context.Context) *Versions {
	v := &Versions{}
	if info, ok := debug.ReadBuildInfo(); ok {
		v.Self = parseBuildInfo(info.String())
	}
	if v.Self.Revision == "" {
		v.SelfErr = fmt.Errorf("构建时没有记录提交（需要在 git 仓库中 go build）")
	}
	v.Main, v.MainErr = latestMain(ctx)
	v.Installed, v.InstalledSame, v.InstalledErr = installedBuild(ctx, o.layout.GatewayBin())
	v.SingBox, v.SingBoxErr = singbox.InstalledVersion(ctx, o.layout)
	v.SingBoxLatest, v.SingBoxUpErr = singbox.LatestVersion(ctx)
	return v
}

// installedBuild 读取已安装程序的构建信息（build-info 子命令，与 go version -m 格式相同），并判断是否与当前程序相同
func installedBuild(ctx context.Context, bin string) (Build, bool, error) {
	if _, err := os.Stat(bin); err != nil {
		return Build{}, false, err
	}
	out, err := exec.CommandContext(ctx, bin, "build-info").Output()
	if err != nil {
		return Build{}, false, fmt.Errorf("%s build-info: %w", bin, err)
	}
	same := false
	if self, err := os.Executable(); err == nil {
		a, errA := system.FileSHA256(self)
		b, errB := system.FileSHA256(bin)
		same = errA == nil && errB == nil && a == b
	}
	return parseBuildInfo(string(out)), same, nil
}

// parseBuildInfo 解析 debug.BuildInfo 的文本格式
func parseBuildInfo(s string) Build {
	var b Build
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch {
		case f[0] == "dep" && f[1] == "github.com/caddyserver/caddy/v2" && len(f) >= 3:
			b.Caddy = f[2]
		case f[0] == "build":
			k, v, _ := strings.Cut(f[1], "=")
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
	return b
}

func latestMain(ctx context.Context) (Build, error) {
	var b Build
	data, err := system.Fetch(ctx, repoAPI+"/commits/main")
	if err != nil {
		return b, err
	}
	var c struct {
		SHA    string `json:"sha"`
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(data, &c); err != nil || c.SHA == "" {
		return b, fmt.Errorf("parse latest commit: %v", err)
	}
	return Build{Revision: c.SHA, Time: c.Commit.Committer.Date}, nil
}
