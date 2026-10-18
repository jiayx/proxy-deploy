package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/jiayx/proxy-deploy/internal/entry/caddy"
	"github.com/jiayx/proxy-deploy/internal/protocol/singbox"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

// repoAPI 是本仓库的 GitHub API 地址，用来查看 main 分支的最新提交
const repoAPI = "https://api.github.com/repos/jiayx/proxy-deploy"

// Versions 是 proxyd、网关（proxy-gateway）、sing-box 的当前版本和可用的新版本；
// 每一项单独查询，失败时记在对应的 Err 字段，不影响其他项
type Versions struct {
	Proxyd, Main             caddy.Build // proxyd 自身的构建、仓库 main 分支的最新提交
	ProxydErr, MainErr       error
	Gateway, GatewayRelease  *caddy.Build // 已安装的、最新发布的网关
	GatewayErr, ReleaseErr   error
	SingBox, SingBoxLatest   string // 已安装的、上游最新的正式版本
	SingBoxErr, SingBoxUpErr error
	LocalGateway             bool // 网关是 --gateway-binary 安装的本地构建，deploy 不会自动更新
}

// SingBoxPinned 是 proxyd 安装的 sing-box 版本
const SingBoxPinned = singbox.Version

// Versions 查询各组件版本；需要访问 GitHub
func (o *Orchestrator) Versions(ctx context.Context) *Versions {
	v := &Versions{}
	v.Proxyd, v.ProxydErr = selfBuild()
	v.Main, v.MainErr = latestMain(ctx)
	v.Gateway, v.GatewayErr = caddy.InstalledBuild(ctx, o.layout)
	if m, err := LoadManifest(o.layout); err == nil {
		v.LocalGateway = m.LocalGateway
	}
	v.GatewayRelease, v.ReleaseErr = caddy.ReleaseBuild(ctx)
	v.SingBox, v.SingBoxErr = singbox.InstalledVersion(ctx, o.layout)
	v.SingBoxLatest, v.SingBoxUpErr = singbox.LatestVersion(ctx)
	return v
}

// selfBuild 从 Go 构建信息读取 proxyd 自身的提交
func selfBuild() (caddy.Build, error) {
	var b caddy.Build
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return b, fmt.Errorf("没有构建信息")
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			b.Revision = s.Value
		case "vcs.time":
			b.Time, _ = time.Parse(time.RFC3339, s.Value)
		case "vcs.modified":
			b.Modified = s.Value == "true"
		}
	}
	if b.Revision == "" {
		return b, fmt.Errorf("构建时没有记录提交（需要在 git 仓库中 go build）")
	}
	return b, nil
}

func latestMain(ctx context.Context) (caddy.Build, error) {
	var b caddy.Build
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
	return caddy.Build{Revision: c.SHA, Time: c.Commit.Committer.Date}, nil
}
