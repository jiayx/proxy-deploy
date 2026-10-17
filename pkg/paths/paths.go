// Package paths 管理所有文件路径，基于可配置的安装前缀。
//
// 除 systemd unit 文件外，所有文件都在前缀目录下；unit 文件名记录在
// manifest 中，卸载时据此清理，保证一键卸载干净。
package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// Layout 持有基于某个前缀派生的所有路径。
type Layout struct {
	Prefix string
	User   bool // rootless 模式：服务由 systemd --user 管理
}

// DefaultPrefix 返回默认安装前缀
func DefaultPrefix(user bool) string {
	if !user {
		return "/opt/proxy-deploy"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "proxy-deploy")
}

func New(prefix string, user bool) *Layout {
	if prefix == "" {
		prefix = DefaultPrefix(user)
	}
	return &Layout{Prefix: prefix, User: user}
}

func (l *Layout) BinDir() string       { return filepath.Join(l.Prefix, "bin") }
func (l *Layout) EtcDir() string       { return filepath.Join(l.Prefix, "etc") }
func (l *Layout) VarDir() string       { return filepath.Join(l.Prefix, "var") }
func (l *Layout) WWWDir() string       { return filepath.Join(l.Prefix, "www") }
func (l *Layout) ManifestPath() string { return filepath.Join(l.Prefix, "manifest.json") }

func (l *Layout) CaddyBin() string         { return filepath.Join(l.BinDir(), "caddy") }
func (l *Layout) CaddyConfig() string      { return filepath.Join(l.EtcDir(), "caddy", "config.json") }
func (l *Layout) CaddyDataDir() string     { return filepath.Join(l.VarDir(), "caddy") }
func (l *Layout) CaddyAdminSocket() string { return filepath.Join(l.VarDir(), "caddy-admin.sock") }

func (l *Layout) ProtocolBin(name string) string { return filepath.Join(l.BinDir(), name) }

// VersionedBin 返回某个版本的二进制路径；ProtocolBin 是指向它的符号链接
func (l *Layout) VersionedBin(name, version string) string {
	return filepath.Join(l.BinDir(), "versions", name+"-"+strings.NewReplacer("/", "-", " ", "-").Replace(version))
}

func (l *Layout) EnvFile(unit string) string     { return filepath.Join(l.EtcDir(), "env", unit+".env") }
func (l *Layout) ProtocolDir(name string) string { return filepath.Join(l.EtcDir(), name) }
func (l *Layout) ProtocolConfig(name string) string {
	return filepath.Join(l.ProtocolDir(name), "config.yaml")
}

// UnitDir 返回 systemd unit 文件目录（在前缀目录之外）
func (l *Layout) UnitDir() string {
	if !l.User {
		return "/etc/systemd/system"
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "systemd", "user")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user")
}

// UnitPath 返回某个 unit 文件（含 .service/.path 后缀）的完整路径
func (l *Layout) UnitPath(unit string) string { return filepath.Join(l.UnitDir(), unit) }
