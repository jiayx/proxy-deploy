// Package system 封装二进制下载、文件写入和 systemd 管理。
package system

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Download 将 url 下载到 dest，设置文件权限 mode，幂等（已存在则跳过）。
func Download(ctx context.Context, url, dest string, mode os.FileMode) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	data, err := fetch(ctx, url)
	if err != nil {
		return err
	}
	return WriteFile(dest, data, mode)
}

// DownloadAndExtract 下载 zip 包，从中提取指定文件名的条目到 dest，幂等。
func DownloadAndExtract(ctx context.Context, url, entryName, dest string, mode os.FileMode) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	data, err := fetch(ctx, url)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("open zip from %s: %w", url, err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != entryName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %s: %w", f.Name, err)
		}
		entry, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("extract %s: %w", entryName, err)
		}
		return WriteFile(dest, entry, mode)
	}
	return fmt.Errorf("entry %q not found in zip from %s", entryName, url)
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// InstallVersioned 把二进制保存为带版本号的 versioned 文件（已存在则复用），
// 再把 link 原子地指向它。旧版本文件保留，便于回滚。
func InstallVersioned(versioned, link string, fetch func(dest string) error) error {
	if _, err := os.Stat(versioned); err != nil {
		if err := fetch(versioned); err != nil {
			return err
		}
	}
	target, err := filepath.Rel(filepath.Dir(link), versioned)
	if err != nil {
		return err
	}
	tmp := link + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

// CopyFile 把 src 复制到 dest（覆盖）。
func CopyFile(src, dest string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return WriteFile(dest, data, mode)
}

// WriteFile 原子写入 dest（先写临时文件再 rename），覆盖已有文件。
func WriteFile(dest string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dest), err)
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// Systemd 封装 systemctl；User 为 true 时操作用户实例（systemctl --user）。
type Systemd struct {
	User bool
}

func (s Systemd) Args(args ...string) []string {
	if s.User {
		return append([]string{"--user"}, args...)
	}
	return args
}

func (s Systemd) run(ctx context.Context, args ...string) error {
	args = s.Args(args...)
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (s Systemd) DaemonReload(ctx context.Context) error { return s.run(ctx, "daemon-reload") }

func (s Systemd) Enable(ctx context.Context, unit string) error { return s.run(ctx, "enable", unit) }

// Restart 重启服务；服务未运行时等同于启动。
func (s Systemd) Restart(ctx context.Context, unit string) error { return s.run(ctx, "restart", unit) }

// ReloadOrRestart 运行中则 reload，否则启动。
func (s Systemd) ReloadOrRestart(ctx context.Context, unit string) error {
	return s.run(ctx, "reload-or-restart", unit)
}

func (s Systemd) DisableNow(ctx context.Context, unit string) error {
	return s.run(ctx, "disable", "--now", unit)
}

// ActiveState 返回 systemctl is-active 的输出（active / inactive / failed ...）。
func (s Systemd) ActiveState(ctx context.Context, unit string) string {
	out, _ := exec.CommandContext(ctx, "systemctl", s.Args("is-active", unit)...).Output()
	return strings.TrimSpace(string(out))
}

// ResetFailed 清除 unit 的 failed 状态，忽略不存在的 unit
func (s Systemd) ResetFailed(ctx context.Context, units ...string) error {
	if len(units) == 0 {
		return nil
	}
	return s.run(ctx, append([]string{"reset-failed"}, units...)...)
}
