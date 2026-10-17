// Package system 封装二进制下载、文件写入和 systemd 管理。
package system

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// httpClient 的超时覆盖整个下载过程，避免网络异常时部署无限挂起
var httpClient = &http.Client{Timeout: 10 * time.Minute}

// Download 将 url 下载到 dest，设置文件权限 mode，幂等（已存在则跳过）。
// sha256 非空时校验下载内容。
func Download(ctx context.Context, url, sum, dest string, mode os.FileMode) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	data, err := fetch(ctx, url, sum)
	if err != nil {
		return err
	}
	return WriteFile(dest, data, mode)
}

// DownloadAndExtract 下载 zip 或 tar.gz 包并校验 sha256，从中提取指定文件名的条目到 dest，幂等。
func DownloadAndExtract(ctx context.Context, url, sum, entryName, dest string, mode os.FileMode) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	data, err := fetch(ctx, url, sum)
	if err != nil {
		return err
	}
	var entry []byte
	if strings.HasSuffix(url, ".tar.gz") {
		entry, err = extractTarGz(data, entryName)
	} else {
		entry, err = extractZip(data, entryName)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	return WriteFile(dest, entry, mode)
}

func extractZip(data []byte, entryName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != entryName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open zip entry %s: %w", f.Name, err)
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("entry %q not found in archive", entryName)
}

func extractTarGz(data []byte, entryName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open tar.gz: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("entry %q not found in archive", entryName)
		}
		if err != nil {
			return nil, fmt.Errorf("read tar.gz: %w", err)
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == entryName {
			return io.ReadAll(tr)
		}
	}
}

// FetchChecksum 读取 sha256sum 格式的校验文件，返回第一个字段
func FetchChecksum(ctx context.Context, url string) (string, error) {
	data, err := fetch(ctx, url, "")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 || len(fields[0]) != sha256.Size*2 {
		return "", fmt.Errorf("%s 不是有效的 sha256 校验文件", url)
	}
	return fields[0], nil
}

func fetch(ctx context.Context, url, wantSum string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if wantSum != "" {
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, wantSum) {
			return nil, fmt.Errorf("download %s: sha256 不匹配（期望 %s，实际 %s）", url, wantSum, got)
		}
	}
	return data, nil
}

// InstallVersioned 把二进制保存为带版本号的 versioned 文件（已存在则复用），
// 再把 link 原子地指向它。不再使用的版本由 PruneBinaries 清理。
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

// PruneBinaries 删除 binDir 下不在 keep 中的文件和链接，以及 binDir/versions 下
// 没有被保留的链接指向的版本文件，返回删除的路径（相对 binDir）。
func PruneBinaries(binDir string, keep []string) ([]string, error) {
	kept := map[string]bool{}
	for _, k := range keep {
		kept[filepath.Clean(k)] = true
	}
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return nil, err
	}
	var removed []string
	targets := map[string]bool{}
	for _, e := range entries {
		path := filepath.Join(binDir, e.Name())
		if e.IsDir() {
			continue
		}
		if !kept[path] {
			if err := os.Remove(path); err != nil {
				return removed, err
			}
			removed = append(removed, e.Name())
			continue
		}
		if target, err := os.Readlink(path); err == nil {
			if !filepath.IsAbs(target) {
				target = filepath.Join(binDir, target)
			}
			targets[filepath.Clean(target)] = true
		}
	}

	versionsDir := filepath.Join(binDir, "versions")
	versions, err := os.ReadDir(versionsDir)
	if errors.Is(err, os.ErrNotExist) {
		return removed, nil
	}
	if err != nil {
		return removed, err
	}
	for _, v := range versions {
		path := filepath.Join(versionsDir, v.Name())
		if targets[path] {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return removed, err
		}
		removed = append(removed, filepath.Join("versions", v.Name()))
	}
	return removed, nil
}

// WriteFileChecked 先把内容写到 dest 旁的临时文件，用 check 校验通过后再替换 dest。
// 校验失败时 dest 保持原样，正在运行的服务重启后仍读到旧配置。
// 临时文件保留原扩展名（config.json → config.check.json），便于按扩展名识别格式的校验工具。
func WriteFileChecked(dest string, data []byte, mode os.FileMode, check func(path string) error) error {
	ext := filepath.Ext(dest)
	tmp := strings.TrimSuffix(dest, ext) + ".check" + ext
	if err := WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := check(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
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

func (s Systemd) Stop(ctx context.Context, unit string) error { return s.run(ctx, "stop", unit) }

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
