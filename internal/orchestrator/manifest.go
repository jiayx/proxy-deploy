package orchestrator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/jiayx/proxy-deploy/pkg/paths"
	"github.com/jiayx/proxy-deploy/pkg/system"
)

// Manifest 记录一次部署在系统中留下的全部痕迹，status/logs/uninstall 都只依赖它
type Manifest struct {
	Prefix   string     `json:"prefix"`
	User     bool       `json:"user"`
	Services []string   `json:"services"` // 主服务 unit，状态展示用
	Units    []string   `json:"units"`    // 写入 unit 目录的全部文件名
	Ports    []Port     `json:"ports"`
	Certs    []CertFile `json:"certs"`
}

type CertFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// ErrNotInstalled 表示前缀目录下没有安装记录
var ErrNotInstalled = errors.New("未找到安装记录")

func LoadManifest(l *paths.Layout) (*Manifest, error) {
	data, err := os.ReadFile(l.ManifestPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w：%s", ErrNotInstalled, l.ManifestPath())
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", l.ManifestPath(), err)
	}
	return &m, nil
}

func saveManifest(l *paths.Layout, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return system.WriteFile(l.ManifestPath(), data, 0644)
}
