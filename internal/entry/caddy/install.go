package caddy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jiayx/proxy-gateway/pkg/paths"
	"github.com/jiayx/proxy-gateway/pkg/system"
)

// Install 把当前运行的程序复制为安装目录中的网关程序：同一个 proxy-gateway 既是命令行工具，
// 也是服务里运行的网关（proxy-gateway run，即 Caddy），所以两者的版本总是一致。
// 已安装的与当前程序相同时不动；changed 表示程序被替换，正在运行的网关需要重启（reload 不会换掉进程）。
func Install(layout *paths.Layout) (changed bool, err error) {
	self, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("locate own executable: %w", err)
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return false, err
	}
	dest := layout.GatewayBin()
	if d, err := filepath.EvalSymlinks(dest); err == nil && d == self {
		return false, nil // 正在运行的就是已安装的程序
	}
	want, err := system.FileSHA256(self)
	if err != nil {
		return false, err
	}
	if have, err := system.FileSHA256(dest); err == nil && have == want {
		return false, nil
	}
	return true, system.CopyFile(self, dest, 0755)
}
