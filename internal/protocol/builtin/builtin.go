// Package builtin 注册 proxy-gateway 内置的全部协议适配器。
package builtin

import (
	"github.com/jiayx/proxy-gateway/internal/protocol"
	"github.com/jiayx/proxy-gateway/internal/protocol/anytls"
	"github.com/jiayx/proxy-gateway/internal/protocol/hysteria2"
	"github.com/jiayx/proxy-gateway/internal/protocol/ss2022"
	"github.com/jiayx/proxy-gateway/internal/protocol/tuic"
	"github.com/jiayx/proxy-gateway/internal/protocol/vlessreality"
	"github.com/jiayx/proxy-gateway/pkg/paths"
)

// Registry 返回包含全部内置协议的注册表
func Registry(layout *paths.Layout) *protocol.Registry {
	reg := protocol.NewRegistry()
	reg.Register(hysteria2.New(layout))
	reg.Register(anytls.New(layout))
	reg.Register(vlessreality.New(layout))
	reg.Register(tuic.New(layout))
	reg.Register(ss2022.New(layout))
	return reg
}
