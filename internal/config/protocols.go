package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Protocols 是启用的协议，按 deploy.yaml 中的书写顺序排列。
// 配置里写成以协议名为键的映射，列出即启用；值可以为空，也可以是该协议的选项：
//
//	protocols:
//	  anytls:
//	  ss2022: {port: 8388, password: "..."}
type Protocols []ProtocolConfig

func (ps *Protocols) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: protocols must be a mapping from protocol name to options, e.g. \"anytls: {}\"", n.Line)
	}
	seen := map[string]bool{}
	for i := 0; i < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if seen[k.Value] {
			return fmt.Errorf("line %d: duplicate protocol %q (each protocol can be configured once)", k.Line, k.Value)
		}
		seen[k.Value] = true
		p := ProtocolConfig{Name: k.Value, Options: map[string]any{}}
		if !(v.Kind == yaml.ScalarNode && v.Tag == "!!null") {
			if v.Kind != yaml.MappingNode {
				return fmt.Errorf("line %d: protocols.%s must be empty or a mapping of options", v.Line, k.Value)
			}
			if err := v.Decode(&p.Options); err != nil {
				return fmt.Errorf("protocols.%s: %w", k.Value, err)
			}
		}
		if port, ok := p.Options["port"]; ok {
			n, ok := port.(int)
			if !ok || n < 1 || n > 65535 {
				return fmt.Errorf("protocols.%s: invalid port %v", k.Value, port)
			}
			p.Port = n
			delete(p.Options, "port")
		}
		if sni, ok := p.Options["sni"]; ok {
			s, ok := sni.(string)
			if !ok || s == "" {
				return fmt.Errorf("protocols.%s: sni must be a domain name", k.Value)
			}
			p.SNI = s
			delete(p.Options, "sni")
		}
		*ps = append(*ps, p)
	}
	return nil
}

// Names 返回启用的协议名
func (ps Protocols) Names() []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}
