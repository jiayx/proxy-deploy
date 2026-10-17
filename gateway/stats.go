package gateway

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(adminAPI{})
}

// routeStats 是一条路由的累计统计。按路由名保存在进程级的注册表里，
// Caddy 重载配置（重建应用实例）不会清零
type routeStats struct {
	Active    atomic.Int64
	Total     atomic.Int64
	BytesUp   atomic.Int64 // 客户端 → 后端
	BytesDown atomic.Int64 // 后端 → 客户端
}

var registry sync.Map // 路由名 → *routeStats

func statsFor(route string) *routeStats {
	s, _ := registry.LoadOrStore(route, new(routeStats))
	return s.(*routeStats)
}

// RouteSnapshot 是管理接口返回的一条路由统计
type RouteSnapshot struct {
	Route     string `json:"route"`
	Active    int64  `json:"active"`
	Total     int64  `json:"total"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
}

func snapshot() []RouteSnapshot {
	var out []RouteSnapshot
	registry.Range(func(k, v any) bool {
		s := v.(*routeStats)
		out = append(out, RouteSnapshot{
			Route:     k.(string),
			Active:    s.Active.Load(),
			Total:     s.Total.Load(),
			BytesUp:   s.BytesUp.Load(),
			BytesDown: s.BytesDown.Load(),
		})
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Route < out[j].Route })
	return out
}

// adminAPI 在 Caddy admin 接口下提供 GET /proxy_gateway/stats
type adminAPI struct{}

func (adminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.proxy_gateway",
		New: func() caddy.Module { return adminAPI{} },
	}
}

func (adminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{{
		Pattern: "/proxy_gateway/stats",
		Handler: caddy.AdminHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			if r.Method != http.MethodGet {
				return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed}
			}
			w.Header().Set("Content-Type", "application/json")
			return json.NewEncoder(w).Encode(snapshot())
		}),
	}}
}

var _ caddy.AdminRouter = adminAPI{}
