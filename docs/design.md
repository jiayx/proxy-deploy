# proxy-deploy 设计

## 目标

服务器首先是一台 Web 服务器，代理协议是挂在网关后面的几条路由：

- 所有公网流量（TCP 和 UDP）先进入网关。网关根据握手中的明文信息（SNI 等）判断：返回网站，还是转发给后端的代理服务。流量不会先进入代理软件、失败后再回退到网站。
- 网站和服务器上已有的 HTTP 服务是主角，代理服务出问题不影响它们。
- 网关负责统计和管理：所有流量都经过它，客户端真实地址也只有它知道。
- 分流由客户端负责，服务端不做按域名或 IP 的路由。以后可能需要的只有一项：让部分流量从 WARP 或另一台机器出站。

## 架构

```text
                    ┌─────────────────────── Caddy（自行构建）────────────────────────┐
公网 TCP/443  ───▶  │ proxy_gateway 应用（本仓库 gateway/）                            │
公网 UDP/443  ───▶  │   ├─ 解析 TLS ClientHello / QUIC Initial，取得 SNI、ALPN         │
                    │   ├─ 协议路由：终结 TLS（证书来自 Caddy tls 应用）→ 回环后端      │
                    │   ├─ 其他流量：原样透传给网站（附 PROXY protocol）               │
                    │   ├─ 统计：每个连接的客户端地址、路由、字节数、后端本地端口      │
                    │   └─ 管理接口：挂在 Caddy admin API 下（/proxy_gateway/...）      │
                    │ http 应用：网站（回环地址，HTTPS + 明文 HTTP）、HTTP→HTTPS 跳转  │
                    │ tls 应用：证书申请与续期                                       │
                    └────────────────────────────────────────────────────────────┘
                                │ 回环地址
                    sing-box（每个协议一个进程，由网关启动和监管）：anytls、hysteria2 ……
```

- **网关**：以 Caddy 应用模块的形式实现（`gateway/`），不依赖 caddy-l4。我们需要的四层功能很少（按 SNI 路由、终结或透传 TLS、TCP/UDP 转发），自己实现后可以按需扩展，统计也能直接放在转发路径里做。
- **Caddy 构建**：`cmd/caddy` 是一个导入官方标准模块和 `gateway` 的 Caddy 入口，依赖版本由本仓库 `go.mod` 固定，用 `go build` 直接构建，不需要 xcaddy。
- **协议后端**：sing-box，每个协议一个独立进程。改动或重启一个协议不影响其他协议；某个协议出问题也不会把网关和网站带挂。
- **`proxyd`**：负责安装二进制、根据 `deploy.yaml` 生成 Caddy 和 sing-box 配置、管理唯一的 systemd unit（Caddy）。sing-box 进程由网关监管，`proxyd` 的运维命令（状态、日志、重启）通过 Caddy 管理接口完成。

## 网关配置（JSON）

```json
"apps": {
  "proxy_gateway": {
    "servers": {
      "tcp_443": {
        "listen": [":443"],
        "routes": [
          {"name": "anytls", "sni": ["anytls.example.com"], "tls": "terminate", "upstream": "127.0.0.1:20002"}
        ],
        "fallback": {"name": "site", "tls": "passthrough", "upstream": "127.0.0.1:20000", "proxy_protocol": true}
      }
    }
  }
}
```

| 字段 | 含义 |
| --- | --- |
| `routes[].name` | 路由名，用于日志和统计，通常是协议名 |
| `routes[].sni` | 匹配的 SNI（精确匹配） |
| `routes[].tls` | `terminate`：用 Caddy 管理的证书终结 TLS，把明文转给后端；`passthrough`：原样转发 |
| `routes[].upstream` | 后端地址 |
| `routes[].proxy_protocol` | 转发前写入 PROXY protocol v2 头，让后端拿到客户端地址（后端需支持；sing-box 不支持） |
| `fallback` | 没有匹配到任何路由的连接（包括非 TLS 流量、ACME TLS-ALPN 验证）的去向 |
| `raw` | 端口专属于一个后端（没有 SNI 的协议，如 Shadowsocks）：不识别 TLS / QUIC，全部连接直接交给 `fallback`；UDP 会话也不学习 QUIC 连接 ID |

证书由 Caddy `tls` 应用的 `automate` 统一申请。网关终结 TLS 时使用 Caddy 的连接策略，按 SNI 取证书。

## UDP 网关

- 会话按客户端地址识别。建立前缓存客户端数据报（最多 16 个），从 QUIC Initial 包重组出 ClientHello 后按 SNI 选路由、连接后端并回放缓存。
- Caddy 重载配置时用 SO_REUSEPORT 绑定同端口的新 socket，所以会话表按监听地址放在进程级，新旧应用实例共用，回包总是经由最新的 socket 发出。
- 连接迁移：QUIC 按连接 ID 识别连接。网关从后端回包的长包头学到服务端连接 ID 的长度，并从客户端短包头学习它当前使用的连接 ID（客户端握手后会改用服务端在加密帧中下发的新 ID，所以只看握手包不够），每个会话保留最近 8 个。陌生地址发来的数据报若带着已知连接 ID，就归入原会话；原地址静默超过 1 秒才把回包切到新地址，防止能看到连接 ID 的中间人伪造来源地址劫持正在通信的会话。客户端主动迁移并换用从未用过的连接 ID 时无法识别，需重新连接。
- 性能：上传方向逐个数据报转发，下载方向在 Linux 上用 GRO/GSO 批量转发。单机回环测试中，经网关的 Hysteria2 下载约为直连的 80%。

## 后端进程监管

```json
"backends": {
  "hysteria2": {
    "command": ["/opt/proxy-deploy/bin/sing-box", "run", "--disable-color", "-c", "/opt/proxy-deploy/etc/hysteria2/config.json"],
    "require_files": ["…/hysteria2.example.com.crt", "…/hysteria2.example.com.key"],
    "revision": "3f2a9c…"
  }
}
```

- 进程表按后端名放在进程级。Caddy 重载时先启动新配置再停止旧配置：命令、环境、`require_files`、`revision` 都相同的后端以引用计数沿用原进程；有变化的先停旧进程（释放端口）再启动新进程。`revision` 由 `proxyd` 根据配置文件内容和程序实际版本计算。
- 进程退出后按 1 秒起、最长 10 秒的间隔重启；连续运行超过 10 秒后间隔重置。`require_files` 齐全前处于 `waiting` 状态，首次部署时等证书签发。
- 停止时先 SIGTERM，10 秒后 SIGKILL。Linux 上设置 Pdeathsig（监管 goroutine 锁定系统线程），Caddy 异常退出时子进程随之退出；systemd 停止服务时也会清理整个 cgroup。
- 子进程标准输出和错误按行写入 Caddy 日志（`backend` 字段，按 sing-box 前缀映射级别），并保留最后 30 行供管理接口返回。
- 管理接口：`GET /proxy_gateway/backends`（状态、PID、运行时长、重启次数、最近输出），`POST /proxy_gateway/backends/<名称>/restart`。
- 部署时协议配置先校验再写入。证书尚未签发时，用临时自签证书生成同样的配置交给 `sing-box check`。

## 统计与日志

- 每个连接结束时记一条日志：客户端地址、SNI、路由、后端本地地址、上下行字节、时长。
- 后端本地地址就是 sing-box 日志中的 `inbound connection from 127.0.0.1:<端口>`，据此可以把客户端真实地址和 sing-box 里的用户对应起来。
- 每个路由的累计连接数、活动连接数、上下行字节，通过 `GET /proxy_gateway/stats`（Caddy admin 接口）读取，`proxyd status` 显示。计数在进程生命周期内保留，Caddy 重载配置不会清零。

## 实现步骤

1. **TCP 网关**（已完成）：ClientHello 解析、终结与透传、PROXY protocol、统计与管理接口；Caddy 改为本仓库构建，去掉 caddy-l4。
2. **UDP 网关**（已完成）：QUIC Initial 解密与 ClientHello 重组（v1/v2，跨包、乱序），按客户端地址维护会话并转发，Linux 上用 GRO/GSO 成批转发回包；主域名的 HTTP/3 由 Caddy 网站直接提供，Hysteria2 退到网关后面。以后支持 Hysteria2 混淆时，启用混淆的协议作为例外独占端口（混淆后的数据报无法识别 SNI）。
3. **sing-box 进程监管**（已完成）：由网关启动并监管 sing-box，Caddy 重载配置时保留没有变化的协议进程；systemd 只剩 Caddy 一个服务。
4. **管理与配置**：Caddyfile 支持、管理接口（状态、用户）、`proxyd` 退化成安装器。
5. **其他**：接入已有 Web 服务器（非代理流量透传给现有 nginx / Caddy）、WARP 等出口。

## 取舍记录

- **不嵌入 sing-box**：嵌进 Caddy 进程能拿到真实 IP，但代理的 bug 会连带网站，sing-box 是 GPL-3.0，内部 Go 接口也不稳定。保持独立进程。
- **不用 sing-box 做入口**：它不能按 SNI 把同一端口分给多个 inbound，也不提供网站，只能做“代理优先、失败回退”。
- **网关只能按明文信息判断**：使用协议 SNI 的连接无论密码对错都会到达后端，认证失败仍由后端处理（Hysteria2 转给伪装网站，AnyTLS 断开连接）。基于 HTTP 的传输方式（WebSocket、gRPC）可以在网关检查路径。
