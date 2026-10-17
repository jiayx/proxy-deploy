# proxy-deploy

`proxyd` 是一个面向 Linux / systemd 的代理服务部署编排 CLI。它把 Caddy（含 caddy-l4）、代理协议服务和网站组合成一套部署：根据 YAML 配置规划公网入口、管理证书、安装二进制、生成配置与 systemd unit，并提供状态、日志、重启和卸载命令。

当前支持 **AnyTLS（TCP）** 和 **Hysteria2（QUIC / UDP）**，服务端均由 sing-box 提供；网站支持静态文件和反向代理。支持系统级部署和 `--user` 用户级部署。

## 工作方式

默认示例同时启用两个协议，入口如下：

```text
公网 TCP/443 → Caddy l4 按 TLS SNI 分流
               ├─ anytls.example.com → Caddy 终结客户端 TLS
               │                      → TLS 连接本机 AnyTLS 后端
               └─ 其他 SNI / 网站流量 → 内部 HTTPS 网站（127.0.0.1:20000）

公网 UDP/443 → Hysteria2 直接监听，读取 Caddy 管理的证书
               └─ 非 Hysteria 请求 → 伪装网站（默认反代内部网站）

公网 TCP/80  → HTTP 跳转 HTTPS / ACME HTTP-01 验证
```

- TCP 和 UDP 可以使用相同的端口号。TCP 协议通过不同 SNI 与网站共享入口，后端只监听回环地址；Caddy 用统一管理的证书终结客户端 TLS，再把明文转发到回环地址上的协议后端（例如 AnyTLS 的 sing-box inbound）。
- 单个 UDP 协议独占某个端口时直接监听公网；规划器也已实现多个 QUIC 协议共享 UDP 端口时按 QUIC SNI 转发到回环后端的逻辑。目前注册的 UDP 协议只有 Hysteria2，尚未接入 TUIC 等其他协议。
- 内部网站以 HTTPS 监听 `127.0.0.1:20000`（供 TCP 入口转发，支持 HTTP/1.1 和 HTTP/2；入口通过 PROXY protocol 传递客户端地址，网站访问日志和反代后端的 `X-Forwarded-For` 都是真实 IP），同时以明文 HTTP 监听 `127.0.0.1:20001`（供协议伪装反代，保留原始 Host）；协议回环后端从 `20002` 起分配。
- 经 Caddy 转发的 TCP 协议（如 AnyTLS）在 sing-box 日志中的来源地址是 `127.0.0.1`：sing-box 自 1.6 起不再支持 PROXY protocol，无法从入口获得客户端地址。直接监听公网端口的协议（如 Hysteria2）能看到真实 IP。
- Caddy 统一管理主域名、启用协议的 SNI 和网站 `host` 的证书。Hysteria2 启动前会等待证书文件就绪（最多 3 分钟），续期后 sing-box 自动重新加载证书文件，无需重启服务；AnyTLS 的客户端 TLS 在 Caddy 终结，无需读取证书文件。

## 构建与部署

从源码构建 CLI（`go.mod` 当前声明 Go 1.27.1）：

```bash
go build -o proxyd ./cmd/proxyd
./proxyd -h
go test ./...
```

部署需要运行在有 `systemctl` 和 `journalctl` 的 Linux 主机上，系统级安装需要 root 权限。构建机与目标平台不同时，可在构建命令前指定 `GOOS=linux GOARCH=amd64` 或目标架构。

使用默认公网证书配置前，需把 `example.com`、`anytls.example.com` 和 `hysteria2.example.com` 替换为自己的域名并解析到服务器；使用额外的网站 `host` 或自定义 SNI 时，也需要配置相应解析。放行 TCP/80、TCP/443 和 UDP/443，并确保公网 ACME 验证可达。修改监听端口不会自动配置防火墙或公网端口转发。

```bash
# 1. 生成带注释的配置（协议密码已随机生成），编辑域名和邮箱
./proxyd init-config > deploy.yaml

# 2. 检查配置与入口规划；加 --show-caddy 可查看生成的 Caddy JSON
./proxyd -c deploy.yaml plan
./proxyd -c deploy.yaml --show-caddy plan

# 3. 在 Linux 服务器上安装并启动服务
sudo ./proxyd -c deploy.yaml deploy

# 4. 查看运行状态与证书有效期
sudo ./proxyd status

# 5. 再次输出客户端连接 URI（deploy 成功时也会输出）
./proxyd -c deploy.yaml client-config
```

`plan` 只做配置和路由规划，不写文件、不下载程序，也不探测实际端口占用。`deploy` 会检查监听端口、安装程序、生成并验证 Caddy 配置、写入 unit 和安装清单，再启动入口与协议服务并检查服务状态。

修改 YAML 后重新执行 `deploy` 即可应用配置；本次不再需要的旧 unit 会被移除。仅执行 `restart` 不会重新生成配置。

## 配置

`init-config` 输出的默认配置等价于：

```yaml
domain: example.com

server:
  address: example.com

certificates:
  provider: letsencrypt
  email: admin@example.com

entry:
  https_port: 443
  http_port: 80

protocols:
  - name: hysteria2
    enabled: true
    config:
      password: "<随机生成>"

  - name: anytls
    enabled: true
    config:
      password: "<随机生成>"

web:
  - name: site
    type: static
```

| 字段 | 含义与默认值 |
| --- | --- |
| `domain` | 必填，主域名和默认网站证书域名 |
| `server.address` | 客户端实际连接地址，默认等于 `domain`，可填 IP；不改变用于 TLS 的 SNI |
| `entry.https_port` / `http_port` | 默认 `443` / `80`，两者必须不同 |
| `protocols[].name` | 当前可用 `anytls`、`hysteria2` |
| `protocols[].enabled` | 只有显式设为 `true` 才启用 |
| `protocols[].port` | 公网端口，默认使用 `entry.https_port` |
| `protocols[].sni` | 默认 `<name>.<domain>`；TCP 协议的 SNI 必须与主域名及网站 `host` 不同 |
| `protocols[].config.password` | 两种协议均必填，不能是占位值 `change-me` |
| `anytls` 的 `config.padding_scheme` | 可选，填充方案，多行字符串或字符串列表，每行一条规则；格式同 sing-box anytls inbound |
| `hysteria2` 的 `config.masquerade_url` | 可选，覆盖默认的内部伪装网站地址 |

每种协议只能配置一个实例（重复的 `name` 会被拒绝）：二进制、配置路径和 systemd unit 都按协议名标识。配置中出现未知字段（例如拼错的字段名）时加载直接报错。

### 证书

| `certificates.provider` | 配置与行为 |
| --- | --- |
| `letsencrypt`（默认） | 使用 Let's Encrypt，必须填写 `email` |
| `acme` | 自定义 ACME 服务，必须填写 `email` 和 `ca`（ACME directory URL） |
| `internal` | 使用 Caddy 内部 CA，适合测试，无需 `email`；不会自动安装根证书到系统信任库，生成的客户端 URI 带 `insecure=1` |

ACME 配置还支持 `dns_provider` 和 `dns_config`，分别指定 Caddy DNS provider 名称及其配置字段。使用 DNS 验证时，需自行提供同时包含 caddy-l4 和对应 DNS provider 模块的 Caddy 二进制，再通过 `--caddy-binary` 部署；默认 xcaddy 回退构建只加入 caddy-l4。

### 网站

`web` 为空时自动提供默认静态站；`type: static` 未填 `root` 时使用 `<prefix>/www`，首次部署会在该目录不存在时创建欢迎页。可按 HTTP Host 配置多个站点，未填 `host` 的条目作为兜底站点（配置一个即可）：

```yaml
web:
  - name: app
    type: reverse_proxy
    host: app.example.com
    upstream: 127.0.0.1:3000
  - name: site
    type: static
    root: /srv/www
```

反向代理要求填写 `upstream`；自定义静态目录需自行准备并确保服务可读。配置生成时会加入网站 `host` 对应的证书。

## 命令与选项

选项统一放在命令前，例如 `./proxyd -n 100 -f logs anytls`。

| 命令 | 用途 | 是否需要 YAML |
| --- | --- | --- |
| `init-config` | 向标准输出写入示例配置 | 否 |
| `plan` | 显示入口、协议、证书和规划冲突 | 是 |
| `deploy` | 安装、更新并启动服务，输出客户端 URI | 是 |
| `client-config` | 根据当前 YAML 生成客户端 URI | 是 |
| `status` | 查看已安装服务状态与证书有效期 | 否，读取安装清单 |
| `logs <服务>` | 查看 Caddy 或协议服务日志 | 否，读取安装清单 |
| `restart [服务]` | 重启全部或指定服务 | 否，读取安装清单 |
| `uninstall` | 停用并删除记录的 unit，删除整个安装目录 | 否，读取安装清单 |

| 选项 | 默认值 / 用途 |
| --- | --- |
| `-c <路径>` | 配置路径，默认 `deploy.yaml` |
| `--prefix <目录>` | 安装目录，系统模式默认 `/opt/proxy-deploy`，用户模式默认 `~/.local/proxy-deploy`；建议使用独立的绝对路径 |
| `--user` | 使用 `systemctl --user` 和用户级 unit 目录 |
| `--caddy-binary <路径>` | `deploy` 时复制并使用本地 Caddy 二进制，必须含所需 l4 模块 |
| `--show-caddy` | `plan` 时额外输出生成的 Caddy JSON |
| `-n <行数>` / `-f` | 日志行数（默认 50）/ 持续跟随日志 |

```bash
sudo ./proxyd -n 100 -f logs anytls
sudo ./proxyd logs caddy
sudo ./proxyd restart hysteria2
sudo ./proxyd restart
sudo ./proxyd uninstall
```

运维命令须使用与部署时一致的 `--user` 和 `--prefix`。`client-config` 读取当前 YAML，不核对已运行的配置；修改配置后应先重新部署再分发 URI。

### 用户级部署

在提供可用 systemd 用户实例的 Linux 主机上，可不使用 root 部署。先将 YAML 中的端口改为高位端口，例如 `entry.https_port: 8443`、`entry.http_port: 8080`（以及显式设置的协议端口均使用大于 1024 的端口）。本机测试可同时将 `certificates.provider` 改为 `internal`，避免公网 ACME 验证要求。

```bash
./proxyd --user -c deploy.yaml plan
./proxyd --user -c deploy.yaml deploy
./proxyd --user status
./proxyd --user -f logs caddy
./proxyd --user uninstall
```

用户服务默认随登录会话启停：未开启 linger 时，用户注销后服务会被停止，开机后也不会自动启动。`deploy` 和 `status` 检测到这种情况会给出提示，需由管理员执行一次 `sudo loginctl enable-linger <用户名>`。

高位端口下使用公网 ACME 证书时，仍需保证 CA 的验证流量能到达服务，或配置 DNS 验证。

## 程序安装与文件布局

Caddy 的安装来源按以下优先级选择，并在安装后检查 TLS / QUIC 匹配和 TLS / proxy 处理模块：

1. `--caddy-binary` 指定的本地文件。
2. 安装目录中已有的 `bin/caddy`。
3. 本项目 GitHub Releases 中 `caddy` release 的 `caddy-l4-<os>-<arch>` 预构建文件，用同时发布的 `.sha256` 文件校验。该 release 由 `.github/workflows/caddy.yml` 构建 linux amd64 / arm64，每月自动重建；也可手动触发并指定 Caddy 版本或额外插件（例如 DNS provider）。已安装的 `bin/caddy` 不会被自动替换。
4. 下载失败时使用本机 `xcaddy build --with github.com/mholt/caddy-l4` 构建，需预先安装 xcaddy 和可用的 Go 工具链。

协议程序从各自上游 GitHub Releases 下载，版本和各平台的 sha256 固定在适配器源码中（当前 sing-box `1.14.3`，支持 linux amd64 / arm64），校验不通过不会写入文件。所有协议都使用 sing-box 作为服务端：共用一份二进制，每个协议运行独立的进程和 unit，修改或重启某个协议不影响其他协议的连接。程序按版本保存并通过符号链接使用；重复部署会复用已存在的版本，部署成功后清理 `bin/` 中不再使用的程序和版本；更新配置不会自动追踪上游最新版本。部署主机需能访问相应下载地址。

```text
<prefix>/
├── bin/                   # Caddy、协议程序链接及 versions/ 下的版本文件
├── etc/
│   ├── caddy/config.json  # 生成的 Caddy 配置
│   ├── hysteria2/config.json # sing-box 配置
│   └── anytls/config.json
├── var/
│   ├── caddy/             # Caddy 证书、私钥及 CA 数据
│   ├── caddy-admin.sock   # Caddy 管理接口 Unix socket
│   └── xdg/               # Caddy 其他运行时数据
├── www/                   # 默认网站
└── manifest.json          # 服务、unit、端口及证书路径的安装清单
```

生成的 Caddy 配置和协议配置（含密码）权限为 `0600`。`deploy.yaml` 由使用者保存，不会自动复制到安装目录。

systemd unit 在安装目录之外：系统模式写入 `/etc/systemd/system/`，用户模式写入 `$XDG_CONFIG_HOME/systemd/user/`（未设置时为 `~/.config/systemd/user/`）。主服务名为 `proxy-deploy-caddy.service`、`proxy-deploy-anytls.service` 和 `proxy-deploy-hysteria2.service`。

`uninstall` 根据清单清理 unit，并递归删除整个 `<prefix>`，包括证书和默认网站；自定义前缀应专用于此部署。外部网站目录及存放在前缀之外的 YAML 和 CLI 二进制不由卸载命令删除。unit 名称固定，使用不同前缀不代表能在同一个 systemd 实例中同时运行多套部署。

## 源码结构与扩展

```text
cmd/proxyd/                CLI 命令、选项和输出
internal/config/           YAML 类型、默认值、基础校验和示例
internal/orchestrator/     入口规划、冲突检查、部署、清单和 systemd 管理
internal/entry/caddy/      Caddy 安装、模块检查和 JSON 配置生成
internal/protocol/         协议接口、注册表及 anytls / hysteria2 适配器；singbox/ 为共用的 sing-box 安装与配置
pkg/paths/                 安装前缀和系统 / 用户模式路径
pkg/system/                下载、解压、版本安装、文件写入和 systemctl 封装
```

新增协议需实现 `protocol.Adapter` 并在 `cmd/proxyd/main.go` 注册；按需实现 `Validator`（规划阶段校验）和 `CertConsumer`（读取证书文件，编排器会等证书签发后再启动）接口。以 sing-box 为服务端的协议可复用 `internal/protocol/singbox` 的安装和配置生成，只需提供 inbound 字段。编排器统一处理入口、证书和服务生命周期；`TransportBoth`（同时监听 TCP 和 UDP）当前仍会被规划器拒绝。
