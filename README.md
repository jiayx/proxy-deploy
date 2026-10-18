# proxy-gateway

`proxy-gateway` 让一台服务器首先是网站，代理协议藏在网站后面：所有公网流量先进入网关，由网关决定交给网站还是代理协议。整个项目只有一个程序 `proxy-gateway`：

- 在命令行里，它是部署和运维工具：根据 YAML 配置规划公网入口、安装程序、生成配置和 systemd 服务，并提供状态、日志、重启和卸载命令。
- 在服务器上，它是网关本身：官方 Caddy 的标准模块加上本仓库的网关模块，服务 `proxy-gateway.service` 执行的是 `proxy-gateway run`。它接收全部公网流量、提供网站、管理证书，并启动和监管协议后端。

`deploy` 把正在执行的程序复制到安装目录作为网关使用，所以部署工具和网关总是同一个版本。

有两种运行方式，网关的功能完全相同：

- **systemd**：`proxy-gateway deploy` 安装到 `/opt/proxy-gateway`，由 systemd 管理（也支持 `--user` 用户级部署）。
- **容器**：镜像 `ghcr.io/jiayx/proxy-gateway`，用 Docker / compose 管理，适合服务器上其他服务也跑在 Docker 里的情况，见[容器部署](#容器部署)。

当前支持 **AnyTLS**、**VLESS + Reality**（TCP，经网关）、**Hysteria2**、**TUIC v5**（QUIC，经网关）和 **Shadowsocks 2022**（TCP+UDP，经网关的专用端口），服务端均由 sing-box 提供；网站支持静态文件和反向代理。支持系统级部署和 `--user` 用户级部署。

## 工作方式

默认示例同时启用两个协议，入口如下：

```text
公网 TCP/443 → 网关按 TLS SNI 分流
               ├─ edge.example.com      → 网关终结 TLS → 回环地址上的 AnyTLS（sing-box）
               ├─ www.microsoft.com     → 原样透传 → 回环地址上的 VLESS + Reality（sing-box，自己握手）
               └─ 其他 SNI / 非 TLS 流量 → 内部 HTTPS 网站（127.0.0.1:20000，附 PROXY protocol）

公网 UDP/443 → 网关按 QUIC SNI 分流（解密 QUIC Initial 包取得 ClientHello）
               ├─ data.example.com      → 回环地址上的 Hysteria2（sing-box，读取网关管理的证书）
               │                          └─ 认证失败的请求 → 伪装网站（反代内部网站）
               ├─ gw.example.com        → 回环地址上的 TUIC（sing-box，读取网关管理的证书）
               └─ 其他 SNI（如浏览器 HTTP/3）→ 内部网站的 HTTP/3（127.0.0.1:20000）

公网 TCP/80  → HTTP 跳转 HTTPS / ACME HTTP-01 验证

公网 TCP+UDP/8388 → 网关专用端口（没有 SNI，不识别直接转发）→ 回环地址上的 Shadowsocks 2022（sing-box）
```

- 所有公网流量先进入网关，由网关决定交给网站还是代理协议，协议后端只监听回环地址；设计见 [docs/design.md](docs/design.md)。TCP 协议的客户端 TLS 由网关用统一管理的证书终结；QUIC 协议的数据报原样转发，由后端终结。多个协议可以共享同一个 TCP 或 UDP 端口，按 SNI 区分。
- 主入口端口总是开启 UDP 网关：内部网站因此提供 HTTP/3，TCP 网站通过 `Alt-Svc` 通告对外端口。需要放行 UDP/443。
- 网关为每个连接（UDP 为每个会话）记录一条日志（客户端地址、SNI、路由、后端本地地址、字节数、时长），`status` 显示每条路由的活动连接、累计连接和流量。网关重载配置时不会断开已建立的 TCP 连接和 QUIC 会话。
- 网关按用户统计流量：用户认证发生在 sing-box 内部，网关从它的日志中得知每个连接属于哪个用户（sing-box 日志中的来源端口就是网关连接后端用的本地端口），把连接流量计入该用户。`status` 显示每个用户的活动连接、累计连接和上下行流量；网关连接日志带 `user` 字段。统计按加密后的传输字节计算，会略多于实际内容；认证失败的连接不计入任何用户。用户流量每 30 秒及网关停止时写入 `<prefix>/var/usage.json`，重启后接着累计（`uninstall` 会一并删除）。
- 用户超过 `traffic_limit` 或过了 `expire` 后，网关断开他的全部活动连接；之后的新连接在认证完成、识别出用户时立即断开（不需要修改 sing-box 配置）。`status` 显示每个用户的状态、本周期用量 / 上限、到期日和限定的协议；修改上限或到期日后重新部署即可生效，已用流量不受影响。用量每秒结算一次，所以实际用量可能超出上限约 1 秒的传输量。
- UDP 会话按客户端地址识别，空闲 2 分钟后清理。网关同时学习每个会话的 QUIC 连接 ID，客户端地址变化（NAT 重新映射、切换网络但沿用原 socket）后仍能找回原会话，连接不断；客户端主动迁移并换用新连接 ID 时需要重新连接。Linux 上网关用 UDP GRO/GSO 成批转发后端回包。
- 内部网站以 HTTPS 监听 `127.0.0.1:20000`（供 TCP 入口转发，支持 HTTP/1.1 和 HTTP/2；入口通过 PROXY protocol 传递客户端地址，网站访问日志和反代后端的 `X-Forwarded-For` 都是真实 IP），同时以明文 HTTP 监听 `127.0.0.1:20001`（供协议伪装反代，保留原始 Host）；每个经网关转发的协议在适配器中声明固定的回环端口（Hysteria2 20002、AnyTLS 20003、VLESS + Reality 20004、TUIC 20005），测试保证互不重复；启用、停用、新增或删除其他协议都不会改变已有协议的端口，也就不会让它们重启。
- 协议后端（sing-box）日志中的来源地址都是 `127.0.0.1`：sing-box 自 1.6 起不再支持 PROXY protocol。客户端真实地址记录在网关日志中，网关日志的 `upstream_local` 与 sing-box 日志中的来源端口一一对应。
- 网关（使用 Caddy 的证书管理）统一管理主域名、启用协议的 SNI 和网站 `host` 的证书。Hysteria2 启动前会等待证书文件就绪（最多 3 分钟），续期后 sing-box 自动重新加载证书文件，无需重启服务；AnyTLS 的客户端 TLS 在网关终结，无需读取证书文件。

## 构建与部署

下载 main 分支最新的构建（每次提交自动更新），或打 tag 后的正式版本：

```bash
curl -LO https://github.com/jiayx/proxy-gateway/releases/download/edge/proxy-gateway-linux-amd64
chmod +x proxy-gateway-linux-amd64 && mv proxy-gateway-linux-amd64 proxy-gateway
```

也可以从源码构建（`go.mod` 当前声明 Go 1.27.1）：

```bash
go build -o proxy-gateway ./cmd/proxy-gateway
./proxy-gateway -h
go test ./...
```

部署需要运行在有 `systemctl` 和 `journalctl` 的 Linux 主机上，系统级安装需要 root 权限。`init-config`、`plan`、`client-config` 在其他系统上也能运行。构建机与目标平台不同时，可在构建命令前指定 `GOOS=linux GOARCH=amd64` 或目标架构。

使用默认公网证书配置前，需把 `example.com` 替换为自己的域名，并把它和 `*.<domain>`（各协议默认 SNI 都是它下一级的子域名，`plan` 会列出来）解析到服务器；使用额外的网站 `host` 或自定义 SNI 时，也需要配置相应解析。放行 TCP/80、TCP/443 和 UDP/443，并确保公网 ACME 验证可达。修改监听端口不会自动配置防火墙或公网端口转发。

```bash
# 1. 生成带注释的配置（协议密码已随机生成），编辑域名和邮箱
./proxy-gateway init-config > deploy.yaml

# 2. 检查配置与入口规划；加 --show-config 可查看生成的网关配置（Caddy JSON）
./proxy-gateway -c deploy.yaml plan
./proxy-gateway -c deploy.yaml --show-config plan

# 3. 在 Linux 服务器上安装并启动服务
sudo ./proxy-gateway -c deploy.yaml deploy

# 4. 查看运行状态与证书有效期
sudo ./proxy-gateway status

# 5. 再次输出客户端连接 URI（deploy 成功时也会输出）
./proxy-gateway -c deploy.yaml client-config
```

`plan` 只做配置和路由规划，不写文件、不下载程序，也不探测实际端口占用。`deploy` 会检查监听端口、安装程序、生成并校验协议配置和网关配置、写入 unit 和安装清单，再启动（或重载）网关，等待网关把各协议后端启动并稳定运行。

修改 YAML 后重新执行 `deploy` 即可应用配置：网关重载配置，配置没有变化的协议后端沿用原进程、连接不断，只有变化了的协议会重启。仅执行 `restart` 不会重新生成配置。

## 配置

`init-config` 输出的默认配置等价于（`vless-reality`、`tuic`、`ss2022` 以注释形式给出，凭据已生成，取消注释即启用）：

```yaml
domain: example.com

server:
  address: example.com

certificates:
  provider: letsencrypt
  # email: admin@example.com   # 可选

entry:
  https_port: 443
  http_port: 80

users:
  - name: default
    secret: "<随机生成>"

protocols:                  # 列出即启用，不需要的删掉
  hysteria2:
  anytls:

web:
  - name: site
    type: static
```

| 字段 | 含义与默认值 |
| --- | --- |
| `domain` | 必填，主域名和默认网站证书域名 |
| `server.address` | 客户端实际连接地址，默认等于 `domain`，可填 IP；不改变用于 TLS 的 SNI |
| `entry.https_port` / `http_port` | 默认 `443` / `80`，两者必须不同 |
| `protocols` | 以协议名为键，列出的协议即启用，当前可用 `anytls`、`hysteria2`、`vless-reality`、`tuic`、`ss2022`，也可以写简称 `hy2`、`reality`、`ss`（`users[].protocols` 中同样可用）。值可以为空，也可以写该协议的选项（见下） |
| `protocols.<协议>.port` | 公网端口，默认使用 `entry.https_port`；`ss2022` 必填，且不能与入口端口或其他协议的端口相同 |
| `protocols.<协议>.sni` | 默认是主域名下一级的一个常见子域名（如 `api`、`cdn`、`static`），由域名和协议决定，同一部署里各不相同，名字里不含协议名，以免证书透明度日志暴露用途；`vless-reality` 默认 `www.microsoft.com`。TCP 协议的 SNI 必须与主域名及网站 `host` 不同 |
| `users[].name` | 用户名，1–32 个字母、数字、`-`、`_`，不能重复；至少一个用户 |
| `users[].secret` | 至少 16 个字符，不能重复。各协议的密码、UUID、密钥都由它推导，所以新增协议时每个用户自动拥有凭据；更换即作废该用户的全部旧凭据 |
| `users[].traffic_limit` | 可选，每个周期的流量上限（上下行合计），如 `200GiB`、`500GB`；不填不限 |
| `users[].reset_day` | 可选，每月几号（1–28，服务器本地时间）重置周期用量，默认 1 |
| `users[].expire` | 可选，到期日 `YYYY-MM-DD`，当天结束前可用 |
| `users[].protocols` | 可选，该用户可以使用的协议，如 `[anytls, hysteria2]`；不填可用全部协议。只有这些协议的服务端接受该用户，`client-config` 也只输出这些链接 |
| `anytls` 的 `padding_scheme` | 可选，填充方案，多行字符串或字符串列表，每行一条规则；格式同 sing-box anytls inbound |
| `hysteria2` 的 `masquerade_url` | 可选，覆盖默认的内部伪装网站地址 |
| `vless-reality` 的 `private_key` / `short_id` | 必填，`init-config` 会生成；公钥由私钥推导，出现在客户端链接中 |
| `vless-reality` 的 `handshake` | 可选，伪装握手的目标 `host:port`，默认是 `sni` 的 443 端口 |
| `tuic` 的 `congestion_control` | 可选，`bbr`（默认）、`cubic` 或 `new_reno` |
| `ss2022` 的 `method` | 可选，`2022-blake3-aes-128-gcm`（默认）或 `2022-blake3-aes-256-gcm`；多用户（SIP022 EIH）只支持 AES |
| `ss2022` 的 `password` | 必填，服务端密钥：随机密钥的 base64 编码，aes-128 为 16 字节、aes-256 为 32 字节；`init-config` 会生成。每个用户另有由 `secret` 推导的密钥，客户端密码为 `服务端密钥:用户密钥` |

每种协议只能配置一个实例：配置路径和后端进程都按协议名标识。配置中出现未知字段或协议不认识的选项（例如拼错的名字）时直接报错。

### VLESS + Reality

Reality 自己完成 TLS 握手：客户端使用伪装目标网站的 SNI（默认 `www.microsoft.com`），网关按这个 SNI 把连接原样透传给 sing-box，不终结 TLS，也不为它申请证书。认证通过的连接被代理；未通过的连接（包括主动探测）由 sing-box 转给真正的目标网站，探测者拿到的是目标网站的真实证书和内容。

- 伪装目标应选择离服务器近、支持 TLS 1.3 和 HTTP/2 的网站，并且服务器能访问到它；不要用本机网站的域名（规划时会报冲突）。
- 示例配置中 `vless-reality` 是注释掉的，取消注释即可启用；凭据由 `init-config` 生成，重复部署保持不变。

### Shadowsocks 2022

Shadowsocks 没有 TLS 握手，网关无法按 SNI 分流，所以 `ss2022` 独占 `port` 指定的公网端口（TCP 和 UDP）。网关在这个端口上以 `raw` 模式监听：不识别 TLS / QUIC，把全部连接原样转给回环地址上的 sing-box。流量和连接照样计入网关的统计和日志，客户端真实地址记录在网关日志中。需要在防火墙放行该端口的 TCP 和 UDP。

### 证书

| `certificates.provider` | 配置与行为 |
| --- | --- |
| `letsencrypt`（默认） | 使用 Let's Encrypt；`email` 可选，作为 ACME 账号的联系邮箱 |
| `acme` | 自定义 ACME 服务，必须填写 `ca`（ACME directory URL），`email` 可选 |
| `internal` | 使用 Caddy 内部 CA，适合测试；不会自动安装根证书到系统信任库，生成的客户端 URI 带 `insecure=1` |

ACME 配置还支持 `dns_provider` 和 `dns_config`，用 DNS 验证代替 HTTP 验证。程序内置 Cloudflare（Token 需要该域名的 DNS 编辑权限）：

```yaml
certificates:
  provider: letsencrypt
  dns_provider: cloudflare
  dns_config:
    api_token: "<Cloudflare API Token>"
```

使用 DNS 验证时，主域名下一级的协议 SNI 共用一张通配符证书 `*.<domain>`：每张公开签发的证书都会记录在证书透明度日志里，任何人都能查到，用通配符证书后日志里看不出用了哪些子域名。主域名和网站 `host` 仍各自申请证书。其他 DNS 服务商需要在 `cmd/proxy-gateway/main.go` 中加入对应模块的 import 后自行构建。

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

选项统一放在命令前，例如 `./proxy-gateway -n 100 -f logs anytls`。

| 命令 | 用途 | 是否需要 YAML |
| --- | --- | --- |
| `init-config` | 向标准输出写入示例配置 | 否 |
| `plan` | 显示入口、协议、证书和规划冲突 | 是 |
| `deploy` | 安装、更新并启动服务，输出客户端 URI | 是 |
| `client-config [用户]` | 根据当前 YAML 生成客户端 URI，按用户分组；指定用户时只输出该用户的 | 是 |
| `status` | 查看已安装服务状态与证书有效期 | 否，读取安装清单 |
| `version` | 查看当前程序、已安装程序和 sing-box 的版本，检查是否有新版本（需要访问 GitHub） | 否 |
| `logs [协议]` | 不指定时查看整个服务的日志（含网关连接日志和全部后端输出），指定协议名时只看该协议后端的输出 | 否，读取安装清单 |
| `restart [协议]` | 不指定时重启整个服务，指定协议名时只重启该协议的后端进程 | 否，读取安装清单 |
| `uninstall` | 停用并删除记录的 unit，删除整个安装目录 | 否，读取安装清单 |

| 选项 | 默认值 / 用途 |
| --- | --- |
| `-c <路径>` | 配置路径，默认 `deploy.yaml` |
| `--prefix <目录>` | 安装目录，系统模式默认 `/opt/proxy-gateway`，用户模式默认 `~/.local/proxy-gateway`；建议使用独立的绝对路径 |
| `--user` | 使用 `systemctl --user` 和用户级 unit 目录 |
| `--show-config` | `plan` 时额外输出生成的网关配置（Caddy JSON） |
| `-n <行数>` / `-f` | 日志行数（默认 50）/ 持续跟随日志 |

```bash
sudo ./proxy-gateway -n 100 -f logs anytls
sudo ./proxy-gateway logs
sudo ./proxy-gateway restart hysteria2
sudo ./proxy-gateway restart
sudo ./proxy-gateway uninstall
```

运维命令须使用与部署时一致的 `--user` 和 `--prefix`。`client-config` 读取当前 YAML，不核对已运行的配置；修改配置后应先重新部署再分发 URI。

### 用户级部署

在提供可用 systemd 用户实例的 Linux 主机上，可不使用 root 部署。先将 YAML 中的端口改为高位端口，例如 `entry.https_port: 8443`、`entry.http_port: 8080`（以及显式设置的协议端口均使用大于 1024 的端口）。本机测试可同时将 `certificates.provider` 改为 `internal`，避免公网 ACME 验证要求。

```bash
./proxy-gateway --user -c deploy.yaml plan
./proxy-gateway --user -c deploy.yaml deploy
./proxy-gateway --user status
./proxy-gateway --user -f logs
./proxy-gateway --user uninstall
```

用户服务默认随登录会话启停：未开启 linger 时，用户注销后服务会被停止，开机后也不会自动启动。`deploy` 和 `status` 检测到这种情况会给出提示，需由管理员执行一次 `sudo loginctl enable-linger <用户名>`。

高位端口下使用公网 ACME 证书时，仍需保证 CA 的验证流量能到达服务，或配置 DNS 验证。

### 容器部署

镜像 `ghcr.io/jiayx/proxy-gateway`（`edge` 跟随 main 分支，`v*` 为正式版本，支持 amd64 / arm64）包含程序和固定版本的 sing-box。容器启动时执行 `proxy-gateway serve`：读取 `/etc/proxy-gateway/deploy.yaml`，生成配置，在前台运行网关。

```yaml
# compose.yml
services:
  proxy-gateway:
    image: ghcr.io/jiayx/proxy-gateway:edge
    container_name: proxy-gateway
    restart: unless-stopped
    network_mode: host          # 直接监听宿主机端口：客户端真实地址、UDP 性能都与 systemd 部署相同
    environment:
      TZ: Asia/Shanghai         # 流量重置日按这个时区计算
    volumes:
      - ./config:/etc/proxy-gateway:ro   # 目录里放 deploy.yaml
      - data:/opt/proxy-gateway/var      # 证书和用户流量统计
volumes:
  data:
```

```bash
docker compose up -d                                        # 启动
docker logs -f proxy-gateway                                # 日志（含网关连接日志和协议输出）
docker exec proxy-gateway proxy-gateway status              # 状态、用户流量、证书
docker exec proxy-gateway proxy-gateway client-config       # 客户端链接
docker exec proxy-gateway proxy-gateway deploy              # 修改 deploy.yaml 后重载配置，连接不断
docker exec proxy-gateway proxy-gateway restart anytls      # 只重启某个协议
docker exec proxy-gateway proxy-gateway logs anytls         # 某个协议最近的输出
docker compose pull && docker compose up -d                 # 升级镜像（会断开现有连接）
```

- 挂载 `deploy.yaml` 所在的目录，不要只挂载这一个文件：编辑器和 `sed -i` 保存时会换成新文件，单文件挂载仍指向旧文件，容器里看不到修改。
- 使用 host 网络时，要反向代理其他容器里的网站，把那个容器的端口映射到本机回环地址（例如 `ports: ["127.0.0.1:8080:80"]`），在 `web` 中写 `upstream: 127.0.0.1:8080`。
- 静态网站目录需要另外挂载进容器，`root` 写容器内的路径。
- `restart`（不指定协议）和 `uninstall` 在容器里不可用，分别用 `docker restart` 和下面的卸载步骤。

卸载容器部署（在 compose 文件所在目录执行）：

```bash
docker compose down         # 停止并删除容器；数据卷（证书和用户流量统计）保留
```

确定不再需要证书和流量统计时，在上面的命令后加 `-v`，数据卷会一并删除，无法恢复。

## 程序安装与文件布局

`deploy` 把正在执行的 `proxy-gateway` 复制为 `<prefix>/bin/proxy-gateway`，服务运行的就是这份副本；它不会放进 PATH，也不会动系统里已有的 Caddy。已安装的与当前程序相同时不复制；不同时（换了新版本或自己构建的版本）替换后重启服务，重启会断开现有连接；只改配置时网关重载配置，连接不断。升级就是换一个新的 `proxy-gateway` 再执行 `deploy`。

`proxy-gateway version` 显示当前程序的提交、其中的 Caddy 版本和 sing-box 版本，与仓库 `main` 分支比较是否有更新；显示已安装的程序是否与当前程序相同；并检查 sing-box 上游是否有新的正式版。sing-box 的版本固定在程序中，上游发布新版本后需要更新 proxy-gateway 才会升级。

协议程序从各自上游 GitHub Releases 下载，版本和各平台的 sha256 固定在适配器源码中（当前 sing-box `1.14.3`，支持 linux amd64 / arm64），校验不通过不会写入文件。所有协议都使用 sing-box 作为服务端：共用一份二进制，每个协议运行一个独立进程，修改或重启某个协议不影响其他协议的连接。程序按版本保存并通过符号链接使用；重复部署会复用已存在的版本，部署成功后清理 `bin/` 中不再使用的程序和版本。部署主机需能访问 sing-box 的下载地址。

```text
<prefix>/
├── bin/                   # proxy-gateway（服务运行的副本）、协议程序链接及 versions/ 下的版本文件
├── etc/
│   ├── gateway/config.json   # 生成的网关配置（Caddy JSON）
│   ├── hysteria2/config.json # sing-box 配置
│   └── anytls/config.json
├── var/
│   ├── gateway/           # 网关的证书、私钥及 CA 数据
│   ├── admin.sock         # 网关管理接口（Caddy admin API）Unix socket
│   └── xdg/               # 网关其他运行时数据
├── www/                   # 默认网站
└── manifest.json          # unit、协议后端、端口及证书路径的安装清单
```

生成的网关配置和协议配置（含密码）权限为 `0600`。`deploy.yaml` 由使用者保存，不会自动复制到安装目录。

systemd unit 在安装目录之外：系统模式写入 `/etc/systemd/system/`，用户模式写入 `$XDG_CONFIG_HOME/systemd/user/`（未设置时为 `~/.config/systemd/user/`）。只有一个服务 `proxy-gateway.service`。协议后端（sing-box）由网关作为子进程启动和监管：

- 进程退出后自动重启，重启间隔逐步加长（最长 10 秒）；依赖证书的协议等证书文件出现后才启动。
- 子进程输出按行写入网关的日志（带 `backend` 字段），`proxy-gateway logs <协议名>` 只显示该协议的输出。
- 网关重载配置时，命令和配置都没变的后端沿用原进程；网关停止或异常退出时子进程随之退出。
- `status` 显示每个后端的状态、PID、运行时长和重启次数；部署时后端没能就绪会显示它最近的输出。

`uninstall` 根据清单清理 unit，并递归删除整个 `<prefix>`，包括证书和默认网站；自定义前缀应专用于此部署。外部网站目录及存放在前缀之外的 YAML 和你执行的 proxy-gateway 程序不由卸载命令删除。unit 名称固定，使用不同前缀不代表能在同一个 systemd 实例中同时运行多套部署。

## 源码结构与扩展

```text
cmd/proxy-gateway/         程序入口：部署命令交给 internal/cli，其余（run、reload 等）交给 Caddy
internal/cli/              部署和运维命令、选项和输出
gateway/                   网关（Caddy 应用模块 proxy_gateway）：SNI 路由、TLS 终结与透传、统计、用户和后端进程管理
docs/design.md             设计目标、架构和实现计划
internal/config/           YAML 类型、默认值、基础校验和示例
internal/orchestrator/     入口规划、冲突检查、部署、清单和 systemd 管理
internal/entry/caddy/      程序自身的安装和 Caddy JSON 配置生成
internal/protocol/         协议接口、注册表及 anytls / hysteria2 适配器；singbox/ 为共用的 sing-box 安装与配置
pkg/paths/                 安装前缀和系统 / 用户模式路径
pkg/system/                下载、解压、版本安装、文件写入和 systemctl 封装
```

新增协议需实现 `protocol.Adapter` 并在 `internal/protocol/builtin` 注册；经网关转发的协议还要实现 `LoopbackPorter`，声明一个未被占用的固定回环端口；按需实现 `Validator`（规划阶段校验）和 `CertConsumer`（读取证书文件，编排器会等证书签发后再启动）接口。以 sing-box 为服务端的协议可复用 `internal/protocol/singbox` 的安装和配置生成，只需提供 inbound 字段。编排器统一处理入口、证书和服务生命周期；`TransportBoth`（同时监听 TCP 和 UDP）当前仍会被规划器拒绝。
