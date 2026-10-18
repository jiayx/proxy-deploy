# syntax=docker/dockerfile:1
# proxy-gateway 容器镜像：同一个程序既是网关也是运维命令，sing-box 也打包在镜像里。
# 用法见 README 的“容器部署”；镜像由 .github/workflows/ci.yml 构建并推送到 ghcr.io/jiayx/proxy-gateway。

FROM --platform=$BUILDPLATFORM golang:1.27.1 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# 保留 .git，让 go build 记录提交信息（proxy-gateway version 用到）
RUN git config --global --add safe.directory /src && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/proxy-gateway ./cmd/proxy-gateway

# sing-box 的官方构建链接 glibc，所以用 Debian 而不是 Alpine
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/proxy-gateway /usr/local/bin/proxy-gateway
# 下载固定版本的 sing-box 到 /opt/proxy-gateway/bin（版本和校验和在程序里）
RUN proxy-gateway fetch
ENV PROXY_GATEWAY_CONTAINER=1
# 默认读取 /etc/proxy-gateway/deploy.yaml；证书和流量统计在 /opt/proxy-gateway/var，应挂载数据卷
WORKDIR /etc/proxy-gateway
VOLUME /opt/proxy-gateway/var
ENTRYPOINT ["proxy-gateway"]
CMD ["serve"]
