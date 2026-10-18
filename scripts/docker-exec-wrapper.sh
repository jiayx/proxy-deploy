#!/bin/sh
# 容器部署时在宿主机上的小工具：把命令转给容器里的 proxy-gateway，
# 装成 /usr/local/bin/proxy-gateway 后可以直接执行 proxy-gateway status 等命令。
if [ -t 0 ] && [ -t 1 ]; then
	exec docker exec -it proxy-gateway proxy-gateway "$@"
fi
exec docker exec -i proxy-gateway proxy-gateway "$@"
