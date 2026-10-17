package gateway

import "syscall"

var terminateSignal = syscall.SIGTERM

// backendSysProcAttr 让后端进程在 Caddy 意外退出时收到 SIGTERM，不会成为孤儿进程
func backendSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
