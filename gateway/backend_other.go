//go:build !linux

package gateway

import (
	"os"
	"syscall"
)

var terminateSignal os.Signal = syscall.SIGTERM

func backendSysProcAttr() *syscall.SysProcAttr { return nil }
