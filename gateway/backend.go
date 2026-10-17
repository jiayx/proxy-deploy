package gateway

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// 后端进程监管：网关启动并监管协议服务端进程（sing-box），systemd 只需管理 Caddy。
//
// 进程表按后端名放在进程级。Caddy 重载配置时先启动新配置、再停止旧配置，
// 命令和 revision 都没变的后端被新配置沿用（引用计数），进程不重启、连接不断；
// 变化了的后端先停掉旧进程（释放端口）再启动新进程。Caddy 退出时进程随之停止。

// Backend 是一个由网关监管的后端进程
type Backend struct {
	// Command 第一个元素是可执行文件的绝对路径
	Command []string          `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
	// RequireFiles 中的文件都存在后才启动，例如协议读取的证书（首次部署时证书尚未签发）
	RequireFiles []string `json:"require_files,omitempty"`
	// Revision 标识配置版本（通常是配置文件内容的哈希）；变化时重启进程
	Revision string `json:"revision,omitempty"`
}

func (b *Backend) key() string {
	data, _ := json.Marshal(b)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

const (
	backendTailLines  = 30
	backendMinBackoff = time.Second
	backendMaxBackoff = 10 * time.Second
	backendStableRun  = 10 * time.Second // 运行超过这么久后退出，重启间隔重置
	backendStopGrace  = 10 * time.Second
)

// 后端进程状态
const (
	StateWaiting = "waiting" // 等待 RequireFiles
	StateRunning = "running" //
	StateBackoff = "backoff" // 退出后等待重启
	StateStopped = "stopped" //
)

type process struct {
	name   string
	key    string
	cfg    Backend
	logger *zap.Logger
	refs   int // 由 procs.mu 保护

	mu       sync.Mutex
	state    string
	cmd      *exec.Cmd
	started  time.Time
	restarts int
	lastExit string
	tail     []string

	restart chan struct{}
	stopCh  chan struct{}
	done    chan struct{}
}

var procs = struct {
	sync.Mutex
	m map[string]*process
}{m: map[string]*process{}}

// acquireBackend 返回名为 name 的运行中的进程，配置相同则沿用，否则替换
func acquireBackend(name string, cfg *Backend, logger *zap.Logger) *process {
	key := cfg.key()
	procs.Lock()
	defer procs.Unlock()
	if p := procs.m[name]; p != nil {
		if p.key == key {
			p.refs++
			return p
		}
		p.logger.Info("configuration changed, restarting")
		p.stop()
	}
	p := &process{
		name: name, key: key, cfg: *cfg, refs: 1,
		logger:  logger.With(zap.String("backend", name)),
		restart: make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
	}
	procs.m[name] = p
	go p.run()
	return p
}

// releaseBackend 释放引用；没有配置再使用时停止进程
func releaseBackend(p *process) {
	procs.Lock()
	defer procs.Unlock()
	if procs.m[p.name] != p {
		return // 已被新配置替换
	}
	if p.refs--; p.refs == 0 {
		delete(procs.m, p.name)
		p.stop()
	}
}

func (p *process) setState(s string) {
	p.mu.Lock()
	p.state = s
	p.mu.Unlock()
}

func (p *process) run() {
	// Pdeathsig 跟随创建子进程的系统线程而不是整个进程：固定在一个线程上，
	// 避免 Go 运行时回收线程时误杀子进程。这个 goroutine 结束时线程随之退出
	runtime.LockOSThread()
	defer close(p.done)
	backoff := backendMinBackoff
	for {
		if !p.waitFiles() {
			return
		}
		start := time.Now()
		err := p.runOnce()
		ran := time.Since(start)

		select {
		case <-p.stopCh:
			return
		default:
		}
		p.mu.Lock()
		p.restarts++
		p.lastExit = exitReason(err)
		p.state = StateBackoff
		p.mu.Unlock()
		if ran >= backendStableRun {
			backoff = backendMinBackoff
		}
		p.logger.Warn("process exited", zap.String("reason", exitReason(err)), zap.Duration("ran", ran), zap.Duration("restart_in", backoff))
		select {
		case <-p.stopCh:
			return
		case <-p.restart:
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, backendMaxBackoff)
	}
}

// waitFiles 等待 RequireFiles 全部存在；返回 false 表示等待期间被停止
func (p *process) waitFiles() bool {
	for {
		missing := ""
		for _, f := range p.cfg.RequireFiles {
			if _, err := os.Stat(f); err != nil {
				missing = f
				break
			}
		}
		if missing == "" {
			return true
		}
		p.setState(StateWaiting)
		select {
		case <-p.stopCh:
			return false
		case <-time.After(time.Second):
		}
	}
}

// runOnce 启动进程并等待它退出；收到停止信号时先 SIGTERM，超时后 SIGKILL
func (p *process) runOnce() error {
	cmd := exec.Command(p.cfg.Command[0], p.cfg.Command[1:]...)
	cmd.Env = os.Environ()
	for k, v := range p.cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.SysProcAttr = backendSysProcAttr()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout // 合并输出
	if err := cmd.Start(); err != nil {
		return err
	}
	p.mu.Lock()
	p.cmd, p.started, p.state = cmd, time.Now(), StateRunning
	p.mu.Unlock()
	p.logger.Info("process started", zap.Int("pid", cmd.Process.Pid))

	logged := make(chan struct{})
	go func() { p.pipeLogs(stdout); close(logged) }()

	exited := make(chan error, 1)
	go func() { <-logged; exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		return err
	case <-p.restart:
		p.terminate(cmd, exited)
		return errors.New("restart requested")
	case <-p.stopCh:
		p.terminate(cmd, exited)
		return nil
	}
}

func (p *process) terminate(cmd *exec.Cmd, exited <-chan error) {
	_ = cmd.Process.Signal(terminateSignal)
	select {
	case <-exited:
	case <-time.After(backendStopGrace):
		_ = cmd.Process.Kill()
		<-exited
	}
}

// pipeLogs 把进程输出按行写入日志，并保留最后几行供管理接口查看
func (p *process) pipeLogs(r io.Reader) {
	acc := logAccounting{backend: p.name, ports: map[string]int{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		p.mu.Lock()
		p.tail = append(p.tail, line)
		if len(p.tail) > backendTailLines {
			p.tail = p.tail[len(p.tail)-backendTailLines:]
		}
		p.mu.Unlock()
		if ce := p.logger.Check(lineLevel(line), line); ce != nil {
			ce.Write()
		}
		acc.line(line)
	}
}

// lineLevel 按 sing-box 日志前缀（INFO[...] / WARN[...] / ERROR[...] / FATAL[...]）映射日志级别
func lineLevel(line string) zapcore.Level {
	switch {
	case strings.HasPrefix(line, "ERROR"), strings.HasPrefix(line, "FATAL"), strings.HasPrefix(line, "PANIC"):
		return zapcore.ErrorLevel
	case strings.HasPrefix(line, "WARN"):
		return zapcore.WarnLevel
	case strings.HasPrefix(line, "DEBUG"), strings.HasPrefix(line, "TRACE"):
		return zapcore.DebugLevel
	}
	return zapcore.InfoLevel
}

func exitReason(err error) string {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return "exited"
	case errors.As(err, &ee):
		return ee.ProcessState.String()
	}
	return err.Error()
}

// stop 停止进程并等待监管循环结束；调用方持有 procs.mu
func (p *process) stop() {
	close(p.stopCh)
	<-p.done
	p.setState(StateStopped)
	p.logger.Info("process stopped")
}

// requestRestart 立即重启进程（管理接口使用）
func (p *process) requestRestart() {
	select {
	case p.restart <- struct{}{}:
	default:
	}
}

// BackendStatus 是管理接口返回的后端状态
type BackendStatus struct {
	Name     string   `json:"name"`
	State    string   `json:"state"`
	PID      int      `json:"pid,omitempty"`
	Uptime   float64  `json:"uptime_seconds,omitempty"`
	Restarts int      `json:"restarts"`
	LastExit string   `json:"last_exit,omitempty"`
	Tail     []string `json:"tail,omitempty"`
}

func backendStatuses() []BackendStatus {
	procs.Lock()
	list := make([]*process, 0, len(procs.m))
	for _, p := range procs.m {
		list = append(list, p)
	}
	procs.Unlock()
	out := make([]BackendStatus, 0, len(list))
	for _, p := range list {
		p.mu.Lock()
		st := BackendStatus{Name: p.name, State: p.state, Restarts: p.restarts, LastExit: p.lastExit, Tail: append([]string(nil), p.tail...)}
		if p.state == StateRunning && p.cmd != nil {
			st.PID = p.cmd.Process.Pid
			st.Uptime = time.Since(p.started).Seconds()
		}
		p.mu.Unlock()
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func restartBackend(name string) error {
	procs.Lock()
	p := procs.m[name]
	procs.Unlock()
	if p == nil {
		return fmt.Errorf("unknown backend %q", name)
	}
	p.requestRestart()
	return nil
}
