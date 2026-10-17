package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func statusOf(t *testing.T, name string) BackendStatus {
	t.Helper()
	for _, st := range backendStatuses() {
		if st.Name == name {
			return st
		}
	}
	return BackendStatus{State: StateStopped}
}

func waitState(t *testing.T, name string, cond func(BackendStatus) bool) BackendStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := statusOf(t, name); cond(st) {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("backend %s: condition not met, last status %+v", name, statusOf(t, name))
	return BackendStatus{}
}

func sleeper(revision string) *Backend {
	return &Backend{Command: []string{"/bin/sh", "-c", "echo started; exec sleep 60"}, Revision: revision}
}

func TestBackendReuseAcrossReload(t *testing.T) {
	name := t.Name()
	first := acquireBackend(name, sleeper("1"), zap.NewNop())
	st := waitState(t, name, func(s BackendStatus) bool { return s.State == StateRunning && slices.Contains(s.Tail, "started") })
	pid := st.PID

	// 重载：新配置先启动（同样的配置），旧配置再停止
	second := acquireBackend(name, sleeper("1"), zap.NewNop())
	releaseBackend(first)
	if second != first || statusOf(t, name).PID != pid {
		t.Fatal("unchanged backend should keep its process across reloads")
	}

	// 配置变化：替换为新进程
	third := acquireBackend(name, sleeper("2"), zap.NewNop())
	releaseBackend(second) // 旧配置停止时不能影响新进程
	st = waitState(t, name, func(s BackendStatus) bool { return s.State == StateRunning && s.PID != pid })

	releaseBackend(third)
	if got := statusOf(t, name).State; got != StateStopped {
		t.Fatalf("backend should stop when no config uses it, got %s", got)
	}
}

func TestBackendRestartsAfterExit(t *testing.T) {
	name := t.Name()
	p := acquireBackend(name, &Backend{Command: []string{"/bin/sh", "-c", "echo boom; exit 3"}}, zap.NewNop())
	defer releaseBackend(p)
	st := waitState(t, name, func(s BackendStatus) bool { return s.Restarts >= 2 })
	if st.LastExit != "exit status 3" || !slices.Contains(st.Tail, "boom") {
		t.Fatalf("unexpected status %+v", st)
	}
}

func TestBackendWaitsForRequiredFiles(t *testing.T) {
	name := t.Name()
	cert := filepath.Join(t.TempDir(), "cert.pem")
	b := sleeper("1")
	b.RequireFiles = []string{cert}
	p := acquireBackend(name, b, zap.NewNop())
	defer releaseBackend(p)

	waitState(t, name, func(s BackendStatus) bool { return s.State == StateWaiting })
	os.WriteFile(cert, []byte("x"), 0600)
	waitState(t, name, func(s BackendStatus) bool { return s.State == StateRunning })
}

func TestBackendRestartRequest(t *testing.T) {
	name := t.Name()
	p := acquireBackend(name, sleeper("1"), zap.NewNop())
	defer releaseBackend(p)
	pid := waitState(t, name, func(s BackendStatus) bool { return s.State == StateRunning }).PID
	if err := restartBackend(name); err != nil {
		t.Fatal(err)
	}
	waitState(t, name, func(s BackendStatus) bool { return s.State == StateRunning && s.PID != pid })
	if err := restartBackend("missing"); err == nil {
		t.Fatal("restarting an unknown backend should fail")
	}
}

func TestLineLevel(t *testing.T) {
	for line, want := range map[string]zapcore.Level{
		"INFO[0005] inbound connection": zapcore.InfoLevel,
		"WARN[0001] something":          zapcore.WarnLevel,
		"ERROR[0007] failed":            zapcore.ErrorLevel,
		"FATAL[0000] decode config":     zapcore.ErrorLevel,
		"plain output":                  zapcore.InfoLevel,
	} {
		if got := lineLevel(line); got != want {
			t.Errorf("%q: got %v, want %v", line, got, want)
		}
	}
}
