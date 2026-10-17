package orchestrator

import "testing"

func TestExecLine(t *testing.T) {
	got := execLine([]string{"/opt/pd/bin/x", "a b", "100%", "$HOME", `q"t`})
	want := `/opt/pd/bin/x "a b" 100%% $$HOME "q\"t"`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
