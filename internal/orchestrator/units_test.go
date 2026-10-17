package orchestrator

import "testing"

func TestExecLine(t *testing.T) {
	got := execLine([]string{"/opt/pd/bin/x", "-p", "${PASSWORD}", "a b", "100%", "$HOME", `q"t`})
	want := `/opt/pd/bin/x -p ${PASSWORD} "a b" 100%% $$HOME "q\"t"`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestEnvFile(t *testing.T) {
	got := string(envFile(map[string]string{"B": `a"b$c` + "`d\\", "A": "x"}))
	want := "A=\"x\"\nB=\"a\\\"b\\$c\\`d\\\\\"\n"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}
