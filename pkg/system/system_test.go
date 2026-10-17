package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadChecksum(t *testing.T) {
	body := []byte("binary")
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			w.Write([]byte(good + "  bin\n"))
			return
		}
		w.Write(body)
	}))
	defer srv.Close()
	ctx := context.Background()
	dir := t.TempDir()

	got, err := FetchChecksum(ctx, srv.URL+"/bin.sha256")
	if err != nil || got != good {
		t.Fatalf("FetchChecksum = %q, %v", got, err)
	}

	bad := filepath.Join(dir, "bad")
	if err := Download(ctx, srv.URL+"/bin", strings.Repeat("0", 64), bad, 0755); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("want checksum error, got %v", err)
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("file with wrong checksum should not be written")
	}

	ok := filepath.Join(dir, "ok")
	if err := Download(ctx, srv.URL+"/bin", good, ok, 0755); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(ok); string(data) != "binary" {
		t.Fatalf("unexpected content %q", data)
	}
}

func TestInstallVersioned(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "bin", "tool")
	fetches := 0
	fetch := func(dest string) error { fetches++; return WriteFile(dest, []byte("v1"), 0755) }
	v1 := filepath.Join(dir, "bin", "versions", "tool-1")
	for i := 0; i < 2; i++ {
		if err := InstallVersioned(v1, link, fetch); err != nil {
			t.Fatal(err)
		}
	}
	if fetches != 1 {
		t.Fatalf("existing version should be reused, fetched %d times", fetches)
	}
	if target, _ := os.Readlink(link); target != "versions/tool-1" {
		t.Fatalf("link should be relative, got %s", target)
	}
}
