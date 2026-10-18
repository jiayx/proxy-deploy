package system

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

func TestExtractTarGz(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"pkg/README": "doc", "pkg/sing-box": "bin"} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()

	got, err := extractTarGz(buf.Bytes(), "sing-box")
	if err != nil || string(got) != "bin" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := extractTarGz(buf.Bytes(), "missing"); err == nil {
		t.Fatal("missing entry should fail")
	}
}

func TestPruneBinaries(t *testing.T) {
	bin := t.TempDir()
	write := func(rel string) {
		if err := WriteFile(filepath.Join(bin, rel), []byte("x"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(name, target string) {
		if err := os.Symlink(target, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	write("proxy-gateway")
	write("versions/sing-box-1.14.3")
	write("versions/sing-box-1.13.0")
	write("versions/anytls-0.0.13")
	link("sing-box", "versions/sing-box-1.14.3")
	link("anytls", "versions/anytls-0.0.13")
	write("sing-box.tmp")

	removed, err := PruneBinaries(bin, []string{filepath.Join(bin, "proxy-gateway"), filepath.Join(bin, "sing-box")})
	if err != nil {
		t.Fatal(err)
	}
	want := "anytls,sing-box.tmp,versions/anytls-0.0.13,versions/sing-box-1.13.0"
	if got := strings.Join(removed, ","); got != want {
		t.Fatalf("removed:\n got %s\nwant %s", got, want)
	}
	for _, rel := range []string{"proxy-gateway", "sing-box", "versions/sing-box-1.14.3"} {
		if _, err := os.Stat(filepath.Join(bin, rel)); err != nil {
			t.Fatalf("%s should be kept: %v", rel, err)
		}
	}
}

func TestWriteFileChecked(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "config.json")
	if err := WriteFile(dest, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	var checked string
	reject := func(path string) error { checked = path; return errors.New("bad") }
	if err := WriteFileChecked(dest, []byte("new"), 0600, reject); err == nil {
		t.Fatal("check failure should be returned")
	}
	if filepath.Base(checked) != "config.check.json" {
		t.Fatalf("temp file should keep the extension, got %s", checked)
	}
	if data, _ := os.ReadFile(dest); string(data) != "old" {
		t.Fatalf("dest must stay unchanged on failure, got %q", data)
	}
	if _, err := os.Stat(checked); !os.IsNotExist(err) {
		t.Fatal("temp file should be removed on failure")
	}

	if err := WriteFileChecked(dest, []byte("new"), 0600, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(dest); string(data) != "new" {
		t.Fatalf("dest should be replaced, got %q", data)
	}
}
