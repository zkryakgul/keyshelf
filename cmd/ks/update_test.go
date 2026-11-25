package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fakeRelease(t *testing.T, tag string, bin []byte, corrupt bool) *httptest.Server {
	t.Helper()
	name := fmt.Sprintf("ks_%s_%s_%s", tag, runtime.GOOS, runtime.GOARCH)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: name + "/ks", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(bin))})
	tw.Write(bin)
	tw.Close()
	zw.Close()
	archive := buf.Bytes()
	sum := sha256.Sum256(archive)
	if corrupt {
		sum[0] ^= 0xff
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":%q}`, tag)
	})
	mux.HandleFunc("/dl/"+tag+"/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s.tar.gz\n%s  other.tar.gz\n", hex.EncodeToString(sum[:]), name, strings.Repeat("0", 64))
	})
	mux.HandleFunc("/dl/"+tag+"/"+name+".tar.gz", func(w http.ResponseWriter, r *http.Request) { w.Write(archive) })
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func updateHarness(t *testing.T, ts *httptest.Server) (*harness, string, *[]string) {
	h := &harness{t: t, dir: t.TempDir()}
	exe := filepath.Join(h.dir, "bin", "ks")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, []byte("old binary"), 0o755)
	var ran []string
	h.update = updateEnv{
		api: ts.URL + "/api", download: ts.URL + "/dl", http: ts.Client(),
		exePath: func() (string, error) { return exe, nil },
		runCmd: func(name string, args ...string) error {
			ran = append(ran, name+" "+strings.Join(args, " "))
			return nil // pretend the service is active
		},
	}
	return h, exe, &ran
}

func withVersion(t *testing.T, v string) {
	old := version
	version = v
	t.Cleanup(func() { version = old })
}

func TestUpdate(t *testing.T) {
	withVersion(t, "v0.1.0")
	newBin := []byte("new binary " + rnd(t))
	h, exe, ran := updateHarness(t, fakeRelease(t, "v0.2.0", newBin, false))

	if out := h.mustKS("update", "--check"); !strings.Contains(out, "v0.2.0 is available") {
		t.Fatalf("check: %s", out)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Fatal("--check must not change anything")
	}
	out := h.mustKS("update")
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, newBin) {
		t.Fatalf("binary not replaced: %s", out)
	}
	if fi, _ := os.Stat(exe); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if !strings.Contains(out, "v0.1.0 → v0.2.0") || !strings.Contains(out, "systemctl --user restart keyshelf") {
		t.Fatalf("output: %s", out)
	}
	for _, c := range *ran {
		if strings.Contains(c, "restart") {
			t.Fatal("restarted without --restart")
		}
	}
	h.mustKS("update", "--restart", "--force")
	if last := (*ran)[len(*ran)-1]; last != "systemctl --user restart keyshelf" {
		t.Fatalf("restart: %v", *ran)
	}
	entries, _ := os.ReadDir(filepath.Dir(exe))
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

func TestUpdateRefusesBadChecksum(t *testing.T) {
	withVersion(t, "v0.1.0")
	h, exe, _ := updateHarness(t, fakeRelease(t, "v0.2.0", []byte("evil"), true))
	_, errs, code := h.ks("update")
	if code != 1 || !strings.Contains(errs, "checksum mismatch") {
		t.Fatalf("%d %s", code, errs)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Fatal("binary changed despite a bad checksum")
	}
}

func TestUpdateUpToDateAndDev(t *testing.T) {
	withVersion(t, "v0.2.0")
	h, exe, _ := updateHarness(t, fakeRelease(t, "v0.2.0", []byte("same"), false))
	if out := h.mustKS("update"); !strings.Contains(out, "up to date") {
		t.Fatalf("up to date: %s", out)
	}
	withVersion(t, "dev")
	if _, errs, code := h.ks("update"); code != 1 || !strings.Contains(errs, "development build") {
		t.Fatalf("dev: %d %s", code, errs)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Fatal("dev build replaced without --force")
	}
}

func TestVersionOrder(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.1.1", "v0.1.0", true}, {"v0.10.0", "v0.9.9", true}, {"v1.0.0", "v0.99.99", true},
		{"v0.1.0", "v0.1.0", false}, {"v0.1.0", "v0.2.0", false}, {"v0.2.0", "dev", false}, {"x", "v0.1.0", false},
	}
	for _, c := range cases {
		if got := newer(c.a, c.b); got != c.want {
			t.Errorf("newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
