package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	releaseRepo = "zkryakgul/keyshelf"
	// Release locations are fixed in the binary, not read from the environment, so a hostile .envrc
	// cannot point `ks update` at another download.
	defaultReleaseAPI      = "https://api.github.com/repos/" + releaseRepo + "/releases"
	defaultReleaseDownload = "https://github.com/" + releaseRepo + "/releases/download"
	maxArchiveSize         = 100 << 20
)

// updateEnv holds what ks update touches, so tests can replace it.
type updateEnv struct {
	api, download string
	http          *http.Client
	exePath       func() (string, error)
	runCmd        func(name string, args ...string) error
}

func (a *app) updater() updateEnv {
	u := a.update
	if u.api == "" {
		u.api = defaultReleaseAPI
	}
	if u.download == "" {
		u.download = defaultReleaseDownload
	}
	if u.http == nil {
		u.http = &http.Client{Timeout: 2 * time.Minute}
	}
	if u.exePath == nil {
		u.exePath = func() (string, error) {
			p, err := os.Executable()
			if err != nil {
				return "", err
			}
			return filepath.EvalSymlinks(p)
		}
	}
	if u.runCmd == nil {
		u.runCmd = func(name string, args ...string) error {
			return exec.Command(name, args...).Run() // #nosec G204 -- only called with "systemctl" and fixed arguments
		}
	}
	return u
}

// parseVersion turns "v1.2.3" into comparable numbers; ok is false for anything else (e.g. "dev").
func parseVersion(v string) (out [3]int, ok bool) {
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// newer reports whether version a is newer than b.
func newer(a, b string) bool {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	if !okA || !okB {
		return false
	}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}

func (u updateEnv) get(url string, limit int64) ([]byte, error) {
	resp, err := u.http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than expected", url)
	}
	return b, nil
}

func (u updateEnv) latestTag() (string, error) {
	raw, err := u.get(u.api+"/latest", 1<<20)
	if err != nil {
		return "", fmt.Errorf("cannot ask GitHub for the latest release: %w", err)
	}
	var rel struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(raw, &rel); err != nil || rel.Tag == "" {
		return "", errors.New("unexpected answer from the GitHub releases API")
	}
	return rel.Tag, nil
}

// extractKS returns the ks binary from a release archive.
func extractKS(archive []byte, dir string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("the archive has no ks binary")
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && h.Name == dir+"/ks" {
			return io.ReadAll(io.LimitReader(tr, maxArchiveSize))
		}
	}
}

func (a *app) cmdUpdate(args []string) error {
	fs := a.flags("update")
	check := fs.Bool("check", false, "only report whether a newer version exists")
	want := fs.String("version", "", "install this release (e.g. v0.1.1) instead of the latest")
	restart := fs.Bool("restart", false, "restart the keyshelf user service afterwards (it comes back sealed)")
	force := fs.Bool("force", false, "reinstall even if up to date, or replace a development build")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	u := a.updater()
	p := a.printer()

	tag := *want
	if tag == "" {
		var err error
		if tag, err = u.latestTag(); err != nil {
			return err
		}
	}
	if _, ok := parseVersion(tag); !ok {
		return usagef("not a release version: %q", tag)
	}
	if _, ok := parseVersion(version); !ok && !*force {
		return fmt.Errorf("this is a development build (%s); use --force to replace it with %s", version, tag)
	}
	if !*force && *want == "" && !newer(tag, version) {
		p.ok("keyshelf %s is up to date", version)
		return nil
	}
	if *check {
		p.info("keyshelf %s is available (you have %s). Run: ks update", tag, version)
		return nil
	}

	exe, err := u.exePath()
	if err != nil {
		return err
	}
	name := fmt.Sprintf("ks_%s_%s_%s", tag, runtime.GOOS, runtime.GOARCH)
	p.step("Downloading %s.tar.gz", name)
	sums, err := u.get(fmt.Sprintf("%s/%s/SHA256SUMS", u.download, tag), 1<<20)
	if err != nil {
		return err
	}
	wantSum := ""
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && f[1] == name+".tar.gz" {
			wantSum = f[0]
		}
	}
	if wantSum == "" {
		return fmt.Errorf("release %s has no build for %s/%s", tag, runtime.GOOS, runtime.GOARCH)
	}
	archive, err := u.get(fmt.Sprintf("%s/%s/%s.tar.gz", u.download, tag, name), maxArchiveSize)
	if err != nil {
		return err
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != wantSum {
		return errors.New("checksum mismatch: the download does not match SHA256SUMS; nothing was changed")
	}
	p.ok("Checksum verified")
	bin, err := extractKS(archive, name)
	if err != nil {
		return err
	}

	// Write next to the old binary and rename over it: the swap is atomic and a running server keeps
	// its old executable until it restarts.
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".ks-update-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s (%w); re-run the install script instead", filepath.Dir(exe), err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil { // #nosec G302 -- an executable must be executable
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		return err
	}
	p.ok("Updated %s → %s (%s)", version, tag, exe)

	if runtime.GOOS != "linux" || u.runCmd("systemctl", "--user", "is-active", "--quiet", "keyshelf") != nil {
		p.info("If ks serve is running, restart it to use the new version (it comes back sealed).")
		return nil
	}
	if !*restart {
		p.warn("The keyshelf service still runs the old version. When convenient:")
		p.cmd("systemctl --user restart keyshelf && ks unseal")
		return nil
	}
	if err := u.runCmd("systemctl", "--user", "restart", "keyshelf"); err != nil {
		return fmt.Errorf("restarting the service: %w", err)
	}
	p.ok("Service restarted; it is sealed now")
	p.cmd("ks unseal")
	return nil
}
