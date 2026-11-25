package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zkryakgul/keyshelf/internal/server"
	"github.com/zkryakgul/keyshelf/internal/store"
	"github.com/zkryakgul/keyshelf/internal/web"
)

func rnd(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type harness struct {
	update    updateEnv
	t         *testing.T
	dir       string
	url       string
	prompts   []string
	stdin     string
	tty       bool
	execd     []string
	execdEnv  []string
	clipboard []byte
}

func (h *harness) app() (*app, *bytes.Buffer, *bytes.Buffer) {
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	a := &app{
		stdin: strings.NewReader(h.stdin), stdout: out, stderr: errb,
		getenv: func(k string) string {
			if k == "KEYSHELF_URL" {
				return h.url
			}
			return ""
		},
		isTTY: func() bool { return h.tty },
		prompt: func(string) (string, error) {
			if len(h.prompts) == 0 {
				h.t.Fatal("unexpected prompt")
			}
			p := h.prompts[0]
			h.prompts = h.prompts[1:]
			return p, nil
		},
		exec:      func(argv0 string, argv, env []string) error { h.execd, h.execdEnv = argv, env; return nil },
		copy:      func(b []byte) error { h.clipboard = b; return nil },
		update:    h.update,
		configDir: filepath.Join(h.dir, "config"),
		dataDir:   filepath.Join(h.dir, "data"),
	}
	return a, out, errb
}

func (h *harness) ks(args ...string) (string, string, int) {
	h.t.Helper()
	a, out, errb := h.app()
	code := a.run(args)
	return out.String(), errb.String(), code
}

func (h *harness) mustKS(args ...string) string {
	h.t.Helper()
	out, errs, code := h.ks(args...)
	if code != 0 {
		h.t.Fatalf("ks %v: exit %d\n%s%s", args, code, out, errs)
	}
	return out
}

// TestEndToEnd follows SPEC §6: start sealed, unseal, create via CLI, read via web, check the audit
// log, revoke the token, confirm the next call fails.
func TestEndToEnd(t *testing.T) {
	h := &harness{t: t, dir: t.TempDir()}
	pass, pw, secret := "pass-"+rnd(t), "pw-"+rnd(t), "value-"+rnd(t)

	h.prompts = []string{pass, pass, pw, pw}
	out := h.mustKS("init")
	if !strings.Contains(out, "Recovery code") {
		t.Fatalf("init output: %s", out)
	}

	st, err := store.Open(filepath.Join(h.dir, "data", "keyshelf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ts := httptest.NewUnstartedServer(nil)
	srv := server.New(st, server.Options{AllowedHosts: []string{ts.Listener.Addr().String()}, UI: web.Files()})
	ts.Config.Handler = srv.Handler()
	ts.Start()
	defer ts.Close()
	h.url = ts.URL

	if out := h.mustKS("status"); !strings.Contains(out, "sealed") {
		t.Fatalf("must start sealed: %s", out)
	}
	if _, errs, code := h.ks("ls"); code == 0 || !strings.Contains(errs, "no token") {
		t.Fatalf("ls without token: %d %s", code, errs)
	}

	h.prompts = []string{pass}
	h.mustKS("unseal")
	h.prompts = []string{pw}
	h.mustKS("login")
	h.prompts = []string{pw}
	h.mustKS("token", "create", "agent", "--scope", "work:list,read,write", "--save")
	cfgRaw, _ := os.ReadFile(filepath.Join(h.dir, "config", "config.json"))
	if fi, _ := os.Stat(filepath.Join(h.dir, "config", "config.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %o", fi.Mode().Perm())
	}

	// Create via CLI, value from a pipe.
	h.stdin = secret + "\n"
	h.mustKS("put", "work/acme/db#password", "--stdin", "--url", "https://db.example.test", "--username", "admin")
	h.stdin = ""
	h.mustKS("gen", "work/acme/db#api", "--length", "40")

	// get refuses to print by default, and never printed the value anywhere so far.
	out, errs, code := h.ks("get", "work/acme/db")
	if code != 2 || strings.Contains(out+errs, secret) {
		t.Fatalf("get without sink: %d", code)
	}
	file := filepath.Join(h.dir, "out", "db.pass")
	h.mustKS("get", "work/acme/db#password", "--to-file", file)
	got, _ := os.ReadFile(file)
	if string(got) != secret {
		t.Fatal("to-file value differs")
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Fatalf("to-file mode %o", fi.Mode().Perm())
	}
	h.mustKS("get", "work/acme/db", "--copy")
	if string(h.clipboard) != secret {
		t.Fatal("copy")
	}
	if out := h.mustKS("get", "work/acme/db", "--reveal"); strings.TrimSpace(out) != secret {
		t.Fatal("reveal")
	}
	ls := h.mustKS("ls", "-r")
	if !strings.Contains(ls, "work/acme/db") || !strings.Contains(ls, "api,password") || strings.Contains(ls, secret) {
		t.Fatalf("ls: %s", ls)
	}
	h.mustKS("run", "--env", "DB_PASS=work/acme/db#password", "--", "env")
	if len(h.execd) != 1 || h.execd[0] != "env" || !containsEnv(h.execdEnv, "DB_PASS="+secret) {
		t.Fatalf("run: %v", h.execd)
	}
	if _, _, code := h.ks("put", "home/x", "--stdin"); code != 1 {
		t.Fatalf("put outside scope must fail: %d", code)
	}

	// Secret notes survive a metadata change through the CLI.
	notes := "notes-" + rnd(t)
	if _, err := st.GetEntry("work/acme/db"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEntry(store.EntryInput{Ref: "work/acme/db", Notes: notes, SecretNotes: true, URL: "https://db.example.test"}, "owner"); err != nil {
		t.Fatal(err)
	}
	h.mustKS("put", "work/acme/db", "--username", "root")
	if v, err := st.GetField("work/acme/db", store.NotesField); err != nil || string(v) != notes {
		t.Fatalf("secret notes lost: %v", err)
	}

	// Read via the web UI: cookie login, then a value read with the cookie.
	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar}
	body, _ := json.Marshal(map[string]any{"password": pw, "cookie": true})
	resp, err := web.Post(ts.URL+"/api/v1/login", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("web login: %v %v", err, resp.Status)
	}
	resp.Body.Close()
	resp, err = web.Get(ts.URL + "/api/v1/values/work/acme/db?field=password")
	if err != nil {
		t.Fatal(err)
	}
	v, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(v) != secret {
		t.Fatalf("web read: %s", resp.Status)
	}
	resp, _ = web.Get(ts.URL + "/")
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "keyshelf") || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatal("web UI not served with its CSP")
	}

	// Audit: the CLI write and the token read are there, with no value.
	audit := h.mustKS("audit", "work/acme/db", "--limit", "100")
	seen := map[string]bool{}
	for _, line := range strings.Split(audit, "\n") {
		if f := strings.Fields(line); len(f) >= 4 {
			seen[f[2]+" "+f[3]] = true
		}
	}
	for _, want := range []string{"token:agent value.write", "token:agent value.read", "owner value.read"} {
		if !seen[want] {
			t.Fatalf("audit lacks %q:\n%s", want, audit)
		}
	}
	if strings.Contains(audit, secret) {
		t.Fatal("audit contains the value")
	}
	if err := st.VerifyAudit(); err != nil {
		t.Fatal(err)
	}

	// Revoke the token; the next call fails.
	toks := h.mustKS("token", "ls")
	if !strings.Contains(toks, "agent") || strings.Contains(toks, string(cfgRaw)) {
		t.Fatalf("token ls: %s", toks)
	}
	id := strings.Fields(strings.Split(toks, "\n")[1])[0]
	h.mustKS("token", "revoke", id)
	if _, errs, code := h.ks("get", "work/acme/db", "--to-file", file+"2"); code != 1 || !strings.Contains(errs, "401") {
		t.Fatalf("revoked token: %d %s", code, errs)
	}

	// Seal; reads fail with the sealed hint; logout removes the session.
	if out := h.mustKS("audit", "--verify"); !strings.Contains(out, "intact") {
		t.Fatalf("audit verify: %s", out)
	}
	h.mustKS("seal")
	if _, errs, _ := h.ks("ls", "--owner"); !strings.Contains(errs, "sealed") {
		t.Fatalf("sealed hint: %s", errs)
	}
	h.mustKS("logout")
	if _, err := os.Stat(filepath.Join(h.dir, "config", "session.json")); !os.IsNotExist(err) {
		t.Fatal("session file left behind")
	}

	// Backup of the live database.
	dest := filepath.Join(h.dir, "backup.db")
	h.mustKS("backup", dest)
	raw, _ := os.ReadFile(dest)
	if len(raw) == 0 || bytes.Contains(raw, []byte(secret)) {
		t.Fatal("backup")
	}
}

func containsEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

func TestInitRefusesSamePassphraseAndPassword(t *testing.T) {
	h := &harness{t: t, dir: t.TempDir()}
	same := "same-" + rnd(t)
	h.prompts = []string{same, same, same, same}
	if _, errs, code := h.ks("init"); code != 1 || !strings.Contains(errs, "differ") {
		t.Fatalf("%d %s", code, errs)
	}
}

func TestParseScope(t *testing.T) {
	s, err := parseScope("work/acme:list,read")
	if err != nil || s.Folder != "work/acme" || len(s.Perms) != 2 {
		t.Fatal(s, err)
	}
	if s, err := parseScope(":list"); err != nil || s.Folder != "" {
		t.Fatal(s, err)
	}
	if _, err := parseScope("work"); err == nil {
		t.Fatal("scope without perms accepted")
	}
}

func TestGenerate(t *testing.T) {
	v, err := generate(64, true)
	if err != nil || len(v) != 64 || strings.Trim(string(v), alnum) != "" {
		t.Fatal("alnum generation")
	}
	if _, err := generate(4, false); err == nil {
		t.Fatal("too short accepted")
	}
	a, _ := generate(32, false)
	b, _ := generate(32, false)
	if bytes.Equal(a, b) {
		t.Fatal("repeats")
	}
}

func TestChildEnv(t *testing.T) {
	base := []string{"PATH=/bin", "KEYSHELF_TOKEN=ks_x", "KEYSHELF_URL=http://127.0.0.1:1", "DB_PASS=old", "HOME=/h"}
	env := childEnv(base, map[string]string{"DB_PASS": "new"}, []string{"DB_PASS"})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "KEYSHELF_") || strings.Contains(joined, "DB_PASS=old") || !strings.Contains(joined, "DB_PASS=new") || !strings.Contains(joined, "PATH=/bin") {
		t.Fatalf("env: %v", env)
	}
}

func TestCheckServerURL(t *testing.T) {
	for u, ok := range map[string]bool{
		"http://127.0.0.1:7733": true, "http://localhost:7733": true, "http://[::1]:7733": true,
		"https://keys.example.org": true, "http://keys.example.org": false, "http://10.0.0.5:7733": false, "ftp://x": false, "": false,
	} {
		if err := checkServerURL(u); (err == nil) != ok {
			t.Errorf("%q: %v", u, err)
		}
	}
}

// The owner-only socket: listenSocket makes it 0600 in a 0700 directory, and the CLI prefers it.
func TestLocalSocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	h := &harness{t: t, dir: t.TempDir()}
	pass, pw := "pass-"+rnd(t), "pw-"+rnd(t)
	h.prompts = []string{pass, pass, pw, pw}
	h.mustKS("init")
	st, err := store.Open(filepath.Join(h.dir, "data", "keyshelf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sock := filepath.Join(dir, "ks.sock")
	l, err := listenSocket(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(st, server.Options{AllowedHosts: []string{"none"}})
	hs := &http.Server{Handler: srv.LocalHandler()}
	go hs.Serve(l)
	defer hs.Close()
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %o", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode %o", fi.Mode().Perm())
	}
	if _, err := listenSocket(sock); err == nil {
		t.Fatal("second listener on a live socket")
	}
	a, out, errb := h.app()
	a.getenv = func(k string) string {
		if k == "KEYSHELF_SOCKET" {
			return sock
		}
		return ""
	}
	h.prompts = []string{pass}
	if code := a.run([]string{"unseal"}); code != 0 {
		t.Fatalf("unseal over socket: %s%s", out, errb)
	}
	if st.Sealed() {
		t.Fatal("still sealed")
	}
}
