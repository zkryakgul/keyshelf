package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zkryakgul/keyshelf/internal/store"
	"github.com/zkryakgul/keyshelf/internal/totp"
)

const host = "127.0.0.1:7733"

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type env struct {
	t                    *testing.T
	st                   *store.Store
	srv                  *Server
	h                    http.Handler
	passphrase, password string
	secret               string // value of work/acme/db#password
	owner                string // owner session
	inScope              string // list/read/write on work
	outScope             string // list/read/write on other only
	rootAgent            string // list/read/write on everything, but not owner
}

func newEnv(t *testing.T, opts Options) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ks.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, passphrase: "pp-" + randHex(t), password: "pw-" + randHex(t), secret: "s-" + randHex(t)}
	if _, err := st.Init([]byte(e.passphrase)); err != nil {
		t.Fatal(err)
	}
	if err := st.SetOwnerPassword([]byte(e.password)); err != nil {
		t.Fatal(err)
	}
	if err := st.SetField("work/acme/db", "password", []byte(e.secret), "owner"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetField("other/thing", "token", []byte("o-"+randHex(t)), "owner"); err != nil {
		t.Fatal(err)
	}
	rw := []string{store.PermList, store.PermRead, store.PermWrite}
	mk := func(name, folder string) string {
		s, _, err := st.CreateAgentToken(name, []store.Scope{{Folder: folder, Perms: rw}}, 0)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	e.inScope, e.outScope, e.rootAgent = mk("in", "work"), mk("out", "other"), mk("root", "")
	e.owner, _, err = st.CreateOwnerSession(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if opts.AllowedHosts == nil {
		opts.AllowedHosts = []string{host, "localhost:7733"}
	}
	e.srv = New(st, opts)
	e.h = e.srv.Handler()
	return e
}

func (e *env) do(method, url, token string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var r io.Reader
	ctype := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		r, ctype = bytes.NewReader(b), "application/octet-stream"
	default:
		raw, _ := json.Marshal(b)
		r, ctype = bytes.NewReader(raw), "application/json"
	}
	req := httptest.NewRequest(method, url, r)
	req.Host = host
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

// TestEveryRouteRefusesOutOfScopeTokens is the permission test CLAUDE.md requires: every route,
// called with a token that has no rights on the target, must refuse or filter. A route added to the
// table without a case here fails the test.
func TestEveryRouteRefusesOutOfScopeTokens(t *testing.T) {
	e := newEnv(t, Options{})
	type tc struct {
		method, url string
		body        any
		token       string
		want        int
		notContain  string // for filtering routes: must not leak this
	}
	entry := store.EntryInput{Kind: "login", Username: "x"}
	cases := map[string][]tc{
		"GET /api/v1/folders": {{"GET", "/api/v1/folders", nil, e.outScope, 200, "work"}},
		"GET /api/v1/entries": {
			{"GET", "/api/v1/entries?folder=work", nil, e.outScope, 403, ""},
			{"GET", "/api/v1/entries?folder=work/acme&recursive=1", nil, e.outScope, 403, ""},
			{"GET", "/api/v1/entries?recursive=1", nil, e.outScope, 200, "work"},
			{"GET", "/api/v1/entries?q=db", nil, e.outScope, 200, "work"},
		},
		"GET /api/v1/entries/{path...}":    {{"GET", "/api/v1/entries/work/acme/db", nil, e.outScope, 403, ""}, {"GET", "/api/v1/entries/work/acme/missing", nil, e.outScope, 403, ""}},
		"PUT /api/v1/entries/{path...}":    {{"PUT", "/api/v1/entries/work/acme/db", entry, e.outScope, 403, ""}, {"PUT", "/api/v1/entries/work/new", entry, e.outScope, 403, ""}},
		"DELETE /api/v1/entries/{path...}": {{"DELETE", "/api/v1/entries/work/acme/db", nil, e.outScope, 403, ""}},
		"GET /api/v1/values/{path...}":     {{"GET", "/api/v1/values/work/acme/db?field=password", nil, e.outScope, 403, ""}},
		"PUT /api/v1/values/{path...}":     {{"PUT", "/api/v1/values/work/acme/db?field=password", []byte("overwrite"), e.outScope, 403, ""}},
		"DELETE /api/v1/values/{path...}":  {{"DELETE", "/api/v1/values/work/acme/db?field=password", nil, e.outScope, 403, ""}},
		// Owner-only routes: an agent token with rights on the whole shelf is still not the owner.
		"GET /api/v1/session":        {{"GET", "/api/v1/session", nil, e.rootAgent, 403, ""}},
		"POST /api/v1/seal":          {{"POST", "/api/v1/seal", nil, e.rootAgent, 403, ""}},
		"GET /api/v1/tokens":         {{"GET", "/api/v1/tokens", nil, e.rootAgent, 403, ""}},
		"POST /api/v1/tokens":        {{"POST", "/api/v1/tokens", map[string]any{"name": "x", "scopes": []store.Scope{{Folder: "", Perms: []string{"read"}}}}, e.rootAgent, 403, ""}},
		"DELETE /api/v1/tokens/{id}": {{"DELETE", "/api/v1/tokens/1", nil, e.rootAgent, 403, ""}},
		"GET /api/v1/audit":          {{"GET", "/api/v1/audit", nil, e.rootAgent, 403, ""}},
		"POST /api/v1/passphrase":    {{"POST", "/api/v1/passphrase", map[string]string{"old": e.passphrase, "new": "n-" + randHex(t)}, e.rootAgent, 403, ""}},
		"POST /api/v1/password":      {{"POST", "/api/v1/password", map[string]string{"old": e.password, "new": "n-" + randHex(t)}, e.rootAgent, 403, ""}},
		"POST /api/v1/totp/setup":    {{"POST", "/api/v1/totp/setup", nil, e.rootAgent, 403, ""}},
		"POST /api/v1/totp/confirm":  {{"POST", "/api/v1/totp/confirm", map[string]string{"code": "123456"}, e.rootAgent, 403, ""}},
		// Logout only ever revokes the caller's own token; checked in TestLogoutRevokesOnlyItself.
		"POST /api/v1/logout": {},
	}
	// Public routes take no token by design; their guard (rate limit, credentials) is tested elsewhere.
	publicRoutes := map[string]bool{"GET /api/v1/status": true, "POST /api/v1/unseal": true, "POST /api/v1/recover": true, "POST /api/v1/login": true}

	for _, rt := range e.srv.routes() {
		if rt.access == public {
			if !publicRoutes[rt.pattern] {
				t.Errorf("route %s is public but not listed as such in this test", rt.pattern)
			}
			continue
		}
		list, ok := cases[rt.pattern]
		if !ok {
			t.Errorf("route %s has no permission test", rt.pattern)
			continue
		}
		for _, c := range list {
			w := e.do(c.method, c.url, c.token, c.body)
			if w.Code != c.want {
				t.Errorf("%s %s: status %d, want %d (%s)", c.method, c.url, w.Code, c.want, w.Body.String())
			}
			if c.notContain != "" && strings.Contains(w.Body.String(), c.notContain) {
				t.Errorf("%s %s leaked %q: %s", c.method, c.url, c.notContain, w.Body.String())
			}
		}
		// Without any token every non-public route is 401.
		method, _, _ := strings.Cut(rt.pattern, " ")
		url := strings.NewReplacer("{path...}", "work/acme/db", "{id}", "1").Replace(strings.TrimPrefix(rt.pattern, method+" "))
		if w := e.do(method, url, "", nil); w.Code != 401 {
			t.Errorf("%s without token: %d", rt.pattern, w.Code)
		}
		if w := e.do(method, url, "ks_"+randHex(t), nil); w.Code != 401 {
			t.Errorf("%s with unknown token: %d", rt.pattern, w.Code)
		}
	}

	// Nothing was changed by the refused calls.
	got, err := e.st.GetField("work/acme/db", "password")
	if err != nil || string(got) != e.secret {
		t.Fatalf("protected value changed: %v", err)
	}
	if e.st.Sealed() {
		t.Fatal("agent sealed the store")
	}
	if toks, _ := e.st.ListAgentTokens(); len(toks) != 3 {
		t.Fatalf("tokens changed: %d", len(toks))
	}
	// Refusals are audited.
	events, _ := e.st.ListAudit(store.AuditFilter{Limit: 1000})
	denied := 0
	for _, ev := range events {
		if strings.HasPrefix(ev.Action, "denied.") {
			denied++
		}
	}
	if denied < 10 {
		t.Fatalf("only %d denials audited", denied)
	}
}

func TestInScopeAgentFlow(t *testing.T) {
	e := newEnv(t, Options{})
	w := e.do("GET", "/api/v1/values/work/acme/db?field=password", e.inScope, nil)
	if w.Code != 200 || w.Body.String() != e.secret || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("read: %d", w.Code)
	}
	binary := []byte{0, 1, 2, 255, '\n'}
	if w := e.do("PUT", "/api/v1/values/work/new/api?field=token", e.inScope, binary); w.Code != 204 {
		t.Fatalf("write: %d %s", w.Code, w.Body)
	}
	if w := e.do("GET", "/api/v1/values/work/new/api?field=token", e.inScope, nil); !bytes.Equal(w.Body.Bytes(), binary) {
		t.Fatal("binary round trip")
	}
	w = e.do("GET", "/api/v1/entries/work/new/api", e.inScope, nil)
	var ent store.Entry
	json.Unmarshal(w.Body.Bytes(), &ent)
	if ent.UpdatedBy != "token:in" || len(ent.Fields) != 1 {
		t.Fatalf("entry %+v", ent)
	}
	if strings.Contains(w.Body.String(), e.secret) {
		t.Fatal("entry metadata contains a value")
	}
	if w := e.do("PUT", "/api/v1/values/work/big?field=x", e.inScope, make([]byte, store.MaxValueSize+1)); w.Code != 413 {
		t.Fatalf("oversize: %d", w.Code)
	}
	// The audit log names the token and never holds the value.
	events, _ := e.st.ListAudit(store.AuditFilter{Target: "work/acme/db"})
	if len(events) == 0 || events[0].Actor != "token:in" || events[0].Action != "value.read" {
		t.Fatalf("audit %+v", events)
	}
	if err := e.st.VerifyAudit(); err != nil {
		t.Fatal(err)
	}
}

func TestHostCheck(t *testing.T) {
	e := newEnv(t, Options{})
	for h, want := range map[string]int{host: 200, "LOCALHOST:7733": 200, "evil.example:7733": 421, "127.0.0.1": 421, "": 421} {
		req := httptest.NewRequest("GET", "/api/v1/status", nil)
		req.Host = h
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("host %q: %d want %d", h, w.Code, want)
		}
	}
}

func TestSealedAndUnseal(t *testing.T) {
	e := newEnv(t, Options{})
	if w := e.do("POST", "/api/v1/seal", e.owner, nil); w.Code != 200 {
		t.Fatalf("seal: %d", w.Code)
	}
	if w := e.do("GET", "/api/v1/values/work/acme/db", e.inScope, nil); w.Code != 503 {
		t.Fatalf("read while sealed: %d", w.Code)
	}
	if w := e.do("POST", "/api/v1/login", "", map[string]string{"password": e.password}); w.Code != 503 {
		t.Fatalf("login while sealed: %d", w.Code)
	}
	w := e.do("GET", "/api/v1/status", "", nil)
	if !strings.Contains(w.Body.String(), `"sealed":true`) {
		t.Fatalf("status %s", w.Body)
	}
	// A cross-site form can only send text/plain; it must be refused before any work.
	req := httptest.NewRequest("POST", "/api/v1/unseal", strings.NewReader(`{"passphrase":"x"}`))
	req.Host = host
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 415 {
		t.Fatalf("text/plain unseal: %d", rec.Code)
	}

	now := time.Unix(1_800_000_000, 0)
	e.srv.now = func() time.Time { return now }
	for i := range 5 {
		if w := e.do("POST", "/api/v1/unseal", "", map[string]string{"passphrase": "wrong-" + randHex(t)}); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w = e.do("POST", "/api/v1/unseal", "", map[string]string{"passphrase": e.passphrase})
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("lockout: %d", w.Code)
	}
	now = now.Add(2 * time.Second)
	if w := e.do("POST", "/api/v1/unseal", "", map[string]string{"passphrase": e.passphrase}); w.Code != 200 {
		t.Fatalf("unseal: %d %s", w.Code, w.Body)
	}
	if w := e.do("GET", "/api/v1/values/work/acme/db", e.inScope, nil); w.Code != 200 {
		t.Fatalf("read after unseal: %d", w.Code)
	}
	events, _ := e.st.ListAudit(store.AuditFilter{})
	fails := 0
	for _, ev := range events {
		if ev.Action == "unseal.fail" {
			fails++
		}
	}
	if fails != 5 {
		t.Fatalf("unseal failures audited: %d", fails)
	}
}

func TestLoginTokensAndRevoke(t *testing.T) {
	e := newEnv(t, Options{})
	if w := e.do("POST", "/api/v1/login", "", map[string]string{"password": "nope-" + randHex(t)}); w.Code != 401 {
		t.Fatalf("wrong login: %d", w.Code)
	}
	w := e.do("POST", "/api/v1/login", "", map[string]string{"password": e.password})
	var login struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &login)
	if w.Code != 200 || login.Token == "" {
		t.Fatalf("login: %d", w.Code)
	}
	w = e.do("POST", "/api/v1/tokens", login.Token, map[string]any{
		"name": "claude", "ttl_seconds": 3600,
		"scopes": []store.Scope{{Folder: "work", Perms: []string{"read"}}},
	})
	var created struct {
		Token string
		Info  store.Token
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	if w.Code != 201 || created.Token == "" {
		t.Fatalf("create token: %d %s", w.Code, w.Body)
	}
	if w := e.do("GET", "/api/v1/values/work/acme/db", created.Token, nil); w.Body.String() != e.secret {
		t.Fatal("new token cannot read")
	}
	if w := e.do("PUT", "/api/v1/values/work/acme/db", created.Token, []byte("x")); w.Code != 403 {
		t.Fatalf("read-only token wrote: %d", w.Code)
	}
	if w := e.do("GET", "/api/v1/entries/work/acme/db", created.Token, nil); w.Code != 403 {
		t.Fatalf("read without list must not show metadata: %d", w.Code)
	}
	w = e.do("GET", "/api/v1/tokens", login.Token, nil)
	if strings.Contains(w.Body.String(), created.Token) {
		t.Fatal("token list contains a secret")
	}
	if w := e.do("DELETE", "/api/v1/tokens/"+itoa(created.Info.ID), login.Token, nil); w.Code != 204 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if w := e.do("GET", "/api/v1/values/work/acme/db", created.Token, nil); w.Code != 401 {
		t.Fatalf("revoked token still works: %d", w.Code)
	}
}

func TestLogoutRevokesOnlyItself(t *testing.T) {
	e := newEnv(t, Options{})
	if w := e.do("POST", "/api/v1/logout", e.outScope, nil); w.Code != 204 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := e.do("GET", "/api/v1/folders", e.outScope, nil); w.Code != 401 {
		t.Fatal("logged-out token still works")
	}
	for _, tok := range []string{e.inScope, e.rootAgent, e.owner} {
		if w := e.do("GET", "/api/v1/folders", tok, nil); w.Code != 200 {
			t.Fatal("logout revoked another token")
		}
	}
}

func TestTOTPLogin(t *testing.T) {
	e := newEnv(t, Options{RequireTOTP: true})
	if w := e.do("POST", "/api/v1/login", "", map[string]string{"password": e.password}); w.Code != 403 {
		t.Fatalf("network login without TOTP set up: %d", w.Code)
	}
	w := e.do("POST", "/api/v1/totp/setup", e.owner, nil)
	var setup struct {
		URI string `json:"otpauth_uri"`
	}
	json.Unmarshal(w.Body.Bytes(), &setup)
	_, q, _ := strings.Cut(setup.URI, "secret=")
	q, _, _ = strings.Cut(q, "&")
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(q)
	if err != nil {
		t.Fatalf("uri %q", setup.URI)
	}
	confirmAt := time.Now()
	if w := e.do("POST", "/api/v1/totp/confirm", e.owner, map[string]string{"code": totp.Code(secret, confirmAt)}); w.Code != 204 {
		t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	if w := e.do("POST", "/api/v1/login", "", map[string]string{"password": e.password}); w.Code != 401 {
		t.Fatalf("login without code: %d", w.Code)
	}
	// Next step's code (accepted within the ±1 window, and not yet used).
	next := totp.Code(secret, confirmAt.Add(30*time.Second))
	if w := e.do("POST", "/api/v1/login", "", map[string]string{"password": e.password, "totp": next}); w.Code != 200 {
		t.Fatalf("login with code: %d %s", w.Code, w.Body)
	}
	if w := e.do("POST", "/api/v1/login", "", map[string]string{"password": e.password, "totp": next}); w.Code != 401 {
		t.Fatalf("replayed code: %d", w.Code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestWebCookieSessionAndCSRF(t *testing.T) {
	e := newEnv(t, Options{})
	w := e.do("POST", "/api/v1/login", "", map[string]any{"password": e.password, "cookie": true})
	if w.Code != 200 {
		t.Fatalf("login: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "ks_") {
		t.Fatal("cookie login must not return the token in the body")
	}
	var resp struct{ CSRF string }
	json.Unmarshal(w.Body.Bytes(), &resp)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Value == "" {
		t.Fatalf("cookie %+v", cookies)
	}
	call := func(method, url, csrf string, body []byte) int {
		req := httptest.NewRequest(method, url, bytes.NewReader(body))
		req.Host = host
		req.AddCookie(cookies[0])
		if body != nil {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := call("GET", "/api/v1/values/work/acme/db", "", nil); c != 200 {
		t.Fatalf("cookie read: %d", c)
	}
	if c := call("PUT", "/api/v1/values/work/acme/db", "", []byte("x")); c != 403 {
		t.Fatalf("write without CSRF: %d", c)
	}
	if c := call("PUT", "/api/v1/values/work/acme/db", strings.Repeat("0", 64), []byte("x")); c != 403 {
		t.Fatalf("write with wrong CSRF: %d", c)
	}
	if c := call("PUT", "/api/v1/values/work/acme/db", resp.CSRF, []byte("x")); c != 204 {
		t.Fatalf("write with CSRF: %d", c)
	}
	// An agent token presented as a cookie is refused: cookies are for owner sessions only.
	req := httptest.NewRequest("GET", "/api/v1/folders", nil)
	req.Host = host
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.inScope})
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("agent token in cookie: %d", rec.Code)
	}
	if c := call("POST", "/api/v1/logout", resp.CSRF, nil); c != 204 {
		t.Fatalf("logout: %d", c)
	}
	if c := call("GET", "/api/v1/folders", "", nil); c != 401 {
		t.Fatalf("cookie after logout: %d", c)
	}
}
