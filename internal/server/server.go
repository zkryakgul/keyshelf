// Package server is keyshelf's HTTP API (/api/v1). Every route is declared in one table with its access
// level, so the permission tests can check that no route is left untested.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zkryakgul/keyshelf/internal/store"
)

type access int

const (
	public   access = iota // no token (status, unseal, login): guarded by rate limits instead
	anyToken               // agent or owner; the handler checks folder permissions
	ownerOnly
)

type handlerFunc func(w http.ResponseWriter, r *http.Request, tok store.Token)

type route struct {
	pattern  string
	access   access
	sealedOK bool // served while sealed
	h        handlerFunc
}

// Options configure a Server.
type Options struct {
	// AllowedHosts are the exact Host header values accepted (e.g. "127.0.0.1:7733"). Anything else is
	// refused, which defeats DNS rebinding. Required.
	AllowedHosts []string
	// RequireTOTP refuses owner login without TOTP; set when listening on a non-loopback address.
	RequireTOTP bool
	// SessionTTL is the lifetime of an owner session; default 1 hour.
	SessionTTL time.Duration
	Logger     *slog.Logger
	// UI is the embedded web interface, served at /. Optional.
	UI fs.FS
}

// Server serves the API.
type Server struct {
	st     *store.Store
	opts   Options
	hosts  map[string]bool
	now    func() time.Time
	log    *slog.Logger
	unseal *limiter
	login  *limiter
	credMu sync.Mutex // one password check (64 MiB Argon2id) at a time
}

// New returns a Server for st.
func New(st *store.Store, opts Options) *Server {
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = time.Hour
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{st: st, opts: opts, hosts: map[string]bool{}, now: time.Now, log: opts.Logger}
	for _, h := range opts.AllowedHosts {
		s.hosts[strings.ToLower(h)] = true
	}
	s.unseal = &limiter{now: func() time.Time { return s.now() }}
	s.login = &limiter{now: func() time.Time { return s.now() }}
	return s
}

func (s *Server) routes() []route {
	return []route{
		{"GET /api/v1/status", public, true, s.handleStatus},
		{"POST /api/v1/unseal", public, true, s.handleUnseal},
		{"POST /api/v1/recover", public, true, s.handleRecover},
		{"POST /api/v1/login", public, false, s.handleLogin},

		{"POST /api/v1/logout", anyToken, true, s.handleLogout},
		{"GET /api/v1/folders", anyToken, false, s.handleFolders},
		{"GET /api/v1/entries", anyToken, false, s.handleListEntries},
		{"GET /api/v1/entries/{path...}", anyToken, false, s.handleGetEntry},
		{"PUT /api/v1/entries/{path...}", anyToken, false, s.handlePutEntry},
		{"DELETE /api/v1/entries/{path...}", anyToken, false, s.handleDeleteEntry},
		{"GET /api/v1/values/{path...}", anyToken, false, s.handleGetValue},
		{"PUT /api/v1/values/{path...}", anyToken, false, s.handlePutValue},
		{"DELETE /api/v1/values/{path...}", anyToken, false, s.handleDeleteValue},

		{"GET /api/v1/session", ownerOnly, true, s.handleSession},
		{"POST /api/v1/seal", ownerOnly, true, s.handleSeal},
		{"GET /api/v1/tokens", ownerOnly, false, s.handleListTokens},
		{"POST /api/v1/tokens", ownerOnly, false, s.handleCreateToken},
		{"DELETE /api/v1/tokens/{id}", ownerOnly, false, s.handleRevokeToken},
		{"GET /api/v1/audit", ownerOnly, false, s.handleAudit},
		{"POST /api/v1/passphrase", ownerOnly, false, s.handlePassphrase},
		{"POST /api/v1/password", ownerOnly, false, s.handlePassword},
		{"POST /api/v1/totp/setup", ownerOnly, false, s.handleTOTPSetup},
		{"POST /api/v1/totp/confirm", ownerOnly, false, s.handleTOTPConfirm},
	}
}

// Handler returns the API handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		mux.Handle(rt.pattern, s.wrap(rt))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such route")
	})
	if s.opts.UI != nil {
		files := http.FileServerFS(s.opts.UI)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			w.Header().Set("Content-Security-Policy", uiCSP)
			files.ServeHTTP(w, r)
		})
	}
	return s.hostCheck(mux)
}

func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if !s.hosts[strings.ToLower(r.Host)] {
			writeError(w, http.StatusMisdirectedRequest, "host not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// uiCSP allows only the embedded files: no inline script or style, no other origin.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

const sessionCookie = "ks_session"

// csrfFor derives the CSRF token of a cookie session. Another site cannot compute it without the
// cookie value, which it can neither read nor (SameSite=Strict) send.
func csrfFor(secret string) string {
	h := sha256.Sum256([]byte("keyshelf-csrf\x00" + secret))
	return hex.EncodeToString(h[:])
}

// credentials returns the bearer token or, for the web UI, the session cookie.
func credentials(r *http.Request) (secret string, viaCookie bool) {
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(v), false
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value, true
	}
	return "", false
}

func (s *Server) wrap(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rt.sealedOK {
			if !s.st.Initialized() {
				writeError(w, http.StatusServiceUnavailable, "not initialised: run ks init")
				return
			}
			if s.st.Sealed() {
				writeError(w, http.StatusServiceUnavailable, "sealed: the owner must unseal keyshelf")
				return
			}
		}
		var tok store.Token
		if rt.access != public {
			secret, viaCookie := credentials(r)
			if secret == "" {
				writeError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			var err error
			tok, err = s.st.Authenticate(secret)
			if err != nil || (viaCookie && !tok.IsOwner()) {
				writeError(w, http.StatusUnauthorized, "invalid, expired or revoked token")
				return
			}
			if viaCookie && r.Method != http.MethodGet && r.Method != http.MethodHead &&
				subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrfFor(secret))) != 1 {
				writeError(w, http.StatusForbidden, "missing or wrong CSRF token")
				return
			}
			if rt.access == ownerOnly && !tok.IsOwner() {
				s.deny(w, r, tok, "owner", r.URL.Path)
				return
			}
		}
		rt.h(w, r, tok)
	})
}

// ---- helpers ----

func source(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) audit(r *http.Request, actor, action, target string) {
	if err := s.st.Audit(store.Event{Actor: actor, Action: action, Target: target, Source: source(r)}); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, tok store.Token, perm, target string) {
	s.audit(r, tok.Actor(), "denied."+perm, target)
	writeError(w, http.StatusForbidden, "forbidden")
}

// allow checks perm on folder and writes a 403 if missing.
func (s *Server) allow(w http.ResponseWriter, r *http.Request, tok store.Token, perm, folder, target string) bool {
	if tok.Allows(perm, folder) {
		return true
	}
	s.deny(w, r, tok, perm, target)
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrInvalidName), errors.Is(err, store.ErrWeakPassphrase), errors.Is(err, store.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, store.ErrTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "value too large")
	case errors.Is(err, store.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "sealed: the owner must unseal keyshelf")
	case errors.Is(err, store.ErrNotInitialized):
		writeError(w, http.StatusConflict, "not initialised: run ks init")
	case errors.Is(err, store.ErrBadCredentials):
		writeError(w, http.StatusUnauthorized, "wrong credentials")
	default:
		s.log.Error("internal error", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// decode reads a JSON body. Requiring application/json means a cross-site HTML form cannot send it
// without a CORS preflight, which this server never answers.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// pathFolder validates the {path...} wildcard and returns the entry's folder.
func pathFolder(w http.ResponseWriter, r *http.Request) (path, folder string, ok bool) {
	path = r.PathValue("path")
	folder, _, err := store.SplitPath(path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", "", false
	}
	return path, folder, true
}

// ---- rate limiting ----

// limiter slows down guessing: after 5 consecutive failures each further attempt waits 2^(n-5)
// seconds, up to 15 minutes. It is global, not per address: all local callers share 127.0.0.1.
type limiter struct {
	mu    sync.Mutex
	fails int
	until time.Time
	now   func() time.Time
}

func (l *limiter) check() (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if wait := l.until.Sub(l.now()); wait > 0 {
		return wait, false
	}
	return 0, true
}

func (l *limiter) fail() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails++
	if l.fails >= 5 {
		d := time.Duration(math.Min(math.Pow(2, float64(l.fails-5)), 900)) * time.Second
		l.until = l.now().Add(d)
	}
}

func (l *limiter) success() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails, l.until = 0, time.Time{}
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
	writeError(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
}

// credential runs check under the limiter and the credential mutex.
// ok is false when the attempt was refused by the limiter (the response is already written).
func (s *Server) credential(w http.ResponseWriter, lim *limiter, check func() error) (ok bool, err error) {
	if wait, allowed := lim.check(); !allowed {
		tooMany(w, wait)
		return false, nil
	}
	s.credMu.Lock()
	err = check()
	s.credMu.Unlock()
	if errors.Is(err, store.ErrBadCredentials) {
		lim.fail()
	} else if err == nil {
		lim.success()
	}
	return true, err
}
