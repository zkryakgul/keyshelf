package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/zkryakgul/keyshelf/internal/client"
	"github.com/zkryakgul/keyshelf/internal/server"
	"github.com/zkryakgul/keyshelf/internal/store"
	"github.com/zkryakgul/keyshelf/internal/web"
)

const defaultListen = "127.0.0.1:7733"

type app struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	getenv         func(string) string
	isTTY          func() bool
	prompt         func(label string) (string, error)
	exec           func(argv0 string, argv, env []string) error
	copy           func([]byte) error
	// configDir and dataDir override the XDG defaults (tests).
	configDir, dataDir string
	color              bool      // stdout is a terminal and NO_COLOR is unset
	update             updateEnv // zero value: the real GitHub releases
}

const usage = `keyshelf: a small shelf for project secrets.

Server (run by the owner):
  ks init                 create the database: unseal passphrase, login password, recovery code
  ks serve                run the server and web UI (default ` + defaultListen + `)
  ks unseal [--recovery]  unseal after a restart (asks for the passphrase on the terminal)
  ks seal                 drop the key from memory
  ks login | ks logout    owner session for the commands marked (owner)
  ks status               server state and which credentials this shell has
  ks backup DEST          copy the encrypted database
  ks update [--check] [--restart]   install the latest release (alias: ks upgrade)

Secrets (agent token from KEYSHELF_TOKEN or ~/.config/keyshelf/config.json; --owner uses the session):
  ks ls [FOLDER] [-r] [-q TEXT]           list entries (names only)
  ks get REF --to-file PATH | --copy | --reveal
  ks put REF [--from-file F | --generate N | --stdin] [--kind K --url U --username N --notes T --tag T]
  ks gen REF [--length 32] [--alnum]      generate a random value and store it, printing nothing
  ks run --env NAME=REF [--env ...] -- COMMAND [ARGS]
  ks rm REF                               remove a field (folder/entry#field) or a whole entry

Owner:
  ks token create NAME --scope FOLDER:list,read,write [--scope ...] [--ttl 720h] [--save]
  ks token ls | ks token revoke ID
  ks audit [TARGET] [--limit N] | ks audit --verify
  ks totp setup

REF is folder/path/entry#field; the field defaults to "password". Values are never printed unless
--reveal is given.
`

func (a *app) run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(a.stdout, usage)
		return 0
	}
	cmds := map[string]func([]string) error{
		"init": a.cmdInit, "serve": a.cmdServe, "unseal": a.cmdUnseal, "seal": a.cmdSeal,
		"login": a.cmdLogin, "logout": a.cmdLogout, "status": a.cmdStatus, "backup": a.cmdBackup,
		"ls": a.cmdLs, "get": a.cmdGet, "put": a.cmdPut, "gen": a.cmdGen, "run": a.cmdRun, "rm": a.cmdRm,
		"token": a.cmdToken, "audit": a.cmdAudit, "totp": a.cmdTOTP,
		"update": a.cmdUpdate, "upgrade": a.cmdUpdate,
		"version": func([]string) error { fmt.Fprintln(a.stdout, "keyshelf", version); return nil },
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		fmt.Fprintf(a.stderr, "ks: unknown command %q (see ks help)\n", args[0])
		return 2
	}
	if err := cmd(args[1:]); err != nil {
		var u usageError
		if errors.As(err, &u) {
			fmt.Fprintf(a.stderr, "ks %s: %v\n", args[0], err)
			return 2
		}
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(a.stderr, "ks %s: %v\n", args[0], hint(err))
		return 1
	}
	return 0
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

func hint(err error) error {
	var ce *client.Error
	if errors.As(err, &ce) {
		switch {
		case ce.Status == 503 && strings.Contains(ce.Message, "sealed"):
			return fmt.Errorf("%v\nkeyshelf is sealed. The owner runs `ks unseal` (agents: ask the owner, do not try)", err)
		case ce.Status == 401:
			return fmt.Errorf("%v\nThe token is missing, expired or revoked (owner commands need `ks login`)", err)
		case ce.Status == 403:
			return fmt.Errorf("%v\nThis token has no permission for that folder; ask the owner for a token that covers it", err)
		}
	}
	return err
}

// ---- configuration ----

type config struct {
	Server string `json:"server,omitempty"`
	Token  string `json:"token,omitempty"`
}

type session struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (a *app) cfgDir() string {
	if a.configDir != "" {
		return a.configDir
	}
	return homeDir(a.getenv, "XDG_CONFIG_HOME", ".config")
}

func (a *app) dbPath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if p := a.getenv("KEYSHELF_DB"); p != "" {
		return p, nil
	}
	dir := a.dataDir
	if dir == "" {
		dir = homeDir(a.getenv, "XDG_DATA_HOME", filepath.Join(".local", "share"))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "keyshelf.db"), nil
}

func (a *app) loadConfig() config {
	var c config
	if raw, err := os.ReadFile(filepath.Join(a.cfgDir(), "config.json")); err == nil {
		json.Unmarshal(raw, &c)
	}
	return c
}

func (a *app) serverURL() string {
	if u := a.getenv("KEYSHELF_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	if c := a.loadConfig(); c.Server != "" {
		return strings.TrimRight(c.Server, "/")
	}
	return "http://" + defaultListen
}

// socketPath is the owner-only local socket: $KEYSHELF_SOCKET or $XDG_RUNTIME_DIR/keyshelf/ks.sock.
func (a *app) socketPath() string {
	if p := a.getenv("KEYSHELF_SOCKET"); p != "" {
		return p
	}
	if d := a.getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "keyshelf", "ks.sock")
	}
	return ""
}

// checkServerURL refuses to send tokens and values in clear text to another machine.
func checkServerURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("invalid keyshelf URL %q", u)
	}
	if parsed.Scheme == "http" && !isLoopback(parsed.Hostname()) {
		return fmt.Errorf("refusing plain http to %s: tokens and values would cross the network unencrypted (use https)", parsed.Host)
	}
	return nil
}

// newClient talks to the server: KEYSHELF_URL if set, else the local socket if present, else TCP.
func (a *app) newClient(token string) (*client.Client, error) {
	if a.getenv("KEYSHELF_URL") == "" {
		if sp := a.socketPath(); sp != "" {
			if fi, err := os.Stat(sp); err == nil && fi.Mode()&os.ModeSocket != 0 {
				return &client.Client{BaseURL: "http://keyshelf.socket", Socket: sp, Token: token}, nil
			}
		}
	}
	u := a.serverURL()
	if err := checkServerURL(u); err != nil {
		return nil, err
	}
	return &client.Client{BaseURL: u, Token: token}, nil
}

func (a *app) publicClient() (*client.Client, error) { return a.newClient("") }

// agentClient uses KEYSHELF_TOKEN or the config file's token; with owner it uses the owner session.
func (a *app) agentClient(owner bool) (*client.Client, error) {
	if owner {
		return a.ownerClient()
	}
	tok := a.getenv("KEYSHELF_TOKEN")
	if tok == "" {
		tok = a.loadConfig().Token
	}
	if tok == "" {
		return nil, errors.New("no token: set KEYSHELF_TOKEN or ask the owner for `ks token create NAME --scope ... --save`")
	}
	return a.newClient(tok)
}

func (a *app) sessionPath() string { return filepath.Join(a.cfgDir(), "session.json") }

func (a *app) ownerClient() (*client.Client, error) {
	var s session
	raw, err := os.ReadFile(a.sessionPath())
	if err == nil {
		err = json.Unmarshal(raw, &s)
	}
	if err != nil || s.Token == "" || time.Now().After(s.ExpiresAt) {
		return nil, errors.New("no owner session: run `ks login`")
	}
	return a.newClient(s.Token)
}

// writePrivate writes data to path with mode 0600, atomically.
func writePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".ks-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// parse parses flags that may come before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos, args = append(pos, args[0]), args[1:]
	}
}

func (a *app) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	return fs
}

func (a *app) promptTwice(label string) (string, error) {
	v, err := a.prompt(label + ": ")
	if err != nil {
		return "", err
	}
	again, err := a.prompt("Repeat " + strings.ToLower(label[:1]) + label[1:] + ": ")
	if err != nil {
		return "", err
	}
	if v != again {
		return "", errors.New("the two entries differ")
	}
	return v, nil
}

// ---- server commands ----

func (a *app) cmdInit(args []string) error {
	fs := a.flags("init")
	db := fs.String("db", "", "database path (default ~/.local/share/keyshelf/keyshelf.db)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	syscall.Umask(0o077)
	path, err := a.dbPath(*db)
	if err != nil {
		return err
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if st.Initialized() {
		return fmt.Errorf("%s is already initialised", path)
	}
	pr := a.printer()
	pr.title("Setting up keyshelf")
	pr.info("Database: %s", path)
	pr.title("1. Unseal passphrase")
	pr.info("Decrypts everything. You type it after every restart. Min %d characters.", store.MinPassphraseLen)
	pass, err := a.promptTwice("Unseal passphrase")
	if err != nil {
		return err
	}
	pr.title("2. Login password")
	pr.info("Opens the web UI and `ks login`. Must differ from the passphrase. Min %d characters.", store.MinPasswordLen)
	pw, err := a.promptTwice("Login password")
	if err != nil {
		return err
	}
	if pw == pass {
		return errors.New("the login password must differ from the unseal passphrase")
	}
	if len(pw) < store.MinPasswordLen {
		return store.ErrWeakPassword
	}
	code, err := st.Init([]byte(pass))
	if err != nil {
		return err
	}
	if err := st.SetOwnerPassword([]byte(pw)); err != nil {
		return err
	}
	pr.ok("keyshelf is initialised")
	pr.title("3. Recovery code: shown once, write it down and keep it offline")
	pr.box(code)
	pr.info("If you forget the passphrase: ks unseal --recovery")
	pr.title("Next")
	pr.cmd("ks unseal")
	pr.cmd("ks login")
	pr.cmd("ks token create claude --scope :list,read,write --save")
	pr.info("Web UI: http://%s", defaultListen)
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func (a *app) cmdServe(args []string) error {
	fs := a.flags("serve")
	listen := fs.String("listen", defaultListen, "address to listen on")
	db := fs.String("db", "", "database path")
	cert := fs.String("tls-cert", "", "TLS certificate file")
	key := fs.String("tls-key", "", "TLS key file")
	insecure := fs.Bool("insecure-http", false, "allow plain HTTP on a non-loopback address (not recommended)")
	proxy := fs.Bool("behind-proxy", false, "a TLS reverse proxy forwards to this loopback address: require TOTP, Secure cookies, trust X-Forwarded-For from loopback")
	sock := fs.String("socket", a.socketPath(), "owner-only Unix socket (mode 0600); empty disables it")
	var hosts multiFlag
	fs.Var(&hosts, "host", "extra Host header value to accept, e.g. keys.example.org (repeatable)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	syscall.Umask(0o077)
	host, port, err := net.SplitHostPort(*listen)
	if err != nil {
		return usagef("--listen: %v", err)
	}
	tls := *cert != "" || *key != ""
	if tls && (*cert == "" || *key == "") {
		return usagef("--tls-cert and --tls-key go together")
	}
	loop := isLoopback(host)
	if !loop && !tls && !*insecure {
		return errors.New("refusing plain HTTP on a non-loopback address: use --tls-cert/--tls-key or a TLS reverse proxy on loopback")
	}
	allowed := []string{*listen}
	if loop {
		allowed = append(allowed, "localhost:"+port, "127.0.0.1:"+port, "[::1]:"+port)
	}
	for _, h := range hosts {
		allowed = append(allowed, h)
		if !strings.Contains(h, ":") {
			allowed = append(allowed, h+":"+port)
		}
	}
	path, err := a.dbPath(*db)
	if err != nil {
		return err
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	logger := slog.New(slog.NewTextHandler(a.stderr, nil))
	network := !loop || *proxy
	for _, h := range hosts {
		name := h
		if hh, _, err := net.SplitHostPort(h); err == nil {
			name = hh
		}
		if !isLoopback(name) {
			network = true // reachable under a public name, e.g. through a proxy
		}
	}
	srv := server.New(st, server.Options{AllowedHosts: allowed, RequireTOTP: network, BehindProxy: *proxy, Logger: logger, UI: web.Files()})
	hs := &http.Server{
		Addr: *listen, Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 2)
	var ls *http.Server
	if *sock != "" {
		l, err := listenSocket(*sock)
		if err != nil {
			return fmt.Errorf("local socket: %w", err)
		}
		ls = &http.Server{Handler: srv.LocalHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
		go func() { errc <- ls.Serve(l) }()
		defer os.Remove(*sock)
	}
	go func() {
		if tls {
			errc <- hs.ListenAndServeTLS(*cert, *key)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	scheme := "http"
	if tls {
		scheme = "https"
	}
	state := "sealed"
	if !st.Initialized() {
		state = "not initialised (run ks init)"
	}
	logger.Info("keyshelf listening", "url", scheme+"://"+*listen, "socket", *sock, "db", path, "state", state,
		"totp_required", network, "version", version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down; sealing")
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ls != nil {
		ls.Shutdown(shut)
	}
	return hs.Shutdown(shut)
}

// listenSocket creates the owner-only Unix socket in a 0700 directory, replacing a stale one.
func listenSocket(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	err := os.Chmod(filepath.Dir(path), 0o700) // #nosec G302 -- a directory needs the x bit; 0700 is owner-only
	if err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s is in use: is another ks serve running?", path)
		}
		os.Remove(path)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (a *app) cmdUnseal(args []string) error {
	fs := a.flags("unseal")
	recovery := fs.Bool("recovery", false, "use the recovery code and set a new passphrase")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, err := a.publicClient()
	if err != nil {
		return err
	}
	if *recovery {
		code, err := a.prompt("Recovery code: ")
		if err != nil {
			return err
		}
		pass, err := a.promptTwice("New unseal passphrase")
		if err != nil {
			return err
		}
		if err := c.Recover(code, pass); err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, "Unsealed; the passphrase has been replaced.")
		return nil
	}
	pass, err := a.prompt("Unseal passphrase: ")
	if err != nil {
		return err
	}
	if err := c.Unseal(pass); err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "Unsealed.")
	return nil
}

func (a *app) cmdSeal(args []string) error {
	c, err := a.ownerClient()
	if err != nil {
		return err
	}
	if err := c.Seal(); err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "Sealed.")
	return nil
}

func (a *app) cmdLogin(args []string) error {
	pw, err := a.prompt("Login password: ")
	if err != nil {
		return err
	}
	c, err := a.publicClient()
	if err != nil {
		return err
	}
	tok, exp, err := c.Login(pw, "")
	var ce *client.Error
	if errors.As(err, &ce) && ce.Status == 401 && strings.Contains(ce.Message, "TOTP") {
		code, perr := a.prompt("TOTP code: ")
		if perr != nil {
			return perr
		}
		tok, exp, err = c.Login(pw, strings.TrimSpace(code))
	}
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(session{Token: tok, ExpiresAt: exp})
	if err := writePrivate(a.sessionPath(), raw); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Logged in until %s. Run `ks logout` when done: agents run as your user.\n", exp.Local().Format("15:04"))
	return nil
}

func (a *app) cmdLogout(args []string) error {
	c, err := a.ownerClient()
	if err == nil {
		c.Logout()
	}
	os.Remove(a.sessionPath())
	fmt.Fprintln(a.stdout, "Logged out.")
	return nil
}

func (a *app) cmdStatus(args []string) error {
	pc, err := a.publicClient()
	if err != nil {
		return err
	}
	st, err := pc.Status()
	if err != nil {
		return err
	}
	state := "unsealed"
	switch {
	case !st.Initialized:
		state = "not initialised"
	case st.Sealed:
		state = "sealed"
	}
	where := a.serverURL()
	if pc.Socket != "" {
		where = pc.Socket
	}
	fmt.Fprintf(a.stdout, "server:  %s (%s)\n", where, state)
	if _, err := a.agentClient(false); err == nil {
		fmt.Fprintln(a.stdout, "token:   configured")
	} else {
		fmt.Fprintln(a.stdout, "token:   none")
	}
	if _, err := a.ownerClient(); err == nil {
		fmt.Fprintln(a.stdout, "session: owner session active")
	}
	return nil
}

func (a *app) cmdBackup(args []string) error {
	fs := a.flags("backup")
	db := fs.String("db", "", "database path")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: ks backup DEST")
	}
	syscall.Umask(0o077)
	path, err := a.dbPath(*db)
	if err != nil {
		return err
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Backup(pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Encrypted backup written to %s (useless without the passphrase or recovery code).\n", pos[0])
	return nil
}

// ---- secret commands ----

func (a *app) cmdLs(args []string) error {
	fs := a.flags("ls")
	rec := fs.Bool("r", false, "include subfolders")
	q := fs.String("q", "", "search names, URLs, usernames and tags")
	owner := fs.Bool("owner", false, "use the owner session")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	c, err := a.agentClient(*owner)
	if err != nil {
		return err
	}
	folder := ""
	if len(pos) > 0 {
		folder = strings.Trim(pos[0], "/")
	}
	if folder == "" && *q == "" {
		*rec = true
	}
	entries, err := c.Entries(folder, *rec, *q)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Path(), e.Kind, strings.Join(e.Fields, ","), e.URL)
	}
	return tw.Flush()
}

func parseRef(s string) (store.Ref, string, error) {
	r, err := store.ParseRef(s)
	if err != nil {
		return r, "", err
	}
	path := r.Entry
	if r.Folder != "" {
		path = r.Folder + "/" + r.Entry
	}
	return r, path, nil
}

func (a *app) cmdGet(args []string) error {
	fs := a.flags("get")
	toFile := fs.String("to-file", "", "write the value to this file (mode 0600)")
	cp := fs.Bool("copy", false, "copy the value to the clipboard")
	reveal := fs.Bool("reveal", false, "print the value (avoid in agent sessions: it lands in the transcript)")
	owner := fs.Bool("owner", false, "use the owner session")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: ks get REF --to-file PATH | --copy | --reveal")
	}
	sinks := 0
	for _, b := range []bool{*toFile != "", *cp, *reveal} {
		if b {
			sinks++
		}
	}
	if sinks != 1 {
		return usagef("choose exactly one of --to-file PATH, --copy or --reveal (values are not printed by default)")
	}
	ref, path, err := parseRef(pos[0])
	if err != nil {
		return err
	}
	c, err := a.agentClient(*owner)
	if err != nil {
		return err
	}
	v, err := c.Value(path, ref.Field)
	if err != nil {
		return err
	}
	switch {
	case *toFile != "":
		if err := writePrivate(*toFile, v); err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "Wrote %s#%s to %s (mode 0600).\n", path, ref.Field, *toFile)
	case *cp:
		if err := a.copy(v); err != nil {
			return err
		}
		fmt.Fprintln(a.stderr, "Copied to the clipboard.")
	default:
		a.stdout.Write(v)
		if len(v) > 0 && v[len(v)-1] != '\n' {
			fmt.Fprintln(a.stdout)
		}
	}
	return nil
}

const (
	alnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	symbols = "-_.!@#%^&*+="
)

func generate(n int, onlyAlnum bool) ([]byte, error) {
	if n < 8 || n > 1024 {
		return nil, usagef("length must be between 8 and 1024")
	}
	set := alnum + symbols
	if onlyAlnum {
		set = alnum
	}
	out := make([]byte, n)
	max := big.NewInt(int64(len(set)))
	for i := range out {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		out[i] = set[k.Int64()]
	}
	return out, nil
}

func (a *app) cmdPut(args []string) error {
	fs := a.flags("put")
	fromFile := fs.String("from-file", "", "read the value from this file (exact bytes)")
	gen := fs.Int("generate", 0, "generate a random value of this length")
	alnumOnly := fs.Bool("alnum", false, "with --generate: letters and digits only")
	fromStdin := fs.Bool("stdin", false, "read the value from standard input")
	kind := fs.String("kind", "", "entry kind: login, api-key, url, note")
	u := fs.String("url", "", "URL")
	user := fs.String("username", "", "username")
	notes := fs.String("notes", "", "notes (plain text, searchable; do not put secrets here)")
	var tags multiFlag
	fs.Var(&tags, "tag", "tag (repeatable)")
	owner := fs.Bool("owner", false, "use the owner session")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: ks put REF [--from-file F | --generate N | --stdin] [metadata flags]")
	}
	ref, path, err := parseRef(pos[0])
	if err != nil {
		return err
	}
	meta := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { meta[f.Name] = true })
	hasMeta := meta["kind"] || meta["url"] || meta["username"] || meta["notes"] || meta["tag"]
	sources := 0
	for _, b := range []bool{*fromFile != "", *gen > 0, *fromStdin} {
		if b {
			sources++
		}
	}
	if sources > 1 {
		return usagef("choose one of --from-file, --generate or --stdin")
	}
	c, err := a.agentClient(*owner)
	if err != nil {
		return err
	}

	var value []byte
	switch {
	case *fromFile != "":
		if value, err = os.ReadFile(*fromFile); err != nil {
			return err
		}
	case *gen > 0:
		if value, err = generate(*gen, *alnumOnly); err != nil {
			return err
		}
	case *fromStdin || !hasMeta:
		if a.isTTY() {
			s, err := a.promptTwice("Value for " + path + "#" + ref.Field)
			if err != nil {
				return err
			}
			value = []byte(s)
		} else {
			if value, err = io.ReadAll(io.LimitReader(a.stdin, store.MaxValueSize+1)); err != nil {
				return err
			}
			value = []byte(strings.TrimSuffix(strings.TrimSuffix(string(value), "\n"), "\r"))
		}
	}

	if hasMeta {
		in := store.EntryInput{}
		if e, err := c.Entry(path); err == nil {
			in = store.EntryInput{Kind: e.Kind, URL: e.URL, Username: e.Username, Notes: e.Notes, SecretNotes: e.SecretNotes, Tags: e.Tags, ExpiresAt: e.ExpiresAt}
			if e.SecretNotes && !meta["notes"] {
				// Secret notes are not in the metadata; send them back unchanged so they are kept.
				v, err := c.Value(path, store.NotesField)
				if err != nil {
					return fmt.Errorf("keeping the secret notes needs read permission: %w", err)
				}
				in.Notes = string(v)
			}
		} else if ce := (*client.Error)(nil); !errors.As(err, &ce) || ce.Status != 404 {
			return err
		}
		if meta["kind"] {
			in.Kind = *kind
		}
		if meta["url"] {
			in.URL = *u
		}
		if meta["username"] {
			in.Username = *user
		}
		if meta["notes"] {
			in.Notes, in.SecretNotes = *notes, false
		}
		if meta["tag"] {
			in.Tags = tags
		}
		if _, err := c.PutEntry(path, in); err != nil {
			return err
		}
	}
	if value != nil {
		if err := c.PutValue(path, ref.Field, value); err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "Stored %s#%s (%d bytes).\n", path, ref.Field, len(value))
	} else {
		fmt.Fprintf(a.stderr, "Updated %s.\n", path)
	}
	return nil
}

func (a *app) cmdGen(args []string) error {
	fs := a.flags("gen")
	n := fs.Int("length", 32, "length")
	alnumOnly := fs.Bool("alnum", false, "letters and digits only")
	owner := fs.Bool("owner", false, "use the owner session")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: ks gen REF [--length N] [--alnum]")
	}
	ref, path, err := parseRef(pos[0])
	if err != nil {
		return err
	}
	v, err := generate(*n, *alnumOnly)
	if err != nil {
		return err
	}
	c, err := a.agentClient(*owner)
	if err != nil {
		return err
	}
	if err := c.PutValue(path, ref.Field, v); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Generated and stored %s#%s (%d characters). Fetch it with ks get or ks run.\n", path, ref.Field, *n)
	return nil
}

func (a *app) cmdRun(args []string) error {
	fs := a.flags("run")
	var envs multiFlag
	fs.Var(&envs, "env", "NAME=REF: set environment variable NAME to the value of REF (repeatable)")
	owner := fs.Bool("owner", false, "use the owner session")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmd := fs.Args()
	if len(envs) == 0 || len(cmd) == 0 {
		return usagef("usage: ks run --env NAME=REF [--env ...] -- COMMAND [ARGS]")
	}
	c, err := a.agentClient(*owner)
	if err != nil {
		return err
	}
	set := map[string]string{}
	var order []string
	for _, e := range envs {
		name, refStr, ok := strings.Cut(e, "=")
		if !ok || name == "" {
			return usagef("--env wants NAME=REF, got %q", e)
		}
		ref, path, err := parseRef(refStr)
		if err != nil {
			return err
		}
		v, err := c.Value(path, ref.Field)
		if err != nil {
			return fmt.Errorf("%s: %w", refStr, err)
		}
		if strings.ContainsRune(string(v), 0) {
			return fmt.Errorf("%s contains a NUL byte and cannot go into an environment variable", refStr)
		}
		if _, dup := set[name]; !dup {
			order = append(order, name)
		}
		set[name] = string(v)
	}
	return a.exec(cmd[0], cmd, childEnv(os.Environ(), set, order))
}

// childEnv drops keyshelf's own credentials and any variable being replaced, then adds the values, so
// the child sees exactly one NAME (getenv takes the first match) and never the agent token.
func childEnv(base []string, set map[string]string, order []string) []string {
	var env []string
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "KEYSHELF_") {
			continue
		}
		if _, replaced := set[name]; replaced {
			continue
		}
		env = append(env, kv)
	}
	for _, name := range order {
		env = append(env, name+"="+set[name])
	}
	return env
}

func (a *app) cmdRm(args []string) error {
	fs := a.flags("rm")
	owner := fs.Bool("owner", false, "use the owner session")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: ks rm folder/entry#field | ks rm folder/entry")
	}
	ref, path, err := parseRef(pos[0])
	if err != nil {
		return err
	}
	c, err := a.agentClient(*owner)
	if err != nil {
		return err
	}
	if strings.Contains(pos[0], "#") {
		if err := c.DeleteValue(path, ref.Field); err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "Removed %s#%s (earlier versions are kept).\n", path, ref.Field)
		return nil
	}
	if err := c.DeleteEntry(path); err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "Removed %s.\n", path)
	return nil
}

// ---- owner commands ----

func parseScope(s string) (store.Scope, error) {
	folder, perms, ok := strings.Cut(s, ":")
	if !ok || perms == "" {
		return store.Scope{}, usagef("--scope wants FOLDER:PERMS, e.g. work/acme:list,read (use :list,read for everything)")
	}
	return store.Scope{Folder: strings.Trim(folder, "/"), Perms: strings.Split(perms, ",")}, nil
}

func (a *app) cmdToken(args []string) error {
	if len(args) == 0 {
		return usagef("usage: ks token create|ls|revoke")
	}
	c, err := a.ownerClient()
	if err != nil {
		return err
	}
	switch args[0] {
	case "create":
		fs := a.flags("token create")
		var scopes multiFlag
		fs.Var(&scopes, "scope", "FOLDER:list,read,write (repeatable)")
		ttl := fs.Duration("ttl", 0, "lifetime, e.g. 720h (default: no expiry)")
		save := fs.Bool("save", false, "store the token in this user's keyshelf config instead of printing it")
		pos, err := parse(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 1 || len(scopes) == 0 {
			return usagef("usage: ks token create NAME --scope FOLDER:PERMS [--ttl D] [--save]")
		}
		var sc []store.Scope
		for _, s := range scopes {
			p, err := parseScope(s)
			if err != nil {
				return err
			}
			sc = append(sc, p)
		}
		pw, err := a.prompt("Login password (to confirm): ")
		if err != nil {
			return err
		}
		secret, info, err := c.CreateToken(pos[0], sc, *ttl, pw)
		if err != nil {
			return err
		}
		if *save {
			cfg := a.loadConfig()
			cfg.Token = secret
			raw, _ := json.MarshalIndent(cfg, "", "  ")
			if err := writePrivate(filepath.Join(a.cfgDir(), "config.json"), raw); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "Token %q (id %d) saved to %s.\n", info.Name, info.ID, filepath.Join(a.cfgDir(), "config.json"))
			return nil
		}
		fmt.Fprintf(a.stdout, "Token %q (id %d), shown once:\n%s\n", info.Name, info.ID, secret)
		return nil
	case "ls":
		list, err := c.Tokens()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tSCOPES\tEXPIRES\tLAST USED")
		for _, t := range list {
			var sc []string
			for _, s := range t.Scopes {
				f := s.Folder
				if f == "" {
					f = "(all)"
				}
				sc = append(sc, f+":"+strings.Join(s.Perms, ","))
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", t.ID, t.Name, strings.Join(sc, " "), fmtTime(t.ExpiresAt), fmtTime(t.LastUsedAt))
		}
		return tw.Flush()
	case "revoke":
		if len(args) != 2 {
			return usagef("usage: ks token revoke ID")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return usagef("ID must be a number (see ks token ls)")
		}
		if err := c.RevokeToken(id); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Token %d revoked.\n", id)
		return nil
	}
	return usagef("usage: ks token create|ls|revoke")
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func (a *app) cmdAudit(args []string) error {
	fs := a.flags("audit")
	limit := fs.Int("limit", 50, "number of events")
	verify := fs.Bool("verify", false, "check the hash chain of the whole log")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	c, err := a.ownerClient()
	if err != nil {
		return err
	}
	if *verify {
		ok, msg, err := c.AuditVerify()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("audit log check FAILED: %s", msg)
		}
		fmt.Fprintln(a.stdout, "Audit log hash chain is intact (this cannot detect the newest rows being cut off).")
		return nil
	}
	target := ""
	if len(pos) > 0 {
		target = pos[0]
	}
	events, err := c.Audit(target, *limit)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	for _, e := range events {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.At.Local().Format("2006-01-02 15:04:05"), e.Actor, e.Action, e.Target, e.Source)
	}
	return tw.Flush()
}

func (a *app) cmdTOTP(args []string) error {
	if len(args) != 1 || args[0] != "setup" {
		return usagef("usage: ks totp setup")
	}
	c, err := a.ownerClient()
	if err != nil {
		return err
	}
	pw, err := a.prompt("Login password (to confirm): ")
	if err != nil {
		return err
	}
	uri, err := c.TOTPSetup(pw)
	if err != nil {
		return err
	}
	pr := a.printer()
	pr.title("Add keyshelf to your authenticator app")
	pr.info("In the app choose \"enter a setup key\" and type the key below (time based, 6 digits, 30 s).")
	if u, err := url.Parse(uri); err == nil && u.Query().Get("secret") != "" {
		pr.info("Account: keyshelf")
		pr.box(groupKey(u.Query().Get("secret")))
	}
	pr.info("Or paste this link into an app that accepts otpauth:// links:")
	fmt.Fprintf(a.stdout, "    %s\n\n", uri)
	code, err := a.prompt("Code shown by the app: ")
	if err != nil {
		return err
	}
	if err := c.TOTPConfirm(strings.TrimSpace(code)); err != nil {
		return err
	}
	pr.ok("TOTP enabled; web and network logins now ask for a code")
	return nil
}

// groupKey splits a base32 setup key into groups of four for typing.
func groupKey(k string) string {
	var b strings.Builder
	for i, r := range k {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}
