# keyshelf: specification (v0.1 draft)

## 1. Goals
1. One place for project secrets of one person: folders, projects, entries. Friends run their own instance.
2. A web UI that is quick to use: search, copy with one click, reveal on demand, add and edit.
3. Agents (Claude Code, Antigravity, scripts) read and write through a CLI and an HTTP API with **scoped tokens**.
4. Secure by default: encrypted at rest, sealed after restart, nothing in plain text on disk, every access audited.
5. Small: one static Go binary with the web UI embedded, one SQLite file, no external services.

Non-goals for v0.x: browser autofill, mobile apps, SSO, clustering/HA, sharing with strangers.

## 2. Data model
- **Folder**: a tree (e.g. `work/acme/staging`). Token scopes are set on folders and inherited by subfolders.
- **Entry**: inside a folder. Fields: `name`, `kind` (login, api-key, url, note), `url`, `username`,
  any number of **secret fields** (`password`, `token`, `key`...), `notes` (markdown), `tags`, `expires_at`,
  `created_by`, `updated_by`, timestamps.
- **Addressing**: `folder/path/entry#field`. The last path segment is always the entry; a folder may not hold a
  subfolder and an entry with the same name. Names: `[A-Za-z0-9._-]`, 1–64 chars. `#field` defaults to `password`.
- **Versions**: every change keeps the previous value (encrypted) from v0.1 on; listing and restore come in v0.2.
- **Owner**: one person per instance in v0.1, with a login password (Argon2id) and optional TOTP (required when the
  server listens on a non-loopback address). The schema keeps an `owner_id` column so v0.3 can add users.
- **Tokens**: for agents and scripts. Name, folder scopes, each with permissions from `list` / `read` / `write`,
  optional expiry, last use. Stored only as a SHA-256 hash (tokens are 256-bit random); shown once at creation.
- **Audit log**: append-only, each row hash-chained to the previous one: actor (owner or token name), action
  (read value, list, create, update, delete, login, unseal, seal, token create/revoke), entry, time, source.
  Values are never logged.

## 3. Security model
- **Encryption at rest.** A random 256-bit data encryption key (DEK) encrypts every secret field with
  XChaCha20-Poly1305 (random 192-bit nonce, `entry id | field name | version` as associated data). The DEK is
  wrapped twice: by a key encryption key (KEK) derived from the **unseal passphrase** with Argon2id
  (≥ 64 MiB, parameters and salt stored in the DB so they can be raised later), and by a KEK derived from a
  **recovery code** (random, shown once at `ks init`). Changing the passphrase re-wraps the DEK only.
  Names, folders, URLs, usernames and tags are plain text in v0.1 (searchable); notes marked secret are encrypted.
- **Sealed on start.** After a restart the server holds no key. It serves only the unseal page and the seal-state
  API until the owner types the passphrase (web or `ks unseal`); other calls return `503 sealed`. The unseal
  passphrase is separate from the login password. There is no unseal-from-file in v0.1: agents run as the same
  Unix user as the service, so such a file would be readable by every agent. Seal again with one click or `ks seal`.
- **Network.** Listens on `127.0.0.1:7733` by default. Every request's `Host` header must match the configured
  listen names (DNS-rebinding defence); no CORS. For other devices TLS is required; the server refuses non-loopback
  plain HTTP unless an explicit flag is set.
- **Web.** Session cookie `HttpOnly; SameSite=Strict`, plus `Secure` whenever the page is served over TLS (browsers
  may drop `Secure` cookies on plain `http://127.0.0.1`), CSRF header on every change, strict CSP (no inline
  script or style, no third-party origins), rate limit and lockout for login **and** unseal attempts (other local
  users can reach loopback), sessions end after 1 hour, values revealed only on click and hidden again and
  cleared from the clipboard after 30 s.
- **Tokens.** Least privilege: a token sees only its folders. Reading a value is a separate permission from listing
  names (`list`, `read`, `write`). Tokens can be revoked at once; optional expiry; last-use time shown.
- **Agent safety.** The CLI never prints a secret value unless `--reveal` is given. Default ways out:
  `ks get x#password --to-file path` (mode 0600), `ks run --env DB_PASS=x#password -- cmd`, `ks get ... --copy`.
  `ks put x#password --from-file f` / `--generate 32` / from stdin; never as a command-line argument.
- **Backups.** `ks backup` writes the encrypted DB; it is useless without the passphrase or recovery code.
- **Supply chain.** Few dependencies (Go standard library, golang.org/x/crypto, golang.org/x/term for no-echo
  prompts, modernc.org/sqlite), `govulncheck`, `staticcheck` and `gosec` in CI, the Go toolchain pinned in go.mod,
  reproducible release builds (`-trimpath`, fixed tar metadata), `SHA256SUMS` plus GitHub build-provenance
  attestations (keyless Sigstore signatures, `gh attestation verify`).
- **Threat model (v0.1)**: protects against a stolen disk/backup, a leaked agent token (limited to its folders,
  visible in the audit log), and web attacks from other sites (CSRF, DNS rebinding). It does **not** protect
  against a compromised host while unsealed, nor against a malicious process running as the same Unix user (it can
  read the agents' token file); token scopes limit damage from leaked tokens, not from hostile local code.
  The README says so.

## 4. Interfaces
- **Web UI**: folder tree on the left, entries in the middle, entry detail on the right; global search (name, url,
  tags); copy buttons per field; audit tab per entry; tokens page; dark and light theme; works on a phone.
- **HTTP API** (`/api/v1`, JSON, `Authorization: Bearer <token>`): folders, entries, fields, tokens, audit,
  seal state. OpenAPI file in the repo. Routes are declared in one table in `internal/server`; the permission
  test fails for any route without an out-of-scope case.
  - Public (no token, rate-limited): `GET status`, `POST unseal`, `POST recover`, `POST login`.
  - Any token, checked per folder: `GET folders`, `GET entries?folder=&recursive=&q=` (results filtered to
    `list`), `GET|PUT|DELETE entries/{path}`, `GET|PUT|DELETE values/{path}?field=` (raw bytes,
    `application/octet-stream`, so values never pass through JSON or a shell argument), `POST logout`.
  - Owner session only: `seal`, `tokens` (list/create/revoke), `audit`, `passphrase`, `password`,
    `totp/setup`, `totp/confirm`.
  - JSON bodies must be `application/json` (a cross-site form cannot send that without a preflight, which is
    never answered). Outside a scope the answer is `403` whether or not the entry exists.
- **Owner sessions.** `POST login` returns an owner session: 15 minutes for the CLI (bearer), 1 hour for the web
  UI (cookie). Because agents run as the same Unix user, the CLI keeps it apart from the agent token, and
  high-impact actions (token create, TOTP setup, password and passphrase change) need the password again
  (step-up). A password change revokes every other owner session.
- **Local socket.** `ks serve` also listens on `$XDG_RUNTIME_DIR/keyshelf/ks.sock` (mode 0600, directory 0700). The
  CLI prefers it. It has its own rate limits, so other Unix users who fail on purpose over TCP cannot lock the
  owner out; login over it never needs TOTP, so TOTP can be set up on the machine itself.
- **Credential checks** (unseal, recover, login, TOTP, step-up) run one at a time per transport; a request that
  finds one running gets 429 at once; bodies are capped at 4 KiB; after 5 failures each try waits 2^(n-5) s (max
  15 min). `--behind-proxy` (or any non-loopback `--host`) requires TOTP over TCP and marks cookies Secure.
- **TOTP**: RFC 6238 (HMAC-SHA1, 30 s, 6 digits) on the standard library's `crypto/hmac`; each code is accepted
  once; the secret is sealed with the DEK.
- **CLI** `ks`: v0.1 has `init`, `serve`, `unseal [--recovery]`, `seal`, `login`, `logout`, `status`, `ls`, `get`,
  `put`, `gen`, `run`, `rm`, `token create|ls|revoke`, `audit`, `totp setup`, `backup`. Later: `mv`, `history`,
  `import`, `export`. Config in `~/.config/keyshelf/config.json` (server URL + agent token, mode 0600);
  `KEYSHELF_TOKEN` and `KEYSHELF_URL` override it. The owner session lives apart in `session.json`; data commands
  use the agent token unless `--owner` is given. Prompts for passphrases and passwords read `/dev/tty` without
  echo and fail without a terminal, so an agent cannot be the one typing them.
- **Agent instructions**: a short `AGENTS.md`/Claude skill text that tells agents how to store a new secret
  (`ks put`), how to fetch one without printing it, and never to write secrets elsewhere.

## 5. Milestones
1. **v0.1**: storage + crypto + seal/unseal + recovery code, owner login (password, optional TOTP), web UI (tree,
   entries, copy, add/edit, search), tokens with folder scopes, audit log, CLI (see §4), systemd user unit.
   Built in this order: crypto → store → API + tokens → CLI → web UI → audit → systemd.
2. **v0.2**: versions list and restore, import from `.env` / Bitwarden JSON / CSV, expiry reminders, file
   attachments (`kind: file`), Docker image.
3. **v0.3**: several users with shared folders, per-folder roles, WebAuthn login.

## 6. Quality bar
- Unit tests for crypto (known-answer tests, nonce uniqueness, wrong-key failure) and for permission checks
  (every API route tested with a token outside its scope).
- An end-to-end test: start sealed, unseal, create via CLI, read via web, check the audit log, revoke the token,
  confirm the next call fails.
- A security review by a second model before each release; findings fixed or listed in SECURITY.md.
