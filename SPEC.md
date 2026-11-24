# keyshelf: specification (v0.1 draft)

## 1. Goals
1. One place for project secrets of one person or a small group of friends: folders, projects, entries.
2. A web UI that is quick to use: search, copy with one click, reveal on demand, add and edit.
3. Agents (Claude Code, Antigravity, scripts) read and write through a CLI and an HTTP API with **scoped tokens**.
4. Secure by default: encrypted at rest, sealed after restart, nothing in plain text on disk, every access audited.
5. Small: one static Go binary with the web UI embedded, one SQLite file, no external services.

Non-goals for v0.x: browser autofill, mobile apps, SSO, clustering/HA, sharing with strangers.

## 2. Data model
- **Folder**: a tree (e.g. `work/customer-trainings/cloudlab`). Permissions are set on folders and inherited.
- **Entry**: inside a folder. Fields: `name`, `kind` (login, api-key, url, note, file), `url`, `username`,
  any number of **secret fields** (`password`, `token`, `key`...), `notes` (markdown), `tags`, `expires_at`,
  `created_by`, `updated_by`, timestamps. Entries are addressed as `folder/path/entry#field`.
- **Versions**: every change keeps the previous value (encrypted), so a wrong overwrite can be undone.
- **Users**: people, with a password (Argon2id) and TOTP (required for admins).
- **Tokens**: for agents and scripts. Name, owner, folder scopes with `read` / `write`, optional expiry, last use.
  Stored only as a hash; shown once at creation.
- **Audit log**: append-only: actor, action (read value, list, create, update, delete, login, token use), entry, time,
  source IP, and for tokens the token name. Values are never logged.

## 3. Security model
- **Encryption at rest.** A random 256-bit data encryption key (DEK) encrypts every secret field and file with
  XChaCha20-Poly1305 (unique nonce, entry id + field name as associated data). The DEK is wrapped by a key
  encryption key (KEK) derived from the **unseal passphrase** with Argon2id (memory ≥ 64 MiB, salt in the DB).
  Names, folders and notes metadata are stored in plain text in v0.1 (searchable); `notes` marked secret are encrypted.
- **Sealed on start.** After a restart the server holds no key. It serves only the unseal page until the owner
  types the passphrase (or `ks unseal`). Optional: unseal from a file readable only by the service user
  (documented as weaker). Seal again with one click or `ks seal`.
- **Network.** Listens on `127.0.0.1` by default. For other devices: TLS (own cert or a reverse proxy) is required;
  the server refuses non-loopback plain HTTP unless an explicit flag is set.
- **Web.** Session cookie `HttpOnly; Secure; SameSite=Strict`, CSRF token on every change, strict CSP (no inline
  script, no third-party origins), login rate limit and lockout, idle session timeout, values revealed only on
  click and cleared from the clipboard after 30 s.
- **Tokens.** Least privilege: a token sees only its folders. Reading a value is a separate permission from listing
  names (`list`, `read`, `write`). Tokens can be revoked at once; optional expiry; last-use time shown.
- **Agent safety.** The CLI never prints a secret value unless `--reveal` is given. Default ways out:
  `ks get x#password --to-file path` (mode 0600), `ks run --env DB_PASS=x#password -- cmd`, `ks get ... --copy`.
  `ks put x#password --from-file f` / `--generate 32` / from stdin; never as a command-line argument.
- **Backups.** `ks backup` writes the encrypted DB; it is useless without the passphrase. Restore drill documented.
- **Supply chain.** Few dependencies (Go standard library, golang.org/x/crypto, a pure-Go SQLite driver),
  `govulncheck` and `gosec` in CI, reproducible release builds, checksums signed.
- **Threat model (v0.1)**: protects against a stolen disk/backup, a leaked agent token (limited to its folders,
  visible in the audit log), and web attacks from other sites. It does not protect against a compromised host while
  unsealed (root can read memory) — say so in the README.

## 4. Interfaces
- **Web UI**: folder tree on the left, entries in the middle, entry detail on the right; global search (name, url,
  tags); copy buttons per field; audit tab per entry; tokens page; dark and light theme; works on a phone.
- **HTTP API** (`/api/v1`, JSON, `Authorization: Bearer <token>`): folders, entries, fields, versions, tokens, audit,
  seal state. OpenAPI file in the repo.
- **CLI** `ks`: `login`, `ls`, `get`, `put`, `gen`, `run`, `mv`, `rm`, `history`, `token create|ls|revoke`,
  `seal`, `unseal`, `backup`, `import` (from `.env` files and a JSON/CSV export of other managers), `export` (encrypted).
  Config in `~/.config/keyshelf/` (server URL + token, file mode 0600).
- **Agent instructions**: a short `AGENTS.md`/Claude skill text that tells agents how to store a new secret
  (`ks put`), how to fetch one without printing it, and never to write secrets elsewhere.

## 5. Milestones
1. **v0.1**: storage + crypto + seal/unseal, users (password + TOTP), web UI (tree, entries, copy, add/edit,
   search), tokens with folder scopes, audit log, CLI `get/put/ls/gen/run`, Docker image and systemd unit.
2. **v0.2**: versions and restore, import from `.env` / Bitwarden JSON / CSV, expiry reminders, file attachments.
3. **v0.3**: several users with shared folders (friends), per-folder roles, WebAuthn login.

## 6. Quality bar
- Unit tests for crypto (known-answer tests, nonce uniqueness, wrong-key failure) and for permission checks
  (every API route tested with a token outside its scope).
- An end-to-end test: start sealed, unseal, create via CLI, read via web, check the audit log, revoke the token,
  confirm the next call fails.
- A security review by a second model before each release; findings fixed or listed in SECURITY.md.
