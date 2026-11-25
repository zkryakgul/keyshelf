# Security

## Reporting

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab) on
<https://github.com/zkryakgul/keyshelf>, not in a public issue.

## Threat model (v0.1)

keyshelf protects against:

- **A stolen disk or backup.** Every secret value (and notes marked secret, and the TOTP secret) is encrypted with
  XChaCha20-Poly1305 under a random data key. The data key is stored only wrapped by keys derived with Argon2id
  (64 MiB, t=3) from the unseal passphrase and from a one-time recovery code. Ciphertexts are bound to their
  entry, field and version, so they cannot be moved around in the file.
- **A leaked agent token.** A token sees only its folders, with separate `list` / `read` / `write` rights; tokens
  are stored as SHA-256 hashes, can expire and are revoked at once; every read, write and refusal is audited.
- **Web attacks from other sites.** Host header allow-list (DNS rebinding), strict CSP without inline code,
  `SameSite=Strict` HttpOnly session cookie plus a CSRF header, JSON-only bodies (no form posts), no CORS,
  `no-store` caching, `frame-ancestors 'none'`.
- **Guessing.** Unseal, recovery, login, TOTP and step-up checks run one at a time per transport; a request that
  arrives while another check runs is refused, and after 5 failures each attempt waits 2^(n-5) s (up to 15 min).
- **Other users on the same machine.** The TCP port is reachable by every local user, so it is guarded as above.
  The owner's CLI uses a Unix socket (`$XDG_RUNTIME_DIR/keyshelf/ks.sock`, mode 0600) with its own limits, so
  another user who triggers the TCP lockout cannot keep the owner from unsealing.

keyshelf does **not** protect against:

- **A compromised host while unsealed.** Root, or anything that can read the server's memory, can read the key.
- **Hostile code running as your own Unix user.** It can read the agent token in `~/.config/keyshelf/`, use the
  owner session file while it is valid (15 minutes after `ks login`), and use the owner socket. Token scopes limit
  the damage of a *leaked* token, not of a malicious process with your uid. High-impact owner actions (creating
  tokens, TOTP setup, password and passphrase changes) ask for the password again, which such a process does not
  have, but it can still read values during an owner session: run `ks logout` when done.
- **Metadata.** Folder and entry names, URLs, usernames, tags and plain notes are not encrypted (they are
  searchable), and a token with only `list` sees them.
- **Rollback by someone who can write the database file.** Deleting the newest version of a field brings back the
  previous one; deleting the newest audit rows is not detected (`ks audit --verify` checks the rest of the chain).
- **Clipboard.** The web UI clears the clipboard after 30 s (it may fail if the tab is not focused, and it clears
  whatever is there); `ks get --copy` does not clear it.
- **Lockout of the web login.** Another local user can keep the TCP login and unseal limiters busy; the owner can
  still use the CLI over the socket.

Passphrases and passwords arrive as Go strings and cannot be reliably wiped from memory; keys are wiped on seal on
a best-effort basis. Core dumps are disabled in the systemd unit.

## Review before v0.1.0

A second model (Claude Fable) reviewed the code at commit 5c513b4 before the first release. It found no critical
issue (no scope bypass, XSS, SQL injection or cryptographic misuse). Its findings and what was done:

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | Rate limit bypassed by parallel requests (all 40 concurrent wrong unseals were evaluated); request bodies could queue without bound; failed unseals held the store lock during Argon2 | Fixed: check-and-reserve under one mutex, busy → 429; 4 KiB body cap; KDF runs outside the store lock; unseal while unsealed answers 409 without the KDF |
| 2 | Medium | Behind a TLS reverse proxy on loopback, TOTP was not required and the cookie was not `Secure` | Fixed: `--behind-proxy`, and any non-loopback `--host`, require TOTP; Secure cookie; X-Forwarded-For from loopback used for the audit source; TOTP setup possible over the local socket |
| 3 | Medium | Another local user could keep the owner locked out of unseal and login | Fixed for the CLI: owner-only Unix socket with its own limits. The web login can still be kept busy (documented above) |
| 4 | Medium | Any agent could use the owner session for its whole hour | Mitigated: CLI sessions last 15 minutes; token creation and TOTP setup need the password again; residual risk documented above |
| 5 | Low | `ks run` passed `KEYSHELF_TOKEN` to the child and could not override an existing variable | Fixed |
| 6 | Low | `ks put --url …` wiped secret notes | Fixed |
| 7 | Low | Audit chain never verified; tail truncation undetectable | `ks audit --verify` added; limitation documented |
| – | Hardening | Password change kept other sessions | Fixed: other owner sessions are revoked |
| – | Hardening | Backup briefly created with the default umask | Fixed: `ks init` and `ks backup` set umask 077 |
| – | Hardening | No ceiling on stored Argon2 parameters | Fixed: time ≤ 64, memory ≤ 4 GiB, threads ≤ 64 |
| – | Hardening | `KEYSHELF_URL` could point to plain http on another host | Fixed: refused unless loopback or https |
| – | Hardening | CI tools at `@latest` | Fixed: pinned versions |
| – | Hardening | A `write` token can learn that an out-of-scope ancestor name is taken (409 instead of 403) | Open, minor |
