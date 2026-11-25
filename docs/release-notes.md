First release: one owner, one machine.

- `ks` single binary: server with embedded web UI, and the CLI for the owner and for agents.
- Values encrypted with XChaCha20-Poly1305 under a data key wrapped by Argon2id (passphrase and a one-time
  recovery code); sealed after every restart.
- Agent tokens scoped to folders with separate list / read / write rights; revocable; every read audited in a
  hash-chained log.
- CLI never prints a value unless `--reveal`: `--to-file` (0600), `--copy`, `ks run --env`.
- Web UI: folder tree, search, reveal and copy with 30 s clearing, tokens, audit per entry, dark mode, phone layout;
  strict CSP, CSRF, DNS-rebinding defence.
- systemd user unit and `scripts/install.sh`.

Verify a download: `sha256sum -c SHA256SUMS --ignore-missing` and `gh attestation verify ks_*.tar.gz -R zkryakgul/keyshelf`.
See SECURITY.md for the threat model and the review that preceded this release.
