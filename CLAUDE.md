# keyshelf: rules for coding agents

- Read SPEC.md first; it is the contract. Change the spec in the same commit when a decision changes.
- Go (1.26), one binary, web UI embedded (`embed`), plain HTML/CSS/JS without a framework or CDN. SQLite via a
  pure-Go driver. Keep dependencies to the list in SPEC.md §3 unless the owner agrees.
- Crypto only through golang.org/x/crypto (argon2, chacha20poly1305) and crypto/rand. No home-made primitives.
- Never put a real secret in code, tests, fixtures, logs, commit messages or issues. Tests generate their own.
- Every API route needs a permission test with an out-of-scope token.
- Public repository: no internal hostnames, IPs, employer names or personal paths in anything committed.
- Commit and push only when the owner asks; releases only with the owner's OK.
