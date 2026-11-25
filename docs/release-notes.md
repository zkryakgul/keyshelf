- **One-line install**: `curl -fsSL https://github.com/zkryakgul/keyshelf/releases/latest/download/install.sh | sh`.
  Checks SHA256SUMS, installs `~/.local/bin/ks` and the systemd user service; running it again upgrades.
- **`ks update`** (alias `ks upgrade`): installs the latest release after checking SHA256SUMS; `--check` only
  reports, `--restart` restarts the service (it comes back sealed).
- The login password needs 8 characters instead of 12. The unseal passphrase still needs 12: it protects the data
  key against offline guessing.
- Clearer output from `ks init`, `ks update` and the installer (colour on terminals, plain when piped or NO_COLOR).

Verify a download: `sha256sum -c SHA256SUMS --ignore-missing` and `gh attestation verify ks_*.tar.gz -R zkryakgul/keyshelf`.
