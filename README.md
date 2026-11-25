# keyshelf

A small, self-hosted shelf for the secrets of your projects: URLs, passwords, API keys, tokens and short notes,
in folders, behind one web page, and reachable by your AI coding agents through a scoped token.

- **People** open the web page, browse `folder / project / entry`, copy a value, add or change one.
- **Agents** use the CLI (`ks get`, `ks put`, `ks run`) with a token that can only see the folders it was given.
  A secret goes from keyshelf into a file or an environment variable, never into the agent's chat or logs.
- **Every read is logged**: who (owner or agent token) read which field, and when.

Password managers such as Bitwarden/Vaultwarden are built for people; secret servers such as HashiCorp Vault and
Infisical are built for teams and clusters. keyshelf is one small binary for one person, with agents as
first-class users. Friends with the same problem run their own copy.

**Status: v0.1.** Single owner, local machine. Read [SECURITY.md](SECURITY.md) for what it protects against and
what it does not.

## Install

Linux or macOS, amd64 or arm64:

```sh
curl -fsSL https://github.com/zkryakgul/keyshelf/releases/latest/download/install.sh | sh
```

The script downloads the latest release, checks it against `SHA256SUMS`, installs `ks` into `~/.local/bin` and,
on Linux, starts it as a systemd user service on `127.0.0.1:7733`. Read it first if you like:
[scripts/install.sh](scripts/install.sh). Options: `KS_VERSION=v0.1.1`, `KS_BIN_DIR=...`, `KS_NO_SERVICE=1`.

By hand: download `ks_<version>_<os>_<arch>.tar.gz` and `SHA256SUMS` from the
[releases](https://github.com/zkryakgul/keyshelf/releases), run `sha256sum -c SHA256SUMS --ignore-missing`
(and optionally `gh attestation verify ks_*.tar.gz -R zkryakgul/keyshelf`), unpack and put `ks` on your PATH.
From a checkout (Go 1.26): `scripts/install.sh --build`.

## Updating

```sh
ks update --check      # is there a newer release?
ks update              # download, verify SHA256SUMS, replace the binary
ks update --restart    # ... and restart the service (it comes back sealed: ks unseal)
```

`ks upgrade` is the same command. Running the install script again also upgrades.

## First run

In **your own terminal** (not through an agent: the recovery code is shown on screen):

```sh
ks init        # choose the unseal passphrase and a different login password; write down the recovery code
ks unseal      # after every restart of the service
ks login       # owner session for 15 minutes (ks logout when done)
ks token create claude --scope work:list,read,write --save   # asks your password again; saves the token to ~/.config/keyshelf
```

Then open <http://127.0.0.1:7733>.

- **Unseal passphrase**: decrypts everything. keyshelf forgets the key on every restart (sealed) until you type
  it again. Nobody else, and no agent, should ever type it.
- **Login password** (and optional TOTP, `ks totp setup`): opens the web UI and owner commands.
- **Recovery code**: shown once at `ks init`; `ks unseal --recovery` uses it to set a new passphrase.

## Everyday use

```sh
ks ls -r                                         # names only, never values
ks put work/acme/db#password                     # asks for the value twice (no echo)
ks put work/acme/db --url https://db.example.org --username admin
ks gen work/acme/api#token --length 40           # generate and store; prints nothing
ks get work/acme/db --to-file ./.db-pass         # file with mode 0600
ks get work/acme/db --copy                       # clipboard
ks run --env DB_PASSWORD=work/acme/db -- ./migrate   # only the child process sees it
ks rm work/acme/db#password                      # earlier versions are kept
```

A reference is `folder/path/entry#field`; the field defaults to `password`. `ks get` refuses to print a value
unless you pass `--reveal`.

Owner commands: `ks token create|ls|revoke`, `ks audit [entry]`, `ks audit --verify`, `ks seal`, `ks totp setup`,
`ks backup DEST`. On the server machine the CLI talks to keyshelf over an owner-only Unix socket
(`$XDG_RUNTIME_DIR/keyshelf/ks.sock`), so nobody else on the machine can lock you out of unsealing.

## Agents

Give each agent (or each kind of work) its own token with the smallest scope that works:

```sh
ks token create claude --scope work:list,read,write --ttl 2160h --save   # saved for every shell of this user
ks token create ci-bot --scope work/acme/ci:read                         # printed once
```

`list` shows names, `read` reveals values, `write` creates and changes. Agents read the token from
`KEYSHELF_TOKEN` or `~/.config/keyshelf/config.json`. [AGENTS.md](AGENTS.md) is the text to give your agents
(for Claude Code, put it in a skill or in `~/.claude/CLAUDE.md`).

## Network use

keyshelf listens on `127.0.0.1` only. To reach it from other devices put it behind TLS
(`ks serve --listen 0.0.0.0:7733 --tls-cert c.pem --tls-key k.pem --host keys.example.org`) or a TLS reverse proxy
(`ks serve --behind-proxy --host keys.example.org`). Plain HTTP on a non-loopback address is refused, and owner
login over the network requires TOTP: set it up first on the machine itself with `ks login` and `ks totp setup`.

## Backups

`ks backup ~/keyshelf-$(date +%F).db` copies the encrypted database while the server runs. It is useless without
the passphrase or the recovery code. To restore, stop the service, put the file at
`~/.local/share/keyshelf/keyshelf.db` (mode 0600), start it and unseal.

## Development

`go test -race ./...` runs everything, including an end-to-end test (start sealed, unseal, write through the CLI,
read through a web session, audit, revoke). Design and decisions: [SPEC.md](SPEC.md). HTTP API:
[docs/openapi.yaml](docs/openapi.yaml).

## License

Apache-2.0
