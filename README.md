# keyshelf

A small, self-hosted shelf for the secrets of your projects: URLs, passwords, API keys, tokens and short notes,
in folders, behind one web page, and reachable by your AI coding agents through a scoped token.

**Status: design phase.** Nothing here stores secrets yet. See [SPEC.md](SPEC.md).

## Why
Every new project leaves secrets in another file: an admin password in `~/backups/x`, a key in a `.env`, a URL in
a chat. Agents create them too, and then nobody can find them. keyshelf gives them one place:

- **People** open the web page, browse `folder / project / entry`, copy a value, add or change one.
- **Agents** use the CLI (`ks get`, `ks put`, `ks run`) with a token that can only see the folders it was given.
  A secret goes from keyshelf into a file or an environment variable, never into the agent's chat or logs.
- **Every read is logged**: who (person or agent token) read which entry, and when.

Password managers such as Bitwarden/Vaultwarden are built for people; secret servers such as HashiCorp Vault and
Infisical are built for teams and clusters. keyshelf is one small binary for one person or a few friends, with
agents as first-class users.

## License
Apache-2.0
