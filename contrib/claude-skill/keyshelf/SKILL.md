---
name: keyshelf
description: Use whenever a task involves a password, API key, token, admin URL with credentials, kubeconfig secret or any other secret - creating, storing, finding or using one. Secrets live in keyshelf (the ks CLI, http://127.0.0.1:7733), never in files, chat, commit messages or logs.
---

# keyshelf


**Secrets live in keyshelf** (`ks`, server at http://127.0.0.1:7733). Passwords, API keys, tokens, admin URLs and
their credentials go there, and only there.

- **Storing a new secret** (one you generated, received or found): `ks gen folder/project/name#field` to generate
  and store one, or pipe it in: `<command that prints it> | ks put folder/project/name#field --stdin`. Add context
  with `--url`, `--username`, `--kind login|api-key|url|note`, `--tag`. Never put a secret in a command-line
  argument, a file in the repository, a `.env` you commit, a log, a commit message, an issue, or the chat.
- **Using a secret**: `ks run --env NAME=folder/project/name#field -- <command>` or
  `ks get folder/project/name#field --to-file <path>` (mode 0600; delete the file when done). Do not use
  `--reveal`: it prints the value into the transcript.
- **Finding one**: `ks ls -r` or `ks ls -q <text>` (names, URLs, usernames, tags; never values).
- **Folder layout**: `<area>/<project>/<entry>`, e.g. `work/acme/staging-db#password`. Reuse existing folders
  (`ks ls -r`) before inventing new ones.
- **Errors**: `sealed` means the owner must run `ks unseal`; tell them and wait, never ask for the passphrase.
  `403` means your token does not cover that folder; ask the owner, do not look for another token. `401` means the
  token is missing or revoked.
- **Never** read or copy `~/.config/keyshelf/*`, the database file, or another agent's token, and never type the
  owner's passphrase or password anywhere.
