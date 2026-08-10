---
name: vaultwarden-mcp
description: Use when the user wants to access, look up, create, edit, or manage credentials, passwords, secrets, login entries, secure notes, TOTP/2FA codes, or vault items in their Vaultwarden / Bitwarden vault via the vaultwarden-mcp MCP server. Trigger whenever the user mentions passwords, credentials, logins, secrets, vault, "my passwords", retrieving a login, adding a credential, rotating a password in the vault, looking up a TOTP/2FA code, or storing a new login — even if they don't name "vaultwarden" explicitly. Covers both read operations (search, get a credential) and write operations (create, edit, soft-delete, restore, permanently delete entries).
---

# Using vaultwarden-mcp

`vaultwarden-mcp` exposes a Vaultwarden (Bitwarden-compatible) vault to AI
agents as fourteen MCP tools. You don't run the binary — the MCP host does. Your
job is to call the tools with the right arguments. This file is the lean
overview; details live in `references/` and are read on demand.

## The fourteen tools

**Read** (safe, idempotent):

| Tool | Purpose | `account` |
|------|---------|-----------|
| `list_accounts` | list connected vault identities | — |
| `search` | find entries by name/username/URI (metadata only — no password) | optional |
| `get_cipher` | fetch one entry by id (full, including password) | required |
| `sync` | re-pull the vault from the server (refresh cache) | optional |

**Write** (mutate the vault):

| Tool | Purpose | `account` |
|------|---------|-----------|
| `create_cipher` | create a login or secure note | required |
| `edit_cipher` | partial-overlay edit (change only the fields you send) | required |
| `soft_delete_cipher` | move to trash (reversible via restore) | required |
| `restore_cipher` | restore a trashed entry | required |
| `delete_cipher` | permanently destroy (irreversible) | required |

**Folders** (organize entries):

| Tool | Purpose | `account` |
|------|---------|-----------|
| `list_folders` | list folder names in a vault | optional |
| `get_folder_id` | resolve a folder name to its id | required |
| `create_folder` | create a folder | required |
| `edit_folder` | rename a folder | required |
| `delete_folder` | delete a folder (entries move to No Folder) | required |

## The two rules that trip up agents

1. **`account` is optional for reads, required for writes.** A write must
   target one vault. If you don't know the label, search first (reads accept no
   account) and read the `account` from the result — or call `list_accounts`.
2. **`search` returns `password: null` by design.** Use `get_cipher` for the
   secret. The split keeps casual queries from dumping plaintext into context.

## The standard lookup flow

```text
search { query: "github" }          → [ { id, name, username, uri, password: null } ]
get_cipher { cipher_id, account }   → { ..., password, totp, notes, fields }
```

## edit_cipher — the overlay rule (one-line summary)

Omit a field to **keep** it; send `null` to **clear** it; send a value to
**set** it. Don't send `null` when you mean "leave it alone" — that wipes it.

## Deletion default

When a user says "delete," default to `soft_delete_cipher` (reversible). Use
`delete_cipher` (permanent) only when they say "permanently" / "forever", or
when cleaning up your own test entries.

## When to read the references

| Need | Read |
|------|------|
| Exact param names, types, required vs optional, return shapes | `references/tools-reference.md` |
| Worked recipes: create login/note, edit overlay, rotation, delete flow | `references/workflows.md` |
| How to configure the server for an MCP client (Claude Desktop, CLI) | `references/setup.md` |

## Bundled assets & scripts

- `assets/example-mcp-config.json` — complete two-account example (MCP client
  config + the matching `secretspec.toml` + `vaultwarden-mcp.toml`).
- `scripts/roundtrip-test.py` — driver that exercises every write tool against
  a live server; useful for confirming writes work after setup. Run with
  `--help` for usage; secrets must be in the environment.
