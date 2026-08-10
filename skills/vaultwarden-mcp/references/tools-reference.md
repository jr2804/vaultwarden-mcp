# Tools reference

Full param schemas and return shapes for every vaultwarden-mcp tool. Read this
when you need exact field names, which params are required, or what a tool
returns. For when-to-use guidance and workflows, see `workflows.md`.

All tool calls are JSON objects passed as MCP `tools/call` arguments. Field
names are `snake_case`. Values are the JSON types below.

## Read tools

### `list_accounts`

List the vault identities the server is connected to. No arguments.

**Returns:** a JSON array:

```json
[
  { "label": "personal", "server": "https://vault.example.com", "email": "you@example.com" }
]
```

Call this first if you don't know which account labels exist — the `label` is
what you pass as `account` to the other tools.

### `search`

Find entries by case-insensitive substring match on name, username, or URI.

| Param | Type | Required | Notes |
|-------|------|----------|-------|
| `query` | string | yes | matched against name, username, URI |
| `account` | string | no | omit to search across all connected vaults |

**Returns:** a JSON array of entries. **Passwords are `null`** in search
results by design — call `get_cipher` for the secret:

```json
[
  {
    "id": "uuid",
    "type": "login",
    "name": "GitHub",
    "username": "octocat",
    "uri": "https://github.com",
    "password": null,
    "notes": null,
    "totp": null,
    "fields": [],
    "ssh_public_key": null,
    "ssh_private_key": null,
    "ssh_fingerprint": null
  }
]
```

### `get_cipher`

Fetch a single entry by id, with all fields decrypted (including the password).

| Param | Type | Required |
|-------|------|----------|
| `cipher_id` | string | yes |
| `account` | string | yes |

**Returns:** one entry object (same shape as a `search` element, but `password`
/ `totp` / `notes` / `fields` are populated).

### `sync`

Re-pull the vault from the server, refreshing the in-memory cache. Use when the
vault may have changed from another client (web, phone) since the server
started.

| Param | Type | Required |
|-------|------|----------|
| `account` | string | no |

**Returns:** a JSON array of per-account summaries:

```json
[
  { "account": "personal", "email": "you@example.com", "cipher_count": 42 }
]
```

You do **not** need `sync` after a write — write tools refresh the cache
themselves. See `workflows.md` § "When to call sync".

## Write tools

All write tools require an explicit `account` (a write must target one vault).
See SKILL.md § "Account selection".

### `create_cipher`

Create a new login or secure note.

| Param | Type | Required | Notes |
|-------|------|----------|-------|
| `account` | string | yes | target vault label |
| `cipher_type` | string | yes | `"login"` or `"note"` |
| `name` | string | yes | display name |
| `username` | string | no | login only |
| `password` | string | no | login only |
| `uri` | string | no | login only |
| `totp` | string | no | TOTP/2FA secret (login) |
| `notes` | string | no | freeform |
| `fields` | array | no | custom fields, see below |

Each `fields` element:

```json
{ "name": "PIN", "value": "4242", "field_type": "hidden" }
```

`field_type` is `"text"` (default), `"hidden"` (masked in UI — use for secret
field values), `"boolean"`, or `"linked"`.

**Returns:** the created entry (full decrypted shape, including the new `id`).

### `edit_cipher`

Partial-overlay edit. Send only the fields you want to change; omitted fields
are preserved. **Read `workflows.md` § "edit_cipher overlay semantics" before
calling this** — the three-state field model (omit / value / `null`) is subtle.

| Param | Type | Required | Notes |
|-------|------|----------|-------|
| `account` | string | yes | |
| `cipher_id` | string | yes | |
| `name` | string | no | omit=unchanged, `null`=clear |
| `username` | string\|null | no | same overlay rule |
| `password` | string\|null | no | same overlay rule |
| `uri` | string\|null | no | same overlay rule |
| `totp` | string\|null | no | same overlay rule |
| `notes` | string\|null | no | same overlay rule |
| `fields` | array | no | replaces the whole field list when present |

`cipher_type` cannot be changed via edit.

**Returns:** the updated entry (full decrypted shape).

### `soft_delete_cipher`

Move an entry to the trash. Reversible via `restore_cipher`.

| Param | Type | Required |
|-------|------|----------|
| `account` | string | yes |
| `cipher_id` | string | yes |

**Returns:** the entry (with a `deleted` timestamp marker).

### `restore_cipher`

Restore a trashed entry to the active vault.

| Param | Type | Required |
|-------|------|----------|
| `account` | string | yes |
| `cipher_id` | string | yes |

**Returns:** the restored entry.

### `delete_cipher`

**Permanently** destroy an entry. Irreversible.

| Param | Type | Required |
|-------|------|----------|
| `account` | string | yes |
| `cipher_id` | string | yes |

**Returns:**

```json
{ "cipher_id": "...", "deleted": true }
```

## Folder tools

### `list_folders`

List folders in a vault by name. No `account` fans across all accounts.

| Param | Type | Required |
|-------|------|----------|
| `account` | string | no |

**Returns:** an array of `{ account, id, name }`.

### `get_folder_id`

Resolve a folder name to its internal id. Errors if the name doesn't exist.

| Param | Type | Required |
|-------|------|----------|
| `account` | string | yes |
| `name` | string | yes |

**Returns:** `{ folder_id, name }`.

### `create_folder`

Create a folder by name.

| Param | Type | Required |
|-------|------|----------|
| `account` | string | yes |
| `name` | string | yes |

**Returns:** `{ id, name }`.

### `edit_folder`

Rename a folder.

| Param | Type | Required |
|-------|------|----------|
| `account` | string | yes |
| `name` | string | yes |
| `new_name` | string | yes |

**Returns:** `{ id, name }`.

### `delete_folder`

Delete a folder. Vaultwarden moves its entries to **No Folder**; password
entries are not deleted.

| Param | Type | Required |
|-------|------|----------|
| `account` | string | yes |
| `name` | string | yes |

**Returns:** `{ deleted: true }`.
