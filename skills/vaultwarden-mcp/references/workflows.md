# Workflows

Concrete recipes for the tasks you'll most often perform. Read the section
relevant to the user's request. For raw param schemas, see `tools-reference.md`.

## Account selection — read vs. write differ

The single most common mistake. **`account` is optional for reads, required
for writes.**

- **Read tools** (`search`, `sync`) take an *optional* `account`. Omit it and
  the query fans out across every connected vault — ideal when you don't know
  which account holds an entry.
- **Write tools** (`create_cipher`, `edit_cipher`, `soft_delete_cipher`,
  `delete_cipher`, `restore_cipher`) **require** an explicit `account`. A write
  must target exactly one vault; the server refuses to guess.
- **`get_cipher`** also requires `account` (cipher ids are per-vault).

If a user asks to "change my GitHub password" and you don't know which account
holds it: `search` (no account) first, read the `account` the result came back
under, then call `edit_cipher` with that account. When in doubt about the
label, call `list_accounts`.

## The standard lookup flow: search → get_cipher

`search` is cheap and returns metadata for many entries (id, name, username,
uri) but **not the password**. Once you have the id, call `get_cipher` for the
full entry including password, TOTP, notes, and fields.

The split is deliberate — a casual "what logins do I have for github?" should
not dump plaintext secrets into context.

```text
search { query: "github" }          → [ { id, name, username, uri, password: null, ... } ]
get_cipher { cipher_id, account }   → { ..., password, totp, notes, fields }
```

## create_cipher — login vs. note

**Login** (a credential with username/password):

```json
{
  "account": "personal",
  "cipher_type": "login",
  "name": "ACME Corp login",
  "username": "jane@example.com",
  "password": "correct horse battery staple",
  "uri": "https://acme.example.com",
  "totp": "JBSWY3DPEHPK3PXP"
}
```

**Secure note** (a secret that isn't a login — recovery phrase, API key blob):

```json
{
  "account": "personal",
  "cipher_type": "note",
  "name": "Wifi password",
  "notes": "Network: HomeNet | Password: hunter2"
}
```

**With custom fields** (PINs, security questions). Use `"field_type": "hidden"`
for secret field values so they're masked in the Bitwarden UI:

```json
{
  "account": "work",
  "cipher_type": "login",
  "name": "Banking portal",
  "username": "jdoe",
  "password": "...",
  "fields": [
    { "name": "PIN", "value": "4242", "field_type": "hidden" },
    { "name": "Security question", "value": "Fluffy" }
  ]
}
```

The tool returns the created entry decrypted (with its new `id`), so you can
confirm what landed.

## edit_cipher overlay semantics (read carefully)

`edit_cipher` is a **partial overlay**: send only the fields you want to change;
anything you omit stays exactly as it was. Under the hood it's a full PUT
replace, but the server fetches the current entry and merges your changes so
you never resend unchanged fields.

Each field has three possible states expressed through JSON:

| Your intent | JSON to send |
|-------------|--------------|
| Leave the field unchanged | **omit the key entirely** |
| Set the field to a new value | `"password": "newvalue"` |
| **Clear** the field (empty it out) | `"password": null` |

The distinction between "omit" and "`null`" matters. Omitting `username` means
"keep the existing username." Sending `"username": null` means "delete the
username." Agents frequently send `null` when they mean "leave it," which
accidentally wipes the field.

**Change just the password, leave everything else alone:**

```json
{ "account": "personal", "cipher_id": "abc-123", "password": "rotated-value" }
```

**Clear the notes field (set it to empty):**

```json
{ "account": "personal", "cipher_id": "abc-123", "notes": null }
```

`cipher_type` cannot be changed via edit. To change type, create a new entry
and delete the old one.

## Deletion: soft vs. hard

Two delete tools, and the difference is permanent:

- `soft_delete_cipher` → moves the entry to the **trash**. Reversible via
  `restore_cipher`. **This is the safe default** when a user says "delete this"
  unless they explicitly say "permanently" or "forever."
- `delete_cipher` → **permanently destroys** the entry. No undo. Reserve for
  explicit user intent or for cleaning up your own test entries.

After a soft-delete, the entry disappears from `search` results (reads filter
out trashed items). Call `restore_cipher` to bring it back.

## When to call sync

The server keeps a decrypted copy of the vault in memory after startup. Reads
(`search`, `get_cipher`) hit this cache — instant, no network. Call `sync`
**only** when the vault may have changed from another client (web vault, phone
app) since the server started. Writes update the cache immediately, so you
never need `sync` after a write to see your own change.

## Folders: reference by name, auto-created on write

Folders are referenced **by name** — the id↔name mapping is internal and you
almost never need it. Key behaviors:

- `list_folders` returns the folder names in a vault (no `account` fans across
  all accounts).
- `create_cipher` / `edit_cipher` accept an optional `folder` **name**. If the
  folder doesn't exist, it is **auto-created** on the server, so you can store
  a new entry into a folder that doesn't exist yet in one call.
- `edit_cipher`'s `folder` is three-state, like every other field:
  - omit → keep the current folder
  - `"Work"` → move to that folder (auto-creates it if missing)
  - `null` → move to **No Folder**
- `delete_folder` removes the folder; the server moves its entries to **No
  Folder** (password entries are **not** deleted).

Example — put a new entry in a folder:

```json
{ "account": "human", "name": "VPN", "type": "login",
  "username": "me", "password": "s3cret", "folder": "Network" }
```

## Putting it together: a rotation workflow

User: "rotate my GitHub password to this new value."

1. `search { "query": "github" }` → find the entry, note its `id` and which
   `account` it came back under.
2. (Optional) `get_cipher { "cipher_id", "account" }` → confirm it's the right
   GitHub entry before mutating.
3. `edit_cipher { "account", "cipher_id", "password": "new-value" }` → returns
   the updated entry; verify the password changed.
4. Confirm to the user. Show name + username; don't echo the password unless
   they ask.

## Common mistakes to avoid

1. **`null` to clear vs. omit to keep.** In `edit_cipher`, omit the key to
   preserve the field; send `null` to clear it.
2. **Forgetting `account` on writes.** Writes require it. Search first (read
   tools accept no account) if you don't know the label.
3. **Expecting the password from `search`.** It's `null` by design — use
   `get_cipher`.
4. **`delete_cipher` when the user said "delete."** Default to
   `soft_delete_cipher`. Only use the permanent delete when the user is
   explicit.
5. **Calling `sync` after every write.** Writes refresh the cache — `sync` is
   only for externally-driven changes.
6. **Editing `cipher_type`.** Fixed per entry. Create new + delete old instead.
