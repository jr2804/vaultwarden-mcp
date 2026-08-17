# AGENTS.md — native/

## Purpose

Rust MCP server — the production codebase. Exposes **read tools**
(`search`, `get_cipher`, `sync`, `list_accounts`), **write tools**
(`create_cipher`, `edit_cipher`, `soft_delete_cipher`, `delete_cipher`,
`restore_cipher`), and **folder tools** (`list_folders`, `get_folder_id`,
`create_folder`, `edit_folder`, `delete_folder`) over MCP v3.0 (2026-07-28)
via `rmcp`, with
`vaultwarden-cli` for read/crypto-key derivation and a local encrypt path
for writes.

## Ownership

- `native/src/main.rs` — CLI entrypoint (`clap`): `serve` + `print-config`
- `native/src/lib.rs` — `VaultwardenSession`, REST client, crypto, write methods
- `native/src/mcp.rs` — `ServerHandler` impl, tool list, `AccountConfig`, write-tool param structs
- `native/src/config.rs` — TOML config loader + env-var merge; resolves `secret://NAME` URIs via secretspec
- `native/src/secrets.rs` — secretspec 0.18 runtime integration (resolve manifest + look up `secret://` values)
- `native/src/crypto.rs` — production symmetric encrypt (`2.{iv}|{ct}|{mac}`, random IV);
  needed because `vaultwarden-cli`'s `CryptoKeys` exposes decrypt but not encrypt
- `native/src/api_write.rs` — thin write HTTP client (POST/PUT/DELETE on `/api/ciphers`
  and `/api/folders`); exists because `vaultwarden-cli`'s `ApiClient` is read-only
  with private fields
- `native/Cargo.toml` — deps, features (`http` default), `[dev-dependencies]` for tests
- `native/.cargo/config.toml` + `native/scripts/{cc,cxx,ar,ranlib}` — C-toolchain
  shims: system compiler first, `zig cc`/`zig ar` fallback (see `docs/build.md`);
  scoped to `x86_64-unknown-linux-gnu` so CI/musl/MSVC toolchain detection is untouched
- `native/tests/common/mod.rs` — shared test fixtures (key derivation + cipher encryption helpers)
- `native/tests/crypto_roundtrip.rs` — **Tier 1**: offline crypto round-trip (no server, no Docker)
- `native/tests/integration_mock.rs` — **Tier 2**: wiremock end-to-end against mock
  `/identity/connect/token`, `/api/sync`, and `/api/ciphers` write endpoints (no Docker)

## Local Contracts

- MCP spec pinned to **2026-07-28 (v3.0)** via `rmcp` v3.1 — no bump without a
  recorded decision in `.agents/HISTORY.md`.
- No plaintext secrets in code — credentials from `VAULTWARDEN_*` env vars;
  HMAC-verified on connect, wrong password aborts.
- `http` feature is default-on; build stdio-only with `--no-default-features`.
- Config contract: [.agents/plans/01-config.md](../.agents/plans/01-config.md).
- secretspec contract: `secret://NAME` references resolve at startup via the
  secretspec 0.18 runtime (provider via `--secretspec-provider`, default `env`;
  profile via `--secretspec-profile`, default `default`). Built providers:
  `env`, `dotenv:<path>`, `keyring`, `bw`, `age`, `kdbx`. Plaintext passes through; an
  unresolvable reference fails the load with a clear error.
- Write-path contract: [.agents/plans/02-write-and-secretspec.md](../.agents/plans/02-write-and-secretspec.md) —
  Option A (keep `vaultwarden-cli` dep; local encrypt + own write HTTP client).
  v1 supports login + secure-note create/edit; card/identity/ssh are read-only.
  Edit is partial-overlay (`None` = unchanged, `Some(None)` = clear). Hard-delete
  is permanent; soft-delete + restore round-trip via `deletedDate`.
- Folder contract: folders are referenced **by name** in the MCP surface; id↔name
  mapping is internal. `create_cipher`/`edit_cipher` accept an optional `folder`;
  a name that doesn't exist is auto-created via `POST /api/folders` (write-locked).
  `edit_cipher` folder is three-state: omit = keep, `"name"` = move, `null` = move
  to No Folder. Folder list is cached in-session and spliced on writes.
  `delete_folder` relies on server behavior (entries move to No Folder); password
  entries must be deleted explicitly.
- `VaultwardenSession::decrypt_ciphers` / `cipher_to_entry` are `pub` so integration
  tests can exercise the decrypt path against fixtures without a live server.
- Tests are Docker-free and network-free: Tier 1 is pure crypto; Tier 2 uses
  in-process `wiremock`. No real Vaultwarden server binary or image is needed
  (upstream publishes none — see `.agents/` memory).

## Work Guidance

- Follow root [AGENTS.md](../AGENTS.md) + [.agents/POLICIES.md](../.agents/POLICIES.md).
- Rust toolchain via mise; tasks in `.config/mise/conf.d/*.toml`.

## Verification

```bash
cargo check --manifest-path native/Cargo.toml
cargo clippy --manifest-path native/Cargo.toml -- -D warnings
cargo test  --manifest-path native/Cargo.toml
```

## Child DOX Index

None.
