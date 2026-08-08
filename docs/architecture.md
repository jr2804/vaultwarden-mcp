# Architecture

## Overview

A pure-Rust MCP server for Vaultwarden (Bitwarden-compatible password manager) that
exposes vault operations as MCP tools. Uses `rmcp` (modelcontextprotocol/rust-sdk)
for MCP v3.0 (2026-07-28) compliance and `vaultwarden-cli` for cryptographic
operations.

## System Diagram

```text
┌──────────────────────────────────────────────┐
│  Rust binary (single exe, no runtime deps)   │
│                                               │
│  vaultwarden-cli        rmcp (MCP SDK v3)     │
│   (REST API read,       ServerHandler          │
│    PBKDF2 keys)         search, get_cipher,    │
│                       ──▶ sync, list_accounts  │
│   local crypto +         + create/edit/delete  │
│   write HTTP client     write tools            │
└──────────┬───────────────────┬─────────────────┘
           │ stdio             │ streamable_http
     MCP clients         HTTP clients
           │
           ▼
  secretspec (secret:// resolution at startup)
```

## Layer Responsibilities

### Rust Binary (`native/`) — Production

| Component | File | Responsibility |
|-----------|------|----------------|
| **CLI** | `main.rs` | Argument parsing (clap), transport selection, server bootstrap |
| **MCP Server** | `mcp.rs` | `ServerHandler` trait: `list_tools()`, `call_tool()`, `get_info()`, write-tool param structs |
| **Vault Client** | `lib.rs` | REST API client (login, sync, search), crypto (key derivation, decrypt), cipher write methods |
| **Field encryption** | `crypto.rs` | Production symmetric encrypt for vault writes (`2.{iv}\|{ct}\|{mac}`, random IV) |
| **Write HTTP client** | `api_write.rs` | POST/PUT/DELETE on `/api/ciphers` (read endpoints come from `vaultwarden-cli`) |
| **Config loader** | `config.rs` | TOML parse, env-var merge, `secret://` resolution |
| **secretspec resolver** | `secrets.rs` | secretspec 0.18 manifest load + `secret://` value lookup |

### Python (`tests/`) — Structural Validation Only

| Component | File | Responsibility |
|-----------|------|----------------|
| **Structural tests** | `test_template_validation.py` | pyproject.toml, Cargo.toml, CI shape (no maturin, CalVer) |

> Runtime behavior (crypto + session + MCP tool calls) is tested in Rust —
> see `native/tests/` (Tier 1: offline crypto round-trip; Tier 2: wiremock
> integration). Both tiers are Docker-free and network-free.

## Data Flow

1. **Startup** → Load `vaultwarden-mcp.toml`, resolve any `secret://` references via secretspec (fail fast if a required secret is missing), merge with env vars
2. **Connect** → One `VaultwardenSession` per account: authenticate (client_credentials) → sync → derive master key → decrypt symmetric key → decrypt all ciphers (abort on HMAC failure)
3. **Client connects** → Rust binary via stdio (subprocess) or HTTP
4. **`initialize` handshake** → Server advertises tools:
   - **Read**: `search`, `get_cipher`, `sync`, `list_accounts`
   - **Write**: `create_cipher`, `edit_cipher`, `soft_delete_cipher`, `delete_cipher`, `restore_cipher`
5. **Read tool call** → decrypts in-memory from the cached sync; `get_cipher` and `search` never re-hit the server
6. **Write tool call** → encrypt each field with the session symmetric key → POST/PUT/DELETE to `/api/ciphers` → splice the returned cipher into the in-memory cache (so the next `search` reflects it immediately)

### Credential verification (step 2 detail)

On login, each `VaultwardenSession`:

- Auth via `client_credentials` grant → access token
- Sync vault → profile email
- Derive master key via PBKDF2(password, email, kdf_iterations)
- Decrypt vault key → `CryptoKeys` (HMAC-verified — wrong password aborts here)
- Test-decrypt all ciphers (abort on HMAC failure)

## Security Model

- **No plaintext secrets persisted** — all cipher operations decrypt in-memory only
- **Credential verification at connect time** — wrong password or credential
  mismatch caught immediately via HMAC check on symmetric key
- **Per-account sessions** — isolated `VaultwardenSession` per identity, multi-account via session pool
- **Metadata-only in search** — `search` decrypts name + username only; full decrypt requires `get_cipher` by ID
- **Secrets never touch disk** — `secret://` references resolve via secretspec at startup into memory; the resolved values are passed straight to the session and never logged (`print-config` redacts them as `***`)
- **Write path mirrors read crypto** — `crypto.rs::encrypt_string` uses the same AES-256-CBC + HMAC-SHA256 envelope the read path decrypts, with a fresh random IV per field; round-trip is verified against the upstream `CryptoKeys::decrypt_to_string` in tests

## Dependencies

| Crate | Purpose |
|-------|---------|
| `rmcp` v3.1 | MCP v3.0 protocol implementation (ServerHandler, stdio/HTTP transport) |
| `vaultwarden-cli` | Bitwarden REST API **read** client, PBKDF2 key derivation, symmetric key decrypt |
| `secretspec` 0.18 | `secret://` resolution (providers: env, dotenv, keyring, bw) |
| `reqwest` | Write-path HTTP client (POST/PUT/DELETE on `/api/ciphers`) |
| `aes` / `cbc` / `hmac` / `sha2` / `base64` | Field encryption for vault writes |
| `clap` | CLI argument parsing |
| `tokio` | Async runtime |
| `serde` / `serde_json` | Serialization for MCP messages |
