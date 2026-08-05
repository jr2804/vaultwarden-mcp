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
│  vaultwarden-cli     rmcp (MCP SDK v3)       │
│   (REST API /        ServerHandler            │
│    PBKDF2 keys)      search, get_cipher,      │
│                   ──▶ sync, list_accounts     │
└──────────┬──────────────────┬─────────────────┘
           │ stdio            │ streamable_http
     MCP clients        HTTP clients
```

## Layer Responsibilities

### Rust Binary (`native/`) — Production

| Component | File | Responsibility |
|-----------|------|----------------|
| **CLI** | `main.rs` | Argument parsing (clap), transport selection, server bootstrap |
| **MCP Server** | `mcp.rs` | `ServerHandler` trait: `list_tools()`, `call_tool()`, `get_info()` |
| **Vault Client** | `lib.rs` | REST API client (login, sync, search), crypto (key derivation, cipher decrypt) |

### Python (`tests/`) — Testing Only

| Component | File | Responsibility |
|-----------|------|----------------|
| **Test Harness** | `test_mcp_server.py` | FastMCP `StdioTransport` launches Rust binary, black-box tool testing |
| **Fixtures** | `conftest.py` | Binary builder, environment setup, MCP client session |

## Data Flow

1. **Client connects** → Rust binary via stdio (subprocess) or HTTP
2. **`initialize` handshake** → Server advertises tools (`search`, `get_cipher`, `sync`, `list_accounts`)
3. **Tool call** → Server authenticates to Vaultwarden API → decrypts → returns results
4. **Credential verification** — On login, server:
   - Auth via `client_credentials` grant → access token
   - Sync vault → profile email
   - Derive master key via PBKDF2(password, email, kdf_iterations)
   - Decrypt vault key → CryptoKeys (HMAC-verified)
   - Test decrypt all ciphers (abort on HMAC failure)

## Security Model

- **No plaintext secrets persisted** — all cipher operations decrypt in-memory only
- **Credential verification at connect time** — wrong password or credential
  mismatch caught immediately via HMAC check on symmetric key
- **Per-account sessions** — isolated `VaultwardenSession` per identity, multi-account via session pool
- **Metadata-only in search** — `search` decrypts name + username only; full decrypt requires `get_cipher` by ID

## Dependencies

| Crate | Purpose |
|-------|---------|
| `rmcp` v3.1 | MCP v3.0 protocol implementation (ServerHandler, stdio/HTTP transport) |
| `vaultwarden-cli` | Bitwarden REST API client, PBKDF2 key derivation, AES cipher decryption |
| `clap` | CLI argument parsing |
| `tokio` | Async runtime |
| `serde` / `serde_json` | Serialization for MCP messages |
