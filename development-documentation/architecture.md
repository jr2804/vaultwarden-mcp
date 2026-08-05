# Vaultwarden MCP — Architecture

## Overview

A pure-Rust MCP server for Vaultwarden (Bitwarden-compatible password manager) that exposes vault operations as MCP tools. Uses `rmcp` (modelcontextprotocol/rust-sdk) for MCP v3.0 (2026-07-28) compliance and `vaultwarden-cli` for cryptographic operations.

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                   Rust binary                         │
│                     (single exe)                      │
│                                                       │
│  ┌────────────────────────┐   ┌────────────────────┐  │
│  │ vaultwarden-cli        │   │ rmcp (MCP SDK v3)  │  │
│  │  (API client / crypto) │──▶│   ServerHandler     │  │
│  │  - Bitwarden REST API  │   │                     │  │
│  │  - PBKDF2 key der.     │   │  tools/search       │  │
│  │  - AES cipher decrypt  │   │  tools/get_cipher   │  │
│  │  - HMAC verification   │   │  tools/sync         │  │
│  └────────────────────────┘   │  tools/list_accounts│  │
│                             └───────┬──────────────┘  │
│                                      │                │
│                       stdio / streamable_http          │
└──────────────────────────────┼───────────────────────┘
                               │
                  ┌────────────▼───────────────┐
                  │  FastMCP Client             │
                  │  (Python test harness)      │
                  │                             │
                  │  StdioTransport(            │
                  │    command="vaultwarden-mcp"│
                  │    args=["serve","stdio"],  │
                  │    env={...}                │
                  │  )                          │
                  │                             │
                  │  await client.list_tools()  │
                  │  await client.call_tool()   │
                  └─────────────────────────────┘
```

## Layer Responsibilities

### Rust Binary (`native/`) — Production

| Component | File | Responsibility |
|-----------|------|----------------|
| **CLI** | `main.rs` | Argument parsing (clap), transport selection, server bootstrap |
| **MCP Server** | `mcp.rs` | `ServerHandler` trait: `list_tools()`, `call_tool()`, `sync()` |
| **Vaultwarden Client** | `lib.rs` | REST API client (login, sync, search), crypto (key derivation, cipher decrypt) |

### Python (`tests/`) — Testing Only

| Component | File | Responsibility |
|-----------|------|----------------|
| **Test Harness** | `test_server.py` | FastMCP `StdioTransport` launches Rust binary, black-box tool testing |

## Data Flow

1. **Client connects** → Rust binary via stdio (subprocess) or HTTP
2. **`initialize` handshake** → Server advertises tools (`search`, `get_cipher`, `sync`, `list_accounts`)
3. **Tool call** → Server authenticates to Vaultwarden API → decrypts → returns results
4. **Credential verification** — On login, server:
   - Auth via `client_credentials` grant → access token
   - Sync vault → profile email
   - Derive master key via PBKDF2(password, email, kdf_iterations)
   - Decrypt vault key → CryptoKeys
   - Test decrypt one cipher (abort on HMAC failure)

## Security

- **No plaintext secrets saved** — all cipher operations decrypt in-memory only
- **Credential verification at connect time** — wrong password or credential mismatch caught immediately
- **Per-account sessions** — isolated `VaultwardenSession` per identity, multi-account via session pool
- **Metadata-only in search** — `search` decrypts name + username only; full decrypt requires `get_cipher` by ID