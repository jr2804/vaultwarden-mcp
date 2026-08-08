# AGENTS.md — native/

## Purpose

Rust MCP server — the production codebase. Exposes `search`, `get_cipher`,
`sync`, `list_accounts` over MCP v3.0 (2026-07-28) via `rmcp`, with
`vaultwarden-cli` for crypto.

## Ownership

- `native/src/main.rs` — CLI entrypoint (`clap`): `serve` + `print-config`
- `native/src/lib.rs` — `VaultwardenSession`, REST client, crypto
- `native/src/mcp.rs` — `ServerHandler` impl, tool list, `AccountConfig`
- `native/src/config.rs` — TOML config loader + env-var merge + `secret://` URIs
- `native/Cargo.toml` — deps, features (`http` default), `[dev-dependencies]` for tests
- `native/tests/common/mod.rs` — shared test fixtures (key derivation + cipher encryption helpers)
- `native/tests/crypto_roundtrip.rs` — **Tier 1**: offline crypto round-trip (no server, no Docker)
- `native/tests/integration_mock.rs` — **Tier 2**: wiremock end-to-end against mock
  `/identity/connect/token` + `/api/sync` (no Docker, no real Vaultwarden)

## Local Contracts

- MCP spec pinned to **2026-07-28 (v3.0)** via `rmcp` v3.1 — no bump without a
  recorded decision in `.agents/HISTORY.md`.
- No plaintext secrets in code — credentials from `VAULTWARDEN_*` env vars;
  HMAC-verified on connect, wrong password aborts.
- `http` feature is default-on; build stdio-only with `--no-default-features`.
- Config contract: [.agents/plans/01-config.md](../.agents/plans/01-config.md).
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
