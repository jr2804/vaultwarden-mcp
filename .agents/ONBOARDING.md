# AGENTS.md — ONBOARDING

Read this when starting a new session. After first read, only revisit when
project structure or tooling changes significantly.

## Project

MCP server for Vaultwarden (Bitwarden-compatible password manager). Pure Rust
binary exposing `search`, `get_cipher`, `sync`, `list_accounts` over MCP v3.0
(stdio or Streamable HTTP). Full docs at [README.md](../README.md) and
[docs/](../docs/).

## Quick start

```bash
# Build (Rust binary — production) — also via `mise run server-release`
cargo build --release --manifest-path native/Cargo.toml

# Python scripting env (pytest structural checks, ruff, zensical docs)
uv sync --extra dev

# Test — Docker-free, no live server needed
cargo test --manifest-path native/Cargo.toml   # Rust unit + crypto + wiremock tiers
uv run pytest                                   # Python structural checks

# Lint / format
mise run lint
mise run format

# Docs
uv run zensical serve    # http://localhost:8000
```

## CLI surface

```bash
vaultwarden-mcp serve --transport stdio              # default; for Claude Desktop
vaultwarden-mcp serve --transport http --host 127.0.0.1 --port 8080
```

Binary lives at `native/target/release/vaultwarden-mcp` (or `vaultwarden-mcp.exe` on Windows).
The `http` feature is on by default — build stdio-only with
`cargo build --manifest-path native/Cargo.toml --no-default-features`.

## Configuration

Two layers, merged with env vars winning per field:

1. **TOML config** — `--config <path>` flag, or auto-discovered at
   `./vaultwarden-mcp.toml` → `~/.config/vaultwarden-mcp/config.toml`. See
   [`vaultwarden-mcp.toml.example`](../vaultwarden-mcp.toml.example).
2. **Env vars** — single-account mode reads `VAULTWARDEN_{SERVER,CLIENT_ID,CLIENT_SECRET,PASSWORD}`;
   multi-account mode reads `VAULTWARDEN_ACCOUNTS=jan,work` plus per-account
   `VAULTWARDEN_ACCOUNT_<NAME>_*` vars. Full matrix — [.agents/FILES.md](FILES.md).

Secret fields can be referenced via `secret://<name>` URIs (parsed today;
secretspec runtime resolution is the planned follow-up —
[.agents/plans/01-config.md](../.agents/plans/01-config.md)).

```bash
# Show effective config
vaultwarden-mcp print-config --config ./vaultwarden-mcp.toml
```

## Entry points (read these first)

| File | Why |
| ------ | ----- |
| [AGENTS.md](../AGENTS.md) | Root rail — rules + `.agents/` index |
| [.agents/POLICIES.md](POLICIES.md) | Boundaries, priorities, verification |
| [.agents/FILES.md](FILES.md) | Source-of-truth locations, env-var matrix |
| [docs/architecture.md](../docs/architecture.md) | System diagram, data flow, security model |
| [native/src/main.rs](../native/src/main.rs) | CLI entrypoint (`clap`): `serve` + `print-config` subcommands, transport + config selection |
| [native/src/lib.rs](../native/src/lib.rs) | Library root: `VaultwardenSession`, REST client, crypto (PBKDF2, AES decrypt) |
| [native/src/mcp.rs](../native/src/mcp.rs) | `ServerHandler` impl — `search`, `get_cipher`, `sync`, `list_accounts`; `AccountConfig` struct |
| [native/src/config.rs](../native/src/config.rs) | TOML config-file loader + env-var merge + `secret://` URI validation |

## Where to dig deeper

- [docs/](../docs/) — user-facing documentation (Zensical)
- [.agents/HISTORY.md](HISTORY.md) — past decisions and rationale
- Subtree AGENTS.md files — local contracts for each area:
  - [native/AGENTS.md](../native/AGENTS.md) — Rust MCP server
  - [tests/AGENTS.md](../tests/AGENTS.md) — Python structural checks
  - [docs/AGENTS.md](../docs/AGENTS.md) — docs build & content
  - [.config/mise/AGENTS.md](../.config/mise/AGENTS.md) — mise tasks

## Available tools

If MCP/CLI tools are available for this workspace:

- **codegraph** — symbol search, call graphs (start here when navigating Rust)
- **grepai** — find code by intent
- **repowise** — architecture overview, risk, health
- **mise** — runs all build/test/lint tasks (`mise run --list`)
- Any project-specific tools
