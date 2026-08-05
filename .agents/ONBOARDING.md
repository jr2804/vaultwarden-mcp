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
# Build (Rust binary — production)
cargo build --release --manifest-path native/Cargo.toml

# Build (Python test client)
uv sync

# Test (black-box via FastMCP client → Rust binary)
uv run pytest

# Lint / format
uv run ruff check . && uv run ruff format .

# Docs
uv run zensical serve    # http://localhost:8000
```

## Entry points (read these first)

| File | Why |
| ------ | ----- |
| [AGENTS.md](../AGENTS.md) | Root rail — rules + `.agents/` index |
| [.agents/POLICIES.md](POLICIES.md) | Boundaries, priorities, verification |
| [.agents/FILES.md](FILES.md) | Source-of-truth locations |
| [docs/architecture.md](../docs/architecture.md) | System diagram, data flow, security model |
| [native/src/lib.rs](../native/src/lib.rs) | Production entry point (Rust) |
| [native/src/mcp.rs](../native/src/mcp.rs) | `ServerHandler` — list/call tools |

## Where to dig deeper

- [docs/](../docs/) — user-facing documentation (Zensical)
- [.agents/HISTORY.md](HISTORY.md) — past decisions and rationale
- Subtree AGENTS.md files — local contracts for each area:
  - [native/AGENTS.md](../native/AGENTS.md) — Rust MCP server
  - [tests/AGENTS.md](../tests/AGENTS.md) — black-box test client
  - [docs/AGENTS.md](../docs/AGENTS.md) — docs build & content
  - [.config/mise/AGENTS.md](../.config/mise/AGENTS.md) — mise tasks
  - [src/vaultwarden_mcp/AGENTS.md](../src/vaultwarden_mcp/AGENTS.md) — Python glue

## Available tools

If MCP/CLI tools are available for this workspace:

- **codegraph** — symbol search, call graphs (start here when navigating Rust)
- **grepai** — find code by intent
- **repowise** — architecture overview, risk, health
- **mise** — runs all build/test/lint tasks (`mise run --list`)
- Any project-specific tools
