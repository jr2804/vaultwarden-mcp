# AGENTS.md — tests/

## Purpose

Black-box MCP testing. Two layers:

- **Python** (`tests/`) — FastMCP client drives the Rust binary over stdio,
  asserts MCP protocol/tool behavior. Requires a live vault (credentials via
  `VAULTWARDEN_*` env vars); cannot run without one.
- **Rust** (`native/tests/`) — Docker-free, network-free crypto + integration
  tests. See [native/AGENTS.md](../native/AGENTS.md) for Tier 1 (offline crypto
  round-trip) and Tier 2 (wiremock end-to-end). Run with
  `cargo test --manifest-path native/Cargo.toml`.

## Ownership

- `tests/test_template_validation.py` — structural lint: pyproject.toml,
  Cargo.toml shape, CalVer, CI uses cargo (no maturin)

## Local Contracts

- Pure file assertions — no binary, no vault, no network.
- MCP tool-call behavior is covered by the Rust tiers in
  [`native/tests/`](../native/tests/) (offline crypto + wiremock integration),
  not here.

## Work Guidance

- Follow root [AGENTS.md](../AGENTS.md) + [.agents/POLICIES.md](../.agents/POLICIES.md).
- Run via `uv run pytest` (mise task `quality`).

## Verification

```bash
uv run pytest --cov
```

## Child DOX Index

None.
