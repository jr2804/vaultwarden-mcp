# AGENTS.md — tests/

## Purpose

Black-box MCP testing: FastMCP client drives the Rust binary over stdio and
asserts tool-call behavior. No unit tests of Rust internals here.

## Ownership

- `tests/conftest.py` — fixtures: binary builder, env setup, MCP session
- `tests/test_mcp_server.py` — tool call assertions
- `tests/test_template_validation.py` — config template checks

## Local Contracts

- Tests launch the real Rust binary (`native/target/debug/vaultwarden-mcp`);
  override path via `VAULTWARDEN_MCP_BINARY`.
- Credentials come from `VAULTWARDEN_*` env vars — never hard-code secrets.
- No plaintext secrets in fixtures or assertions.

## Work Guidance

- Follow root [AGENTS.md](../AGENTS.md) + [.agents/POLICIES.md](../.agents/POLICIES.md).
- Run via `uv run pytest` (mise task `quality`).

## Verification

```bash
uv run pytest --cov
```

## Child DOX Index

None.
