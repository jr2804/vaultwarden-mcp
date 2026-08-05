# AGENTS.md — src/vaultwarden_mcp/

## Purpose

Python test-client package — FastMCP glue used by the black-box test suite.
**Not production code.** Production is the Rust binary under `native/`.

## Ownership

- `src/vaultwarden_mcp/__init__.py` — FastMCP client glue
- `src/vaultwarden_mcp/__about__.py` — `__version__`

## Local Contracts

- Never ship production logic here — Rust owns it.
- Package metadata lives in `pyproject.toml` (name, version, pytest config).

## Work Guidance

- Follow root [AGENTS.md](../../AGENTS.md) + [.agents/POLICIES.md](../../.agents/POLICIES.md).
- Python via uv; lint/format via ruff.

## Verification

```bash
uv run ruff check src/vaultwarden_mcp
uv run ty check src tests
```

## Child DOX Index

None.
