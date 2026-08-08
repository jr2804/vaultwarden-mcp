# AGENTS.md — tests/

## Purpose

Python structural checks — assert the project layout and config shape
(pyproject.toml, Cargo.toml, CI workflow) are correct. Pure file assertions,
no binary, no vault, no network.

The runtime behavior of the MCP server is tested in Rust — see
[native/AGENTS.md](../native/AGENTS.md) for Tier 1 (offline crypto round-trip)
and Tier 2 (wiremock integration), run with
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
- Run via `uv run pytest` (mise task `test`).

## Verification

```bash
uv run pytest
```

## Child DOX Index

None.
