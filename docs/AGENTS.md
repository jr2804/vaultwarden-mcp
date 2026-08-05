# AGENTS.md — docs/

## Purpose

User-facing documentation rendered by Zensical. Public behavior lives here —
AGENTS.md files point to docs, never duplicate them.

## Ownership

- `docs/index.md` — landing page
- `docs/architecture.md` — system design, data flow, security model
- `docs/build.md` — compiling the Rust binary
- `docs/contributing.md` — development workflow, PR guidelines
- Config SPEC (design contract) — [.agents/plans/01-config.md](../.agents/plans/01-config.md)
- `zensical.toml` — site config (nav, theme, plugins)

## Local Contracts

- Docs of record: public behavior is documented here, not in AGENTS.md files.
- Config SPEC is the contract for `native/src/config.rs` — keep in sync.

## Work Guidance

- Follow root [AGENTS.md](../AGENTS.md) + [.agents/POLICIES.md](../.agents/POLICIES.md).
- Docs build via mise task `docs` (`uv run zensical build --strict`).

## Verification

```bash
uv run zensical build --strict
```

## Child DOX Index

None.
