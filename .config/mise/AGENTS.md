# AGENTS.md — .config/mise/

## Purpose

Mise task/tooling configuration. All build, lint, format, test, docs, and
MCP tasks live here as fragments — never in `pyproject.toml` scripts.

## Ownership

- `.config/mise/conf.d/*.toml` — one file per concern:
  `default`, `lint`, `format`, `quality`, `docs`, `mcp`, `skills`
- `.config/mise/config.toml` — global mise settings

## Local Contracts

- Add tasks in `conf.d/*.toml`, not in `pyproject.toml` `[project.scripts]`.
- Keep one concern per fragment file.

## Work Guidance

- Follow root [AGENTS.md](../../AGENTS.md) + [.agents/POLICIES.md](../../.agents/POLICIES.md).
- List tasks with `mise run --list`.

## Verification

```bash
mise run --list
```

## Child DOX Index

None.
