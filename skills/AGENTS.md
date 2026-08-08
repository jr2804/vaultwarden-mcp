# AGENTS.md — skills/

## Purpose

Repo-bundled agent skills — usage instructions that teach AI agents how to
operate the tools this project provides. Each skill is a self-contained
directory with a `SKILL.md` (lean, triggering + core concepts) plus
progressive-disclosure `references/`, `assets/`, and `scripts/`.

## Ownership

| Skill | Purpose | Read when |
|-------|---------|-----------|
| `vaultwarden-mcp/` | How to call the 9 vaultwarden-mcp MCP tools (read + write) | Working on or using the vault tools |

## Local Contracts

- Skills are **usage skills**, not generative ones — accuracy is verified by
  reading against the live tool schemas (`tools/list` over MCP), not by running
  eval prompt suites.
- Keep `SKILL.md` lean (triggering, core rules, tool index, pointers). Push
  detailed schemas, workflows, and recipes into `references/`.
- Bundled `scripts/` must run standalone (documented via `--help`) and be
  validated against a live server before commit.
- Bundled `assets/` hold reusable config templates; real secret names stay out
  (use `VWMCP_*` test-scoped names in examples).

## Work Guidance

- Follow root [AGENTS.md](../AGENTS.md) + [.agents/POLICIES.md](../.agents/POLICIES.md).
- When the MCP tool surface changes (new tool, renamed param, new return field),
  update the matching skill in the same commit.

## Verification

- Validate a skill's param claims against the live server:

  ```bash
  # from a dir containing a working secretspec.toml + vaultwarden-mcp.toml
  vaultwarden-mcp serve --transport stdio  # then tools/list over the MCP protocol
  ```

- Run bundled scripts end-to-end:

  ```bash
  python skills/vaultwarden-mcp/scripts/roundtrip-test.py \
    --bin native/target/release/vaultwarden-mcp \
    --config <config> --account <label>
  ```

## Child DOX Index

(none)
