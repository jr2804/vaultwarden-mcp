# Global Instructions for Vaultwarden MCP

Applies across all subfolders. More local AGENTS.md files override these defaults when they conflict.

## Priorities

If rules conflict, lower-numbered priority wins:

1. Correctness
2. Evidence
3. Safety
4. Minimal changes
5. Consistency
6. Performance

## Core Contract

- AGENTS.md files are binding work contracts for their subtrees.
- Before editing, read the applicable AGENTS.md chain from repo root to target path.
- The nearest AGENTS.md controls local details. Parent AGENTS.md files provide repo-wide rules.
- A child AGENTS.md may add constraints but must not weaken parent safety or quality rules.

## Boundaries

- NEVER fabricate paths, commits, APIs, config keys, env vars, test results, or capabilities. State gaps explicitly.
- NEVER game verification by weakening assertions, narrowing scope, reducing coverage, or skipping checks to get a pass.
- NEVER expose secrets (tokens, keys, credentials). If encountered, report location and stop.
- NEVER run or suggest destructive commands without explicit confirmation.
- Be direct. Avoid filler and agreement with incorrect premises.

## Read Before Editing (DOX Pass)

1. Read the root AGENTS.md.
2. Identify files and folders you expect to touch.
3. Walk from repository root to each target path.
4. Read every AGENTS.md encountered on each path.
5. If a parent AGENTS.md lists a child AGENTS.md covering the path, read it and continue.
6. Re-read the applicable chain in the current session before edits.

## Uncertainty and Decisions

- Ask before acting when intent is materially ambiguous.
- Ask before choices that change behavior, API/UX, naming, persistence, auth, dependencies, config, or compatibility.
- Prefer one targeted question.
- Proceed without asking only when ambiguity is low-risk and conventions make the choice clear; state the assumption.

## Evidence and Workflow

- Gather evidence proportional to risk.
- For behavioral/API/dependency changes, trace execution path, constraints, and regression surface before editing.
- Prefer the smallest correct change using existing abstractions and style.
- Review/debug/analysis requests do not require code changes once findings are evidenced.
- Use subagents only as a true parallel batch: use 2+ subagents or none.

## Testing and Validation

- Preserve existing tests. Update tests when behavior changes.
- Run the narrowest relevant checks based on risk and changed surface.
- If checks already fail, report that baseline.
- If your change fails validation, make one targeted fix when cause is clear; otherwise stop and report.

## Update After Editing (DOX Closeout)

Every meaningful change requires a DOX pass before completion.

Update the nearest owning AGENTS.md when changes affect:

- purpose, scope, ownership, or responsibilities
- durable structure, contracts, workflows, or operating rules
- required inputs, outputs, permissions, constraints, side effects, or artifacts
- user preferences about behavior, communication, process, organization, or quality
- AGENTS.md creation, deletion, move, rename, or child index contents

Also update affected parent and child AGENTS.md files when their contracts or indexes changed.
Remove stale or contradictory text immediately.

## Child Doc Shape

Create a child AGENTS.md when a folder becomes a durable boundary with specific purpose, contracts, workflow, or quality checks.

Default section order for child docs:

1. Purpose
2. Ownership
3. Local Contracts
4. Work Guidance
5. Verification
6. Child DOX Index

## Child DOX Index

Start lean. Add child AGENTS.md entries incrementally when boundaries become durable.

Top-level boundaries in this template:

- `src/vaultwarden_mcp/` (primary package code)
- `tests/` (test suite)
- `docs/` (documentation)
- `.config/mise/` (task/tooling configuration)

## User Preferences

When a user requests a durable behavior change, record it in the nearest applicable AGENTS.md.

## Project-specific instructions

### Project Structure

Generate project structure with:

```shell
rg --files | tree-cli --fromfile
```