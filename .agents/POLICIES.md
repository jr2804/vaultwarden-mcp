# AGENTS.md — POLICIES

Always applicable. Boundaries, priorities, verification, checklist.

## Priorities

1. Correctness
2. Evidence
3. Safety
4. Minimal changes
5. Consistency
6. Performance

## Boundaries

- NEVER fabricate paths, commits, APIs, config keys, env vars, test results,
  or benchmark numbers. If you don't know, say so.
- NEVER guess at command names, flags, or paths. Read source or run `--help`.
- NEVER add secrets, API keys, or tokens to files. Use env vars
  (`VAULTWARDEN_*` — see [.agents/FILES.md](FILES.md)).
- NEVER run destructive commands (`rm -rf`, `git reset --hard`,
  `git push --force`) without explicit confirmation.
- NEVER delete or move files without explicit instruction.
- NEVER create temp files in project root. Use `.tmp/` (gitignored).
- NEVER bump MCP spec version past **2026-07-28 (v3.0)** without recording the
  decision in [.agents/HISTORY.md](HISTORY.md).

## Change constraints

- Minimal, surgical edits. Preserve existing style.
- New dependencies need explicit instruction. Right manifest per language
  (`native/Cargo.toml` for Rust, `pyproject.toml` for Python).
- No unrelated refactoring while fixing a bug.
- Update only directly affected tests.
- Production changes in Rust ([native/src/](../native/src/)); Python edits are
  scripting/tooling only (tests, docs) — never production logic.

## Code quality

- **SRP** — one reason to change per module/function.
- **DRY** — extract on the _third_ occurrence (Rule of Three).
- **Redundant code** — remove dead branches, unreachable conditions, unused
  params/imports before finishing.
- **Duplication vs. abstraction** — prefer a little duplication over the
  wrong premature abstraction.
- No new code-quality tooling, patterns, or value-object rules by default.

## Completion checklist

- Change solves the stated problem
- Relevant validation ran (or gaps explicitly stated) — see Verification below
- No unintended side effects introduced
- No secrets added or exposed
- DOX chain updated if contracts/structure/ownership changed

## DOX authoring (keep AGENTS.md lean)

AGENTS.md and `.agents/` files share limited context. Bloat and duplication
are the failure mode — they waste context on every entry to a subtree and
drift apart as rules change.

### Where a rule lives

- Applies to **all code** → `.agents/POLICIES.md` (default).
- Meaningful **only in one subtree** → that subtree's `AGENTS.md`.
- Just helps navigation → parent's Child DOX Index.

### Reference, don't restate

A rule appears in **exactly one file**. Every other file uses a **pointer line**:
`<topic> — see <file>`. Never copy the rule, rationale, or code example.

### Rule first, rationale second, never third

A DOX line is the rule. If a rationale is costly to rediscover, add one
short clause. Never multi-paragraph explanations or ❌/✅ code pairs — those
belong in a skill or a [docs/](../docs/) page.

### Content rules

- **No tree views.** Use `rg --files | tree-cli --fromfile` on demand.
- **No history.** Git log has it. Record only decisions costly to rediscover
  (in [.agents/HISTORY.md](HISTORY.md) with commit refs).
- **No TODO lists.** Use issue trackers or beads.

### Size budget

- `.agents/` files: ≤ **120 lines** (always-injected context).
- Subtree `AGENTS.md`: ≤ **250 lines** (cumulative with every parent).

Exceeding the budget signals the doc is restating instead of pointing. Cut
first; split the subtree only as a last resort.

## Implementation Plans

- Plans, refactoring plans, and design docs go in `.agents/plans/` — NOT under

  version control (gitignored).

- Name descriptively with phase-number prefixes so file order matches

  implementation order, e.g. `01-sub-feature.md`, `02-next-sub-feature.md`.

- NEVER commit plans to git. They are mutable working artifacts.

- Shipped docs (user-facing guides, API references) go in `docs/` and ARE committed.

## Documentation

- When `.agents/HISTORY.md` grows too large, archive older entries to

  `.agents/history/`. Reference them from `.agents/HISTORY.md`.
- Completed plans may be archived to `.agents/history/` for long-term reference.
- `.agents/history/` IS version-controlled (durable decision records).

## Verification

Run the narrowest relevant checks for the changed surface. Full task list:
`mise run --list`. CI gates in
[`.config/mise/conf.d/quality.toml`](../.config/mise/conf.d/quality.toml).

```bash
# Rust (production) — also via `mise run lint`
cargo check --manifest-path native/Cargo.toml
cargo clippy --manifest-path native/Cargo.toml --all-targets --fix --allow-dirty
cargo test  --manifest-path native/Cargo.toml

# Python (structural checks + lint) — also via `mise run lint`
uv run ruff check tests
uv run ruff format --check tests
uv run pytest

# Docs
uv run zensical build --strict
```

## Response format

Concise and specific. No filler, intros, or restated requirements.
Answer direct questions directly.

For review/debugging/analysis: findings with references, conclusion,
approach. Mention caveats.

## Closeout

1. Run verification
2. Report docs intentionally left unchanged and why
