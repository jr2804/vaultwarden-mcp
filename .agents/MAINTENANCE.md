# AGENTS.md — MAINTENANCE

How to keep `.agents/` files current.

## Process

1. When a rule changes, update the owning file — never another file.
2. When adding a new `.agents/` file, add it to the index table in root [AGENTS.md](../AGENTS.md).
3. After any `.agents/` change, check the index for stale entries.
4. When adding a new durable subtree boundary, create a subtree `AGENTS.md`
   and add it to the root **Child DOX Index**.

## Principles

- **Single source of truth.** Each rule lives in exactly one file. The tier,
  pointer, rationale, and size rules are in **DOX authoring**
  ([.agents/POLICIES.md](POLICIES.md)) — consult it on every DOX change.
- **AGENTS.md is an index.** It points to `.agents/` files, does not replace them.
- **Demand-loaded over always-injected.** Move a rule from a subtree `AGENTS.md`
  to `.agents/` only when it applies universally.

## File update triggers

| File | Update when |
| ------ | ------------- |
| [ONBOARDING.md](ONBOARDING.md) | Project structure, tooling, or entry points change |
| [POLICIES.md](POLICIES.md) | Boundaries, priorities, or verification change |
| [FILES.md](FILES.md) | Path constants, config keys, or naming conventions change |
| [HISTORY.md](HISTORY.md) | Notable decision made or resolved |
| [MAINTENANCE.md](MAINTENANCE.md) | Maintenance procedures, triggers, or principles change |

## Subtree AGENTS.md triggers

Create a subtree `AGENTS.md` when a directory gains:

- its own purpose, ownership, or responsibility
- local contracts that would bloat the root file
- specialized workflow (build steps, test patterns, etc.)
- quality checks that don't apply project-wide

Keep it lean. Point to root and `.agents/` files instead of restating their rules.
