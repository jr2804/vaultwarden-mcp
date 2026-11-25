# AGENTS.md — HISTORY

Recorded decisions with git references. Read when relevant to current task.
Acts as simple long-term memory for the project.

## Format

| Date | Decision | Rationale | Git ref |
|------|----------|-----------|---------|
| YYYY-MM-DD | [description] | [why] | [commit hash/tag] |

## Guidance

- Record decisions that would be costly to rediscover.
- Note false turns and why they were rejected.
- Link to relevant commits.
- Keep entries brief — enough to reconstruct reasoning.

## Entries

| Date | Decision | Rationale | Git ref |
|------|----------|-----------|---------|
| 2026-11-25 | Use mise platform fragments; default Windows x64 to GNU | Conda provides GCC/binutils; release stays MSVC pending GNU validation. | db7b88d |
| 2026-11-25 | Add redacted `print-config` JSON formats | Preserve text output while enabling scripted config inspection. | uncommitted |
| 2026-11-25 | Persist an owner-only session token/key cache | Reuse authentication while retaining password verification and auth invalidation. | uncommitted |
