# AGENTS.md — .config/mise/

## Purpose

Mise task/tooling config fragments in `conf.d/*.toml`: build, lint, format,
test orchestration for both the Rust server and the Python test client.

## Local Contracts

- `mise run lint` — ruff (Python) + `cargo clippy --fix` (Rust), both
  auto-fixing safe lints. Clippy runs with `--all-targets --fix --allow-dirty`
  (also runs rustfmt on touched files). Remaining unfixable lints fail the task.
  The 3 pre-existing Rust lints (unused `kdf`, collapsible `if`) are fixed.
- `mise run format` — `cargo fmt` + `ruff format` + `ruff check --select I --fix`.
- `mise run test` — Rust Tier 1+2 + Python structural tests (all Docker-free).

## Child DOX Index

None.
