# AGENTS.md — .config/mise/

## Purpose

Mise configuration in `config.toml` and `conf.d/*.toml`: build, lint, format,
test orchestration, and platform-specific native toolchains for the Rust server
and Python scripting environment.

## Local Contracts

- Root `.miserc.toml` enables `auto_env` so mise loads the matching
  `conf.d/native-toolchain/mise.<os>.toml` fragment.
- Native toolchain contracts — see
  [conf.d/native-toolchain/AGENTS.md](conf.d/native-toolchain/AGENTS.md).
- User-facing build behavior and output paths — see [docs/build.md](../../docs/build.md).
- `mise run lint` — ruff (Python) + `cargo clippy --fix` (Rust), both
  auto-fixing safe lints. Clippy runs with `--all-targets --fix --allow-dirty`
  (also runs rustfmt on touched files). Remaining unfixable lints fail the task.
  The 3 pre-existing Rust lints (unused `kdf`, collapsible `if`) are fixed.
- `mise run format` — `cargo fmt` + `ruff format` + `ruff check --select I --fix`.
- `mise run test` — Rust Tier 1+2 + Python structural tests (all Docker-free).

## Verification

```bash
mise config ls
mise ls
mise exec -- cargo check --manifest-path native/Cargo.toml
```

## Child DOX Index

| Path | Owns | Read when |
| ---- | ----- | --------- |
| `conf.d/native-toolchain/AGENTS.md` | OS-specific compiler and Rust target configuration | Touching `conf.d/native-toolchain/**` |
