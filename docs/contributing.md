# Contributing

## Development Setup

1. **Fork** the repository
2. **Clone** your fork locally
3. **Build** the Rust binary (requires Rust 1.88+):

```bash
cd native
cargo build
```

4. **Run tests** — the test suite is Docker-free and needs no live Vaultwarden
   server:

```bash
cargo test          # Rust tests: unit + Tier 1 crypto round-trip + Tier 2 wiremock integration (native/)
uv sync --extra dev # install Python scripting env (pytest, ruff, zensical)
uv run pytest       # Python structural checks (tests/test_template_validation.py)
```

## Project Structure

```text
vaultwarden-mcp/
├── native/                     # Rust MCP server (production)
│   ├── src/
│   │   ├── main.rs             # CLI entrypoint (clap)
│   │   ├── mcp.rs              # ServerHandler implementation
│   │   ├── config.rs           # TOML config + env-var merge
│   │   └── lib.rs              # Vaultwarden client + crypto
│   ├── tests/                  # Rust tests (Tier 1: crypto, Tier 2: wiremock)
│   └── Cargo.toml
├── tests/                      # Python structural checks (pyproject/Cargo/CI shape)
├── docs/                       # Documentation (Zensical)
├── .config/mise/               # Mise tasks (build, lint, format, test, docs)
└── zensical.toml               # Docs config
```

## Making Changes

1. Create a feature branch from `main`
2. Make your changes
3. Verify the Rust code compiles: `cargo check` in `native/`
4. Run Rust tests: `cargo test` in `native/`
5. Submit a pull request

## Code Style

- **Rust**: Follow `cargo fmt` and `cargo clippy` conventions
- **Python**: Follow `ruff` formatting (line-length 88, target Python 3.13)

## Mise tasks

All build/lint/format/test tasks live in `.config/mise/conf.d/`. Run
`mise run --list` to see them; `mise run all` runs the full quality gate.

## Versioning

CalVer (`YYYY.MM.N`). Version is set in `native/Cargo.toml`:

```toml
[package]
version = "2026.8.1"
```

Git tags matching `2026.*` (e.g. `2026.8.1`) trigger automated binary releases via GitHub Actions.

## Release Process

Releases are fully automated:

1. **Push to `main`** → the `auto-release.yml` workflow bumps the CalVer patch
   version in `native/Cargo.toml` + `Cargo.lock`, commits it, creates the
   `YYYY.M.N` tag, and dispatches `release.yml` to build binaries + publish the
   GitHub release. Nothing to do manually.
2. **Skip a release** → append the magic marker `[skip-release]` to the last
   commit message (e.g. `fix: typo [skip-release]`). The workflow checks the
   head commit of the push and exits early — no bump, no tag, no release.

Manual fallback (still supported):

1. Bump the version in `native/Cargo.toml` (and `native/Cargo.lock`)
2. Commit and push
3. Create and push a matching git tag:

```bash
git tag 2026.8.1
git push origin 2026.8.1
```

GitHub Actions will build binaries for all platforms and create a GitHub Release automatically.
