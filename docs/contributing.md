# Contributing

## Development Setup

1. **Fork** the repository
2. **Clone** your fork locally
3. **Build** the Rust binary (requires Rust 1.88+):

```bash
cd native
cargo build
```

4. **Run tests:**

```bash
cargo test          # Rust unit tests (in native/)
uv sync --dev       # install Python test dependencies
uv run pytest       # black-box MCP tests via FastMCP
```

## Project Structure

```text
vaultwarden-mcp/
├── native/                     # Rust MCP server
│   ├── src/
│   │   ├── main.rs             # CLI entrypoint (clap)
│   │   ├── mcp.rs              # ServerHandler implementation
│   │   └── lib.rs              # Vaultwarden client + crypto
│   └── Cargo.toml
├── tests/                      # Python black-box tests (FastMCP)
├── docs/                       # Documentation (Zensical)
├── src/vaultwarden_mcp/        # Python test helpers
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

## Versioning

CalVer (`YYYY.MM.N`). Version is set in `native/Cargo.toml`:

```toml
[package]
version = "2026.8.0"
```

Git tags matching `2026.*` (e.g. `2026.8.1`) trigger automated binary releases via GitHub Actions.

## Release Process

Releases are automated. To cut a new release:

1. Bump the version in `native/Cargo.toml`
2. Commit and push
3. Create and push a matching git tag:

```bash
git tag 2026.8.1
git push origin 2026.8.1
```

GitHub Actions will build binaries for all platforms and create a GitHub Release automatically.
