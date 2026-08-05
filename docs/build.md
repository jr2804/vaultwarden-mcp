# Build from Source

## Prerequisites

- **Rust 1.88+** — install via [rustup](https://rustup.rs/)
- **Git** — for cloning the repository
- **C compiler** — for compiling native dependencies (gcc/clang)

## Clone and Build

```bash
git clone https://github.com/jr2804/vaultwarden-mcp.git
cd vaultwarden-mcp/native
cargo build --release
```

The binary is at `target/release/vaultwarden-mcp`.

## Build Features

| Feature | Description | Default |
|---------|-------------|---------|
| `http` | Streamable HTTP transport (axum server) | ✅ enabled |

To build without HTTP transport:

```bash
cargo build --release --no-default-features
```

## Development Build

```bash
cargo build          # faster, unoptimized, with debug info
cargo check          # type-check only (no binary)
cargo build --release  # optimized, stripped
```

## Cross-Compilation

The project targets are:

| Target | Platform |
|--------|----------|
| `x86_64-unknown-linux-gnu` | Linux x86_64 |
| `aarch64-unknown-linux-gnu` | Linux ARM64 |
| `aarch64-apple-darwin` | macOS Apple Silicon |
| `x86_64-pc-windows-msvc` | Windows x86_64 |

Cross-compilation requires the appropriate Rust target and system linker. For example:

```bash
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

## Binary Size

| Platform | Size (stripped) |
|----------|-----------------|
| Linux x86_64 | ~8 MB |
| Linux ARM64 | ~7 MB |
| macOS aarch64 | ~7 MB |
| Windows x86_64 | ~9 MB |
