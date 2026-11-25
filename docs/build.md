# Build from Source

## Prerequisites

- **Rust 1.88+** — install via [rustup](https://rustup.rs/) or mise
- **Git** — for cloning the repository
- **C compiler** — for compiling native dependencies (gcc/clang)
- **mise** (recommended) — manages the Rust toolchain, C compiler, and platform build defaults

## Clone and Build

```bash
git clone https://github.com/jr2804/vaultwarden-mcp.git
cd vaultwarden-mcp/native
cargo build --release
```

The binary is at `target/release/vaultwarden-mcp`.

## Managed Toolchain

The repository includes mise configuration for Linux and Windows x86_64:

```bash
mise install
mise exec -- cargo build --release --manifest-path native/Cargo.toml
```

`mise install` installs GCC and GNU binutils through mise's conda backend.
On Windows x86_64, it also installs `x86_64-pc-windows-gnu` and sets that as
Cargo's default target. The resulting executable lives at
`native/target/x86_64-pc-windows-gnu/release/vaultwarden-mcp.exe`.

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
| `x86_64-pc-windows-gnu` | Windows x86_64 (mise default) |
| `x86_64-pc-windows-msvc` | Windows x86_64 (release workflow) |

The release workflow still builds the MSVC target; Windows GNU builds still need validation.

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
