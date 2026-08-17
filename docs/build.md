# Build from Source

## Prerequisites

- **Rust 1.88+** — install via [rustup](https://rustup.rs/)
- **Git** — for cloning the repository
- **C compiler** — for compiling native dependencies (gcc/clang). **Optional:**
  on machines without a C toolchain, [Zig](https://ziglang.org/) ≥ 0.13 (e.g.
  via `mise install zig`) is used automatically instead.

## Clone and Build

```bash
git clone https://github.com/jr2804/vaultwarden-mcp.git
cd vaultwarden-mcp/native
cargo build --release
```

The binary is at `target/release/vaultwarden-mcp`.

### C toolchain: system or Zig

The native crate's C dependencies (dbus, ring) need a C compiler and an
archiver. `native/.cargo/config.toml` wires up shims
(`native/scripts/{cc,cxx,ar,ranlib}`) that:

1. **Prefer the system compiler** (`cc`/`gcc`/`clang`, `musl-gcc` for musl
   targets) when one is installed — CI and normal dev machines are unaffected.
2. **Fall back to Zig** (`zig cc` / `zig ar` / `zig ranlib`) when no system
   C toolchain exists, so `cargo build` works with only Rust + Zig installed.

The shims are scoped to the `x86_64-unknown-linux-gnu` target only; cross and
MSVC builds keep using their own toolchain detection.

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
