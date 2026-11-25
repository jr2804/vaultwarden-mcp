# AGENTS.md — native-toolchain/

## Purpose

OS-specific mise fragments for the Rust server's native compiler toolchain and
Rust targets.

## Ownership

- `mise.linux.toml` — Linux GCC and GNU binutils
- `mise.windows.toml` — Windows x86_64 GCC, GNU binutils, and Rust GNU target

## Local Contracts

- Keep platform compiler and target declarations in this folder; the base
  `.config/mise/config.toml` stays platform-neutral.
- Use `conda:gcc` and `conda:binutils`; bare `gcc` and `binutils` are absent from
  the mise registry.
- Windows x86_64 installs and defaults Cargo to `x86_64-pc-windows-gnu`.
- Release-target status and build output paths — see [docs/build.md](../../../../docs/build.md).

## Work Guidance

## Verification

```bash
mise config ls
mise ls
```

## Child DOX Index

None.
