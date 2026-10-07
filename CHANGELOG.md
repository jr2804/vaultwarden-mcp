# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Changed

- Startup messages (`--print-config` dump, HTTP `Listening on…` banner) now go
  through the `tracing` crate instead of `println!`, respecting `RUST_LOG`
  (default level: `info`). See the "Log level" section in `docs/configuration.md`.

## 2026.8.0 (2026-08-05)

### Added

- Pure Rust MCP server using `rmcp` (modelcontextprotocol/rust-sdk) v3.1.0
- MCP v3.0 (2026-07-28) protocol compliance
- 4 MCP tools: `search`, `get_cipher`, `sync`, `list_accounts`
- Multi-account support via environment variables
- Stdio and Streamable HTTP transports
- Credential verification with HMAC-checked key derivation
- Prebuilt binary releases for Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64)
- Claude Desktop / AI IDE configuration support

### Changed

- **Breaking**: Complete rewrite from Python/PyO3 to pure Rust
- **Breaking**: Python MCP server removed (FastMCP retained as test client only)
- **Breaking**: `pyproject.toml` now serves only the Python test suite

### Security

- Vault password verified at connect time via HMAC check on symmetric key decryption
- No plaintext secrets persisted anywhere
