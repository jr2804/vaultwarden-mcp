# AGENTS.md — FILES

Single source of truth for paths, config keys, and naming conventions.
Kept compact — agents hallucinate less when they know where definitions live.

## Pattern

- One file owns each class of definition (paths, config defaults, enums).
- Import from that file. Never hard-code values in other modules.
- Variables that address files get `_file` suffix; directories get `_dir`.

## Project-specific sources of truth

| What | Where | Key names |
| ------ | ------- | ----------- |
| **Production entry (Rust)** | [`native/src/main.rs`](../native/src/main.rs) | CLI args, transport selection, config-file loader |
| **MCP server handlers** | [`native/src/mcp.rs`](../native/src/mcp.rs) | `ServerHandler` impl, tool list |
| **Vault client + crypto** | [`native/src/lib.rs`](../native/src/lib.rs) | `VaultwardenSession`, key derivation, decrypt |
| **Config file loader** | [`native/src/config.rs`](../native/src/config.rs) | TOML parse, env-var merge, `secret://` URI validation |
| **Rust crate config** | [`native/Cargo.toml`](../native/Cargo.toml) | `rmcp` version, `vaultwarden-cli`, `toml`, features (`http`) |
| **Bundled config file (example)** | [`vaultwarden-mcp.toml.example`](../vaultwarden-mcp.toml.example) | Annotated sample config file |
| **secretspec manifest (scaffold)** | [`secretspec.toml`](../secretspec.toml) | Secret declarations for the upcoming secretspec integration |
| **Config SPEC** | [`.agents/plans/01-config.md`](../.agents/plans/01-config.md) | Design contract for the TOML config + secretspec feature |
| **Python test client** | [`src/vaultwarden_mcp/__init__.py`](../src/vaultwarden_mcp/__init__.py) | FastMCP client glue |
| **Python metadata** | [`src/vaultwarden_mcp/__about__.py`](../src/vaultwarden_mcp/__about__.py) | `__version__` |
| **Test fixtures** | [`tests/conftest.py`](../tests/conftest.py) | Binary builder, env setup, MCP session |
| **Black-box tests** | [`tests/test_mcp_server.py`](../tests/test_mcp_server.py) | Tool call assertions |
| **Package metadata** | [`pyproject.toml`](../pyproject.toml) | `name`, `version`, pytest config |
| **Lint config** | [`ruff.toml`](../ruff.toml), [`ty.toml`](../ty.toml) | line length, target Python |
| **Tooling tasks** | [`.config/mise/conf.d/*.toml`](../.config/mise/) | `default`, `lint`, `format`, `quality`, `docs`, `mcp`, `skills` |
| **Docs site config** | [`zensical.toml`](../zensical.toml) | nav, theme, plugins |
| **User docs** | [`docs/`](../docs/) | `index`, `architecture`, `build`, `contributing` |
| **Release notes** | [`CHANGELOG.md`](../CHANGELOG.md) | version history |
| **Credits script** | [`scripts/gen_credits.py`](../scripts/gen_credits.py) | dependency attribution |

## Environment variables (runtime)

| Var | Purpose | Required |
| ----- | --------- | ---------- |
| `VAULTWARDEN_SERVER` | Vaultwarden base URL | yes |
| `VAULTWARDEN_CLIENT_ID` | OAuth client id | yes |
| `VAULTWARDEN_CLIENT_SECRET` | OAuth client secret | yes |
| `VAULTWARDEN_PASSWORD` | Master password (HMAC-verified on connect) | yes |
| `VAULTWARDEN_ACCOUNT_NAME` | Logical account label | no (default: `default`) |
| `VAULTWARDEN_ALLOW_HTTP` | Permit `http://` servers | no (only for local/test) |
| `VAULTWARDEN_ACCOUNTS` | Comma list of accounts for multi-account mode | no |
| `VAULTWARDEN_ACCOUNT_<NAME>_*` | Per-account overrides for the vars above | conditional |

## Path conventions

| Path | Role |
| ------ | ------ |
| `native/src/` | Rust production modules |
| `src/vaultwarden_mcp/` | Python test-client package only |
| `tests/` | pytest suite (black-box via FastMCP) |
| `docs/` | Zensical-rendered user docs |
| `.config/mise/conf.d/` | Mise task fragments (one file per concern) |
| `.agents/` | DOX markdown (5 tracked files — see [.gitignore](../.gitignore) override) |
| `.tmp/` | Scratch space (gitignored) |

## Cargo / Python feature flags

| Flag | Effect |
|------|--------|
| `http` (Rust, default) | Enables Streamable HTTP transport via `axum` |
| `dev` (Python, optional) | pytest + ruff + zensical install |
