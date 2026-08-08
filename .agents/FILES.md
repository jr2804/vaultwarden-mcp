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
| **MCP server handlers** | [`native/src/mcp.rs`](../native/src/mcp.rs) | `ServerHandler` impl, read + write tool list |
| **Vault client + crypto** | [`native/src/lib.rs`](../native/src/lib.rs) | `VaultwardenSession`, key derivation, decrypt, write methods |
| **Field encryption** | [`native/src/crypto.rs`](../native/src/crypto.rs) | production symmetric encrypt for vault writes |
| **Write HTTP client** | [`native/src/api_write.rs`](../native/src/api_write.rs) | POST/PUT/DELETE on `/api/ciphers` |
| **secretspec resolver** | [`native/src/secrets.rs`](../native/src/secrets.rs) | secretspec 0.18 manifest load + `secret://` value lookup |
| **Config file loader** | [`native/src/config.rs`](../native/src/config.rs) | TOML parse, env-var merge, `secret://` resolution via secretspec |
| **Rust crate config** | [`native/Cargo.toml`](../native/Cargo.toml) | `rmcp` version, `vaultwarden-cli`, `toml`, features (`http`) |
| **Bundled config file (example)** | [`vaultwarden-mcp.toml.example`](../vaultwarden-mcp.toml.example) | Annotated sample config file |
| **secretspec manifest (scaffold)** | [`secretspec.toml`](../secretspec.toml) | Secret declarations for the upcoming secretspec integration |
| **Config SPEC** | [`.agents/plans/01-config.md`](../.agents/plans/01-config.md) | Design contract for the TOML config + secretspec feature |
| **Python metadata** | [`pyproject.toml`](../pyproject.toml) | `name`, `version`, pytest config, ruff config |
| **Structural tests** | [`tests/test_template_validation.py`](../tests/test_template_validation.py) | pyproject.toml, Cargo.toml, CI shape checks |
| **Rust tests (Tier 1+2)** | [`native/tests/`](../native/tests/) | Offline crypto round-trip + wiremock integration (Docker-free) |
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
| `native/tests/` | Rust tests (Tier 1 crypto round-trip, Tier 2 wiremock) |
| `tests/` | pytest structural checks (pyproject/Cargo/CI shape) |
| `docs/` | Zensical-rendered user docs |
| `.config/mise/conf.d/` | Mise task fragments (one file per concern) |
| `.agents/` | DOX markdown (5 tracked files — see [.gitignore](../.gitignore) override) |
| `.tmp/` | Scratch space (gitignored) |

## Cargo / Python feature flags

| Flag | Effect |
|------|--------|
| `http` (Rust, default) | Enables Streamable HTTP transport via `axum` |
| `dev` (Python, optional) | pytest + ruff + zensical install |
