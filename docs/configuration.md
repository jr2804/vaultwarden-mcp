# Configuration

`vaultwarden-mcp` is configured two ways — choose one or combine them:

1. **Environment variables** — fastest for a single account, no files to manage.
2. **TOML config file** + **secretspec manifest** — multi-account, and the only
   way to keep secrets out of the process arguments and shell history.

This page covers both, with a worked two-account example at the end.

## Config file lookup

`vaultwarden-mcp --config <path>` sets the config file explicitly. Without it,
the loader checks, in order:

1. `--config <path>` CLI flag
2. `./vaultwarden-mcp.toml` (current directory)
3. `~/.config/vaultwarden-mcp/config.toml`

The first file found wins; later candidates are ignored.

## Environment variables (single account)

| Variable | Meaning |
|----------|---------|
| `VAULTWARDEN_SERVER` | Server URL (e.g. `https://vault.example.com`) |
| `VAULTWARDEN_CLIENT_ID` | OAuth client id |
| `VAULTWARDEN_CLIENT_SECRET` | OAuth client secret |
| `VAULTWARDEN_PASSWORD` | Vault master password |
| `VAULTWARDEN_ACCOUNT_NAME` | Optional label (default `default`) |
| `VAULTWARDEN_ALLOW_HTTP` | `1` / `true` to allow `http://` (dev only) |

Env vars **override** the config file on a per-field basis, so you can keep
non-secret values in the TOML and inject only the secret ones via env.

## Environment variables (multi-account)

List account labels in `VAULTWARDEN_ACCOUNTS=jan,work`, then set per-account
vars for each:

```text
VAULTWARDEN_ACCOUNTS=jan,work
VAULTWARDEN_ACCOUNT_JAN_SERVER=https://vault.jan.example.com
VAULTWARDEN_ACCOUNT_JAN_CLIENT_ID=user.jan
VAULTWARDEN_ACCOUNT_JAN_CLIENT_SECRET=...
VAULTWARDEN_ACCOUNT_JAN_PASSWORD=...
VAULTWARDEN_ACCOUNT_WORK_SERVER=https://vault.work.example.com
...
```

## TOML config + secretspec (recommended for multi-account)

The config file holds non-secret values (servers, client ids, transport). Any
field can instead be a `secret://NAME` reference, resolved at startup by
[secretspec](https://secretspec.dev) — a declarative secret manager with
pluggable providers.

### Why `secret://` instead of plaintext in the TOML?

- The TOML file is safe to commit (it contains no secrets).
- Secrets come from a provider you control: environment variables, a `.env`
  file, the OS keyring, or the Bitwarden CLI itself.
- Secrets are resolved into memory at startup and never logged — `print-config`
  shows them as `***`.

### Built-in secretspec providers

| Provider | `--secretspec-provider` value | Source |
|----------|-------------------------------|--------|
| Environment | `env` (default) | `NAME`-keyed environment variables |
| Dotenv | `dotenv:/path/to/.env` | A `.env` file |
| OS keyring | `keyring` | macOS Keychain / Windows Credential Manager / Linux Secret Service |
| Bitwarden CLI | `bw` | A logged-in `bw` session (see [secretspec bw provider](https://secretspec.dev/providers/bw/)) |

> Other providers (aws, gcp, azure, vault, etc.) exist in secretspec but are
> not compiled into this build to keep the binary small.

### The two files

**`secretspec.toml`** — declares which secret names exist and is found by
walking up from the current directory (override with `SECRETSPEC_MANIFEST`):

```toml
[project]
name = "vaultwarden-mcp"
revision = "1.0"

[profiles.default]
# Declare each secret the config will reference. `required = true` makes
# startup fail with a clear error if it's missing.
VWMCP_HUMAN_CLIENT_SECRET = { description = "OAuth client secret — human account", required = true }
VWMCP_HUMAN_PASSWORD      = { description = "Master password — human account", required = true }
VWMCP_AGENT_CLIENT_SECRET = { description = "OAuth client secret — agent account", required = true }
VWMCP_AGENT_PASSWORD      = { description = "Master password — agent account", required = true }
```

**`vaultwarden-mcp.toml`** — references those names and holds the rest:

```toml
[server]
default_transport = "stdio"
allow_http = false

# Human account — a real person's personal vault.
[[accounts]]
label = "human"
server = "https://vault.example.com"
client_id = "user.human"
client_secret = "secret://VWMCP_HUMAN_CLIENT_SECRET"
password = "secret://VWMCP_HUMAN_PASSWORD"

# Agent account — a service/automation identity with its own vault.
[[accounts]]
label = "agent"
server = "https://vault.example.com"
client_id = "user.agent"
client_secret = "secret://VWMCP_AGENT_CLIENT_SECRET"
password = "secret://VWMCP_AGENT_PASSWORD"
```

### Running it

With the `env` provider (default), export one variable per declared secret:

```bash
export VWMCP_HUMAN_CLIENT_SECRET="..."
export VWMCP_HUMAN_PASSWORD="..."
export VWMCP_AGENT_CLIENT_SECRET="..."
export VWMCP_AGENT_PASSWORD="..."
vaultwarden-mcp serve --transport stdio
```

Or with a custom manifest location:

```bash
vaultwarden-mcp serve --secretspec-manifest /path/to/secretspec.toml
```

Or with a `.env` file:

```bash
vaultwarden-mcp serve --secretspec-provider dotenv:./secrets.env
```

### Verifying without starting the server

`print-config` resolves everything (including `secret://` refs) and logs the
effective config with secrets redacted as `***` — a quick way to confirm your
manifest and provider are wired correctly. Output is emitted through `tracing`
to stderr (see [Log level](#log-level) below); the default `info` level means
the dump appears out of the box.

```bash
vaultwarden-mcp print-config --config ./vaultwarden-mcp.toml
```

```text
2026-10-07T12:00:00.000000Z  INFO  vaultwarden_mcp: vaultwarden-mcp — effective config:
2026-10-07T12:00:00.000001Z  INFO  vaultwarden_mcp:   [human]
2026-10-07T12:00:00.000002Z  INFO  vaultwarden_mcp:     server:        https://vault.example.com
2026-10-07T12:00:00.000003Z  INFO  vaultwarden_mcp:     client_id:     user.human
2026-10-07T12:00:00.000004Z  INFO  vaultwarden_mcp:     client_secret: ***
2026-10-07T12:00:00.000005Z  INFO  vaultwarden_mcp:     password:      ***
2026-10-07T12:00:00.000006Z  INFO  vaultwarden_mcp:     allow_http:    false
2026-10-07T12:00:00.000007Z  INFO  vaultwarden_mcp:   [agent]
2026-10-07T12:00:00.000008Z  INFO  vaultwarden_mcp:     server:        https://vault.example.com
2026-10-07T12:00:00.000009Z  INFO  vaultwarden_mcp:     client_id:     user.agent
2026-10-07T12:00:00.000010Z  INFO  vaultwarden_mcp:     client_secret: ***
2026-10-07T12:00:00.000011Z  INFO  vaultwarden_mcp:     password:      ***
2026-10-07T12:00:00.000012Z  INFO  vaultwarden_mcp:     allow_http:    false
```

To suppress startup/config output (e.g. for scripting), raise the log level:

```bash
RUST_LOG=warn vaultwarden-mcp print-config --config ./vaultwarden-mcp.toml
```

## Log level

All startup and runtime diagnostics — including `print-config` output and the
HTTP `Listening on …` banner — go through the
[`tracing`](https://docs.rs/tracing) crate and respect the `RUST_LOG`
environment variable. When `RUST_LOG` is **unset**, the default is `info`, so
informational messages appear out of the box.

| `RUST_LOG` | Effect |
|------------|--------|
| *(unset)*  | `info` — startup banners, config dump, and listening address are shown |
| `warn`     | `warn` and above only — suppresses `info`-level startup output |
| `debug`    | `debug` and above — includes per-request diagnostics |
| `trace`    | Most verbose — everything |

Per-crate granularity is supported using `target=level` syntax:

```bash
# Only see trace-level messages from vaultwarden-mcp itself
RUST_LOG=vaultwarden_mcp=trace vaultwarden-mcp serve --transport stdio

# Quiet: only warnings and errors, from all crates
RUST_LOG=warn vaultwarden-mcp serve --transport http
```

If a required secret is missing, startup fails fast with the name of the
offending secret:

```text
Error: secretspec resolution is missing required secrets: VWMCP_AGENT_PASSWORD
```

## Field resolution order

For every field in every account, the effective value is chosen as:

1. **Env var** (`VAULTWARDEN_ACCOUNT_<LABEL>_<FIELD>` or `VAULTWARDEN_<FIELD>`) — wins if set
2. **`secret://` resolution** — if the merged value is a `secret://NAME` reference
3. **Config file plaintext** — the literal string in `vaultwarden-mcp.toml`

A `secret://` reference that cannot be resolved (missing manifest, missing
secret, or a `required` secret absent from the provider) fails startup with a
clear error rather than passing the raw `secret://...` string to the server.
