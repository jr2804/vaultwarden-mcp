# Vaultwarden MCP

MCP server for [Vaultwarden](https://github.com/dani-garcia/vaultwarden) — search, read, and sync
vault entries via the Model Context Protocol.

**Pure Rust binary** using [modelcontextprotocol/rust-sdk](https://github.com/modelcontextprotocol/rust-sdk)
(MCP v3.0, 2026-07-28 spec). Multi-account support. Stdio and Streamable HTTP transports.

## Features

- 🔐 **Vault search** — find credentials by name, URI, or username
- 📋 **Cipher read** — retrieve full credential details by ID
- 🔄 **Vault sync** — refresh cipher cache from Vaultwarden server
- 👥 **Multi-account** — connect to multiple vaults simultaneously
- 🛡️ **Credential verification** — HMAC-checked master key derivation on connect (wrong password caught immediately)
- 📡 **MCP v3.0** — compliant with the 2026-07-28 protocol spec
- 🚀 **Single binary** — no runtime dependencies, no Python, no Node.js

## Installation

### Download (recommended)

Download the latest release binary from [GitHub Releases](https://github.com/jr2804/vaultwarden-mcp/releases):

```bash
# Linux (x86_64)
curl -sL https://github.com/jr2804/vaultwarden-mcp/releases/latest/download/vaultwarden-mcp-linux-x86_64 \
  -o vaultwarden-mcp && chmod +x vaultwarden-mcp

# Linux (ARM64)
curl -sL https://github.com/jr2804/vaultwarden-mcp/releases/latest/download/vaultwarden-mcp-linux-aarch64 \
  -o vaultwarden-mcp && chmod +x vaultwarden-mcp

# macOS (Apple Silicon)
curl -sL https://github.com/jr2804/vaultwarden-mcp/releases/latest/download/vaultwarden-mcp-macos-aarch64 \
  -o vaultwarden-mcp && chmod +x vaultwarden-mcp

# Windows (PowerShell)
$url = "https://github.com/jr2804/vaultwarden-mcp/releases/latest/download/vaultwarden-mcp-windows-x86_64.exe"
Invoke-WebRequest -Uri $url -OutFile vaultwarden-mcp.exe
```

??? tip "Build from source"

```text
Requires Rust 1.88+. See the [Build guide](build.md) for instructions.
```

## Configuration

Set environment variables to connect to your Vaultwarden server:

```bash
export VAULTWARDEN_SERVER="https://vault.example.com"
export VAULTWARDEN_CLIENT_ID="your-client-id"
export VAULTWARDEN_CLIENT_SECRET="your-client-secret"
export VAULTWARDEN_PASSWORD="your-vault-password"
export VAULTWARDEN_ACCOUNT_NAME="my-vault"           # optional, defaults to "default"
export VAULTWARDEN_ALLOW_HTTP="true"                  # only for http:// servers
```

### Multi-account

For multiple vaults, set `VAULTWARDEN_ACCOUNTS` as a comma-separated list and prefix per-account vars:

```bash
export VAULTWARDEN_ACCOUNTS="personal,work"

# Personal vault
export VAULTWARDEN_ACCOUNT_PERSONAL_SERVER="https://personal-vault.example.com"
export VAULTWARDEN_ACCOUNT_PERSONAL_CLIENT_ID="..."
export VAULTWARDEN_ACCOUNT_PERSONAL_CLIENT_SECRET="..."
export VAULTWARDEN_ACCOUNT_PERSONAL_PASSWORD="..."

# Work vault
export VAULTWARDEN_ACCOUNT_WORK_SERVER="https://work-vault.example.com"
export VAULTWARDEN_ACCOUNT_WORK_CLIENT_ID="..."
export VAULTWARDEN_ACCOUNT_WORK_CLIENT_SECRET="..."
export VAULTWARDEN_ACCOUNT_WORK_PASSWORD="..."
```

## MCP Client Setup

Use [add-mcp](https://github.com/neon-solutions/add-mcp) to configure vaultwarden-mcp for any MCP-compatible agent:

```bash
npx add-mcp /path/to/vaultwarden-mcp --args "serve --transport stdio" \
  --env VAULTWARDEN_SERVER=https://vault.example.com \
  --env VAULTWARDEN_CLIENT_ID="your-client-id" \
  --env VAULTWARDEN_CLIENT_SECRET="your-client-secret" \
  --env VAULTWARDEN_PASSWORD="your-vault-password"
```

`add-mcp` supports Claude Code, Codex, Cursor, OpenCode, VS Code, Gemini CLI, and
[17 more agents](https://github.com/neon-solutions/add-mcp#supported-agents).

## MCP Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `search` | `query`, `account` (optional) | Search vault by name, URI, or username |
| `get_cipher` | `cipher_id`, `account` (optional) | Get full credential details by ID |
| `sync` | `account` (optional) | Refresh cipher cache from server |
| `list_accounts` | — | List all connected vault accounts |

## Usage

```bash
# Stdio transport (for MCP clients)
vaultwarden-mcp serve --transport stdio

# HTTP transport (Streamable HTTP at /mcp)
vaultwarden-mcp serve --transport http --host 127.0.0.1 --port 8080

# Show version
vaultwarden-mcp --version
```

## Security

- **No plaintext secrets stored** — all cipher operations decrypt in-memory only
- **Credential verification on connect** — wrong password or credential mismatch
  caught immediately (HMAC check on symmetric key)
- **Per-account isolation** — separate sessions per vault identity
- **No logging of secrets** — tracing limited to operation metadata

## Documentation

- [Architecture](docs/architecture.md) — system design, data flow, layer responsibilities
- [Build from source](docs/build.md) — compiling the Rust binary
- [Contributing](docs/contributing.md) — development workflow, PR guidelines

## License

MIT — see [LICENSE](LICENSE) for details.
