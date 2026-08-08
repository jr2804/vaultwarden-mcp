# Setup & client configuration

vaultwarden-mcp runs as an MCP server that a host (Claude Desktop, an IDE, the
`claude` CLI, etc.) launches and connects to. As an agent you don't run it
yourself — but you may be asked to help configure it. This file covers the
common setup.

## Transport

- **stdio** (default) — the host spawns the binary as a subprocess. Used by
  Claude Desktop and most local MCP clients.
- **streamable-http** — the binary serves HTTP on a port. Used when the host
  connects over the network.

```bash
vaultwarden-mcp serve --transport stdio
vaultwarden-mcp serve --transport http --host 127.0.0.1 --port 8080
```

## Configuration sources (precedence high → low)

1. **Environment variables** — per-field override of the config file. See the
   project docs for the full `VAULTWARDEN_*` list. Single-account default.
2. **TOML config file** (`vaultwarden-mcp.toml`) — multi-account, non-secret
   values + `secret://` references. Located via `--config` or discovered from
   `./` then `~/.config/vaultwarden-mcp/`.
3. **secretspec manifest** (`secretspec.toml`) — resolves `secret://NAME`
   references at startup. Provider chosen by `--secretspec-provider` (default
   `env`).

`secret://` references that can't be resolved fail startup with a clear error.
`print-config` shows the effective config with secrets redacted as `***`.

See `assets/example-mcp-config.json` for a complete two-account example, and
the project's `docs/configuration.md` for the full guide.

## Client config snippets

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "vaultwarden": {
      "command": "/path/to/vaultwarden-mcp",
      "args": ["serve", "--transport", "stdio", "--config", "/path/to/vaultwarden-mcp.toml"],
      "env": {
        "VWMCP_HUMAN_CLIENT_SECRET": "...",
        "VWMCP_HUMAN_PASSWORD": "...",
        "VWMCP_AGENT_CLIENT_SECRET": "...",
        "VWMCP_AGENT_PASSWORD": "..."
      }
    }
  }
}
```

### `claude` CLI (`.mcp.json` in project root)

Same shape as Claude Desktop under the `mcpServers` key.

## Built-in secretspec providers

| Provider | `--secretspec-provider` | Source |
|----------|-------------------------|--------|
| Environment | `env` (default) | `NAME`-keyed env vars |
| Dotenv | `dotenv:/path/to/.env` | a `.env` file |
| OS keyring | `keyring` | macOS Keychain / Windows Credential Manager / Linux Secret Service |
| Bitwarden CLI | `bw` | a logged-in `bw` session |

For details on each provider, see <https://secretspec.dev/providers/>.

## Verifying setup

```bash
# resolves secrets + connects to the server, prints effective config (secrets as ***)
vaultwarden-mcp print-config --config /path/to/vaultwarden-mcp.toml

# interactive MCP over stdio (for manual protocol testing)
vaultwarden-mcp serve --transport stdio
```

`scripts/roundtrip-test.py` is a self-contained driver that exercises every
write tool against a live server — useful for confirming writes work after
setup.
