"""Vaultwarden MCP server — multi-account vault access.

This MCP server wraps the native PyO3 bindings (:mod:`vaultwarden_mcp._native`)
which provide secure Rust-based crypto (AES-256-CBC + HMAC-SHA256) from
``vaultwarden-cli``.

Multi-account design: each account (server + client_id) gets its own
:class:`VaultwardenSession`. Sessions are stored in a global registry keyed
by an account name, allowing both simultaneous accounts and parallel server
instances.
"""

from __future__ import annotations

import os
import asyncio
import logging
from typing import Any

import mcp_types as types
from mcp.server import Server, NotificationOptions
from mcp.server.stdio import stdio_server

from vaultwarden_mcp._native import VaultwardenSession

logger = logging.getLogger(__name__)

# ── Account registry ────────────────────────────────────────────────
# Each account key maps to a VaultwardenSession (cached after init).
# This allows multiple accounts (e.g. jan@reimes.de and openclaw@reimes.ws)
# to coexist, and also supports running parallel MCP server instances
# by setting different VAULTWARDEN_ACCOUNT env vars.
_accounts: dict[str, VaultwardenSession] = {}


def _resolve_account(account: str | None) -> str:
    """Resolve the account name from arg or env, defaulting to the primary."""
    if account:
        return account
    env_account = os.environ.get("VAULTWARDEN_ACCOUNT")
    if env_account:
        return env_account
    return "default"


def _get_credentials(account: str) -> tuple[str, str, str, str, bool]:
    """Load credentials for an account from environment.

    Returns: (server, client_id, client_secret, master_password, allow_http)

    Credentials are resolved from environment variables named
    ``VAULTWARDEN_{ACCOUNT}_*`` where {ACCOUNT} is the upper-cased account name.
    """
    env_prefix = account.upper()

    server = os.environ.get(
        f"VAULTWARDEN_{env_prefix}_SERVER",
        os.environ.get("VAULTWARDEN_SERVER", ""),
    )
    client_id = os.environ.get(
        f"VAULTWARDEN_{env_prefix}_CLIENT_ID",
        os.environ.get("VAULTWARDEN_CLIENT_ID", ""),
    )
    client_secret = os.environ.get(
        f"VAULTWARDEN_{env_prefix}_CLIENT_SECRET",
        os.environ.get("VAULTWARDEN_CLIENT_SECRET", ""),
    )
    master_password = os.environ.get(
        f"VAULTWARDEN_{env_prefix}_PASSWORD",
        os.environ.get("VAULTWARDEN_PASSWORD", ""),
    )
    allow_http = os.environ.get("VAULTWARDEN_ALLOW_HTTP", "0") == "1"

    return server, client_id, client_secret, master_password, allow_http


def _get_or_init_session(account: str) -> VaultwardenSession:
    """Get or lazily initialize the session for an account.

    Credential verification runs at construction (in Rust), so if
    credentials are wrong the session init fails immediately.
    The cached session holds decrypted vault keys in memory only.
    """
    if account not in _accounts:
        server, client_id, client_secret, master_password, allow_http = _get_credentials(account)
        if not server or not client_id or not client_secret or not master_password:
            raise ValueError(
                f"Vaultwarden credentials not configured for account '{account}'. "
                f"Set VAULTWARDEN_{account.upper()}_SERVER, _CLIENT_ID, "
                f"_CLIENT_SECRET, and _PASSWORD environment variables."
            )
        session = VaultwardenSession(
            server=server,
            client_id=client_id,
            client_secret=client_secret,
            master_password=master_password,
            allow_http=allow_http,
        )
        _accounts[account] = session

    return _accounts[account]


# ── Handler functions ───────────────────────────────────────────────

async def list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
    """List available MCP tools."""
    tools: list[types.Tool] = [
        types.Tool(
            name="search",
            description="Search cipher entries by name or URI across a Vaultwarden vault. "
            "Returns metadata only (entry ID, name, username) — no secrets are exposed.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search term to match against cipher names and URIs.",
                    },
                    "account": {
                        "type": "string",
                        "description": "Account key (e.g. 'jan' or 'openclaw'). "
                        "Defaults to VAULTWARDEN_ACCOUNT env var or 'default'.",
                    },
                },
                "required": ["query"],
            },
        ),
        types.Tool(
            name="get_cipher",
            description="Retrieve a full cipher entry by ID from a Vaultwarden vault. "
            "Returns all decrypted fields including passwords and secrets. "
            "Use 'search' first to find cipher IDs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Cipher ID from a prior search result.",
                    },
                    "account": {
                        "type": "string",
                        "description": "Account key (e.g. 'jan' or 'openclaw'). "
                        "Defaults to VAULTWARDEN_ACCOUNT env var or 'default'.",
                    },
                },
                "required": ["id"],
            },
        ),
        types.Tool(
            name="sync",
            description="Sync the vault and return a summary (email, cipher count).",
            inputSchema={
                "type": "object",
                "properties": {
                    "account": {
                        "type": "string",
                        "description": "Account key (e.g. 'jan' or 'openclaw'). "
                        "Defaults to VAULTWARDEN_ACCOUNT env var or 'default'.",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_accounts",
            description="List all configured accounts and their sync status.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]
    return types.ListToolsResult(tools=tools)


def _handle_error(e: Exception, detail: str) -> list[types.ContentBlock]:
    """Convert an exception into MCP error content blocks."""
    msg = f"{detail}: {e}"
    return [types.TextContent(type="text", text=msg)]


async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    """Handle MCP tool calls.

    Each call resolves the account (from arg or env), lazily initializes
    the session (with credential verification), then dispatches to the
    appropriate native method.
    """
    name = params.name
    arguments = params.arguments or {}

    try:
        if name == "search":
            query = arguments.get("query")
            if not query:
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text="Error: 'query' parameter is required.")],
                    is_error=True,
                )
            account = _resolve_account(arguments.get("account"))
            session = _get_or_init_session(account)
            results = session.search(query)
            entries = [
                {
                    "id": e.id,
                    "type": e.cipher_type,
                    "name": e.name,
                    "username": e.username,
                }
                for e in results
            ]
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(entries))],
            )

        elif name == "get_cipher":
            cipher_id = arguments.get("id")
            if not cipher_id:
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text="Error: 'id' parameter is required.")],
                    is_error=True,
                )
            account = _resolve_account(arguments.get("account"))
            session = _get_or_init_session(account)
            entry = session.get_cipher(cipher_id)
            data = {
                "id": entry.id,
                "type": entry.cipher_type,
                "name": entry.name,
                "username": entry.username,
                "password": entry.password,
                "uri": entry.uri,
                "notes": entry.notes,
                "fields": entry.fields,
                "ssh_public_key": entry.ssh_public_key,
                "ssh_private_key": entry.ssh_private_key,
                "ssh_fingerprint": entry.ssh_fingerprint,
            }
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(data))],
            )

        elif name == "sync":
            account = _resolve_account(arguments.get("account"))
            session = _get_or_init_session(account)
            summary = session.sync()
            data = {
                "email": summary.email,
                "cipher_count": summary.cipher_count,
                "account": account,
            }
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(data))],
            )

        elif name == "list_accounts":
            accounts = {}
            for acc in list(_accounts.keys()):
                try:
                    session = _accounts[acc]
                    summary = session.sync()
                    accounts[acc] = {
                        "email": summary.email,
                        "cipher_count": summary.cipher_count,
                    }
                except Exception as e:
                    accounts[acc] = {"error": str(e)}
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(accounts))],
            )

        else:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"Unknown tool: {name}")],
                is_error=True,
            )

    except ValueError as e:
        # Credential/configuration errors
        return types.CallToolResult(
            content=_handle_error(e, "Configuration error"),
            is_error=True,
        )
    except RuntimeError as e:
        # Crypto failures (wrong password, HMAC mismatch, etc.)
        return types.CallToolResult(
            content=_handle_error(e, "Vault operation failed"),
            is_error=True,
        )
    except Exception as e:
        logger.exception("Unhandled error in MCP tool call")
        return types.CallToolResult(
            content=_handle_error(e, "Unexpected error"),
            is_error=True,
        )


# ── MCP server ──────────────────────────────────────────────────────

server = Server(
    "vaultwarden-mcp",
    version="0.1.0",
    on_list_tools=list_tools,
    on_call_tool=call_tool,
)


async def main() -> None:
    """Run the MCP server over stdio."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(
                notification_options=NotificationOptions(),
                experimental_capabilities=None,
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
