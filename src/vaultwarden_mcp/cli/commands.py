"""CLI command implementations for Vaultwarden MCP."""

from __future__ import annotations

import asyncio
import json
import logging

import typer

from vaultwarden_mcp.cli.app import app

APP_NAME_UPPERCASE = "VAULTWARDEN_MCP"

logger = logging.getLogger(__name__)


@app.command()
def serve(
    transport: str = typer.Option(
        "stdio",
        "--transport",
        "-t",
        help="Transport to use: 'stdio' (default) or 'http'",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        "-H",
        help="HTTP host (only for --transport http)",
    ),
    port: int = typer.Option(
        8080,
        "--port",
        "-p",
        help="HTTP port (only for --transport http)",
    ),
) -> None:
    """Start the Vaultwarden MCP server.

    By default, the server runs over stdio for integration with MCP clients.
    Use --transport http for a long-running HTTP endpoint.
    """
    if transport == "stdio":
        from vaultwarden_mcp.mcp_server import main as mcp_main
        asyncio.run(mcp_main())
    elif transport == "http":
        from vaultwarden_mcp.mcp_server_http import serve_http
        asyncio.run(serve_http(host=host, port=port))
    else:
        raise typer.BadParameter(f"Unknown transport: {transport}. Use 'stdio' or 'http'.")


@app.command()
def list_tools() -> None:
    """List available MCP tools without starting the server."""
    from vaultwarden_mcp.mcp_server import list_tools as _list_tools
    result = asyncio.run(_list_tools(None, None))
    print(json.dumps([
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.input_schema,
        }
        for t in result.tools
    ], indent=2))


@app.command()
def check_account(
    account: str = typer.Option(
        "default",
        "--account",
        "-a",
        help="Account key to check (e.g. 'jan' or 'openclaw')",
    ),
) -> None:
    """Check account credentials and vault connectivity.

    Attempts to initialize the VaultwardenSession for the given account.
    If credentials are wrong, the credential verification safeguard
    will catch it and report the error.
    """
    from vaultwarden_mcp.mcp_server import _get_or_init_session
    try:
        session = _get_or_init_session(account)
        summary = session.sync()
        print(f"Account '{account}': OK")
        print(f"  Server:  {session.server}")
        print(f"  Email:   {summary.email}")
        print(f"  Ciphers: {summary.cipher_count}")
        print(f"  Unlocked: {session.is_unlocked}")
    except Exception as e:
        print(f"Account '{account}': FAILED")
        print(f"  Error: {e}")


@app.command()
def default() -> None:
    """Default command showing welcome message."""
    typer.echo("Vaultwarden MCP Server")
    typer.echo("Run 'vaultwarden-mcp serve --help' to start the server.")
    typer.echo("Run 'vaultwarden-mcp --help' to see all commands.")
