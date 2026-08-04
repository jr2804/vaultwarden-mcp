"""Typer CLI app for Vaultwarden MCP."""

from __future__ import annotations

from importlib.metadata import version

import typer

# Version management
def _get_version() -> str:
    """Get application version from package metadata."""
    try:
        return version("vaultwarden_mcp")
    except Exception:
        return "0.0.0"  # Fallback for development mode

app = typer.Typer(
    name="vaultwarden_mcp",
    help="MCP server for accessing Vaultwarden servers with multi-account support",
    add_completion=True,
    no_args_is_help=True,
)

@app.callback(invoke_without_command=True)
def _callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit",
        is_eager=True,
    ),
) -> None:
    """MCP server for accessing Vaultwarden servers with multi-account support"""
    if version:
        typer.echo(_get_version())
        raise typer.Exit()


def main() -> None:
    """Entry point for the CLI application."""
    app()


# Import commands to register them with app
from vaultwarden_mcp.cli import commands  # noqa: E402, F401
