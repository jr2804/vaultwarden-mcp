"""Pytest configuration and fixtures for vaultwarden-mcp tests.

These tests use FastMCP as a client to black-box test the Rust MCP server.
The Rust binary is launched as a subprocess via stdio transport.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

# Path to the Rust binary (built by cargo, can be overridden)
BINARY_PATH = os.environ.get(
    "VAULTWARDEN_MCP_BINARY",
    str(Path(__file__).parent.parent / "native" / "target" / "debug" / "vaultwarden-mcp"),
)


def build_binary() -> str:
    """Build the Rust binary if it doesn't exist. Returns the binary path."""
    path = Path(BINARY_PATH)
    if not path.exists():
        project_root = Path(__file__).parent.parent / "native"
        subprocess.run(
            ["cargo", "build"],
            cwd=str(project_root),
            check=True,
            capture_output=True,
            text=True,
        )
    return str(path)


@pytest.fixture(scope="session")
def binary_path() -> str:
    """Return the path to the compiled Rust binary, building if necessary."""
    return build_binary()


@pytest.fixture
def mock_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Set up mock environment variables for vaultwarden-mcp.

    These point to a stub server; the real tests would use actual credentials.
    """
    env = os.environ.copy()
    env["VAULTWARDEN_SERVER"] = "https://vaultwarden.example.com"
    env["VAULTWARDEN_CLIENT_ID"] = "test-client-id"
    env["VAULTWARDEN_CLIENT_SECRET"] = "test-client-secret"
    env["VAULTWARDEN_PASSWORD"] = "test-password"
    env["VAULTWARDEN_ACCOUNT_NAME"] = "test-account"
    return env


@pytest.fixture
async def client(binary_path: str, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator:
    """FastMCP client connected to the Rust MCP server via stdio transport.

    The server must connect successfully (i.e., vaultwarden credentials
    must be valid). Tests that need a working vault should set real
    credentials via environment variables.
    """
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    transport = StdioTransport(
        command=binary_path,
        args=["serve", "--transport", "stdio"],
        env=os.environ.copy(),
    )
    client = Client(transport)
    async with client:
        yield client
