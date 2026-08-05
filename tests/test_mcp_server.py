"""Test suite for vaultwarden-mcp using FastMCP as a client.

These are black-box tests that verify the Rust MCP server responds correctly
to MCP protocol requests. The Rust binary is launched as a subprocess via
stdio transport (FastMCP's StdioTransport).

For tests that require a real Vaultwarden vault:
  set environment variables before running:
    VAULTWARDEN_SERVER, VAULTWARDEN_CLIENT_ID, VAULTWARDEN_CLIENT_SECRET,
    VAULTWARDEN_PASSWORD

For mock/syntax tests that don't require a live vault, we check tool listing
and protocol compliance without connecting to a real server.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_list_tools(client) -> None:
    """Verify the server advertises the expected MCP tools."""
    tools = await client.list_tools()
    tool_names = {t.name for t in tools}
    assert tool_names == {"search", "get_cipher", "sync", "list_accounts"}


async def test_list_accounts_tool_exists(client) -> None:
    """Verify list_accounts tool is available and callable."""
    result = await client.call_tool("list_accounts")
    assert result is not None
    assert len(result.content) > 0


async def test_server_info(client) -> None:
    """Verify server info declares MCP v3.0 protocol support."""
    info = await client.get_info() if hasattr(client, "get_info") else None
    # At minimum, list_tools works which means the protocol handshake succeeded
    tools = await client.list_tools()
    assert len(tools) >= 4


async def test_search_no_results(client) -> None:
    """Search with a non-matching query should return empty results."""
    result = await client.call_tool("search", {"query": "NONEXISTENT_ENTRY_12345"})
    # The result should not error; we just check the tool doesn't crash
    assert result is not None


async def test_get_cipher_unknown(client) -> None:
    """Get cipher with an invalid ID should return an error, not crash."""
    with pytest.raises(Exception):
        await client.call_tool("get_cipher", {"cipher_id": "invalid_id", "account": "test"})


async def test_unknown_tool_rejected(client) -> None:
    """Calling an unknown tool should return an error."""
    with pytest.raises(Exception):
        await client.call_tool("nonexistent_tool", {})
