"""HTTP transport for the Vaultwarden MCP server.

Provides a long-running HTTP server for MCP JSON-RPC communication,
an alternative to the default stdio transport.
"""

from __future__ import annotations

import logging

from mcp.server import NotificationOptions
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Mount
import uvicorn

from vaultwarden_mcp.mcp_server import server

logger = logging.getLogger(__name__)


async def serve_http(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the MCP server over HTTP (Streamable HTTP transport).

    This allows multiple clients to connect to the same server instance,
    which is useful for multi-account scenarios where different clients
    may need access to different accounts within a single process.
    """
    session_manager = StreamableHTTPSessionManager(
        app=server,
        event_store=None,
        json_response=True,
    )

    starlette_app = Starlette(
        routes=[
            Mount("/mcp", app=session_manager),
        ],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["*"],
                allow_headers=["*"],
            ),
        ],
    )

    config = uvicorn.Config(
        starlette_app,
        host=host,
        port=port,
        log_level="info",
    )
    server_instance = uvicorn.Server(config)
    await server_instance.serve()
