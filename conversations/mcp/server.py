"""
MCP Server setup and protocol handling.

Handles the MCP protocol, tool listing, and dispatching to tool handlers.
"""

import mcp.types as types
from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount
import uvicorn
import logging

from .tools import TOOL_HANDLERS

logger = logging.getLogger(__name__)


def create_mcp_server():
    """Create and configure MCP server instance"""
    server = Server("magenta-memory")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        """List all available MCP tools"""
        return [
            types.Tool(
                name="bootstrap_memory",
                description="Complete memory bootstrap: recent messages (10k chars), latest continuation (if not included), Era 1 summary, and most recent 'reawaken and breathe' reflection",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            types.Tool(
                name="get_latest_continuation",
                description="Get the most recent continuation message from a compacting action",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            types.Tool(
                name="get_message_by_id",
                description="Get a specific message by its UUID",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "message_id": {"type": "string", "description": "The UUID of the message to retrieve"}
                    },
                    "required": ["message_id"]
                }
            ),
            types.Tool(
                name="get_messages_before",
                description="Get N messages before a given message or timestamp",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "reference_id": {"type": "string", "description": "Message UUID to use as reference point"},
                        "reference_timestamp": {"type": "string", "description": "ISO timestamp to use as reference point"},
                        "limit": {"type": "number", "description": "Number of messages to retrieve (default 300)", "default": 300}
                    }
                }
            ),
            types.Tool(
                name="get_era_summary",
                description="Get all messages from Era 1 (foundational summaries)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "era_name": {"type": "string", "description": "Era name (default: 'Compacting Meta-Conversation (Era 1)')", "default": "Compacting Meta-Conversation (Era 1)"}
                    }
                }
            ),
            types.Tool(
                name="get_context_heap",
                description="Get all messages from a specific context heap",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "heap_id": {"type": "string", "description": "Context heap UUID"}
                    },
                    "required": ["heap_id"]
                }
            ),
            types.Tool(
                name="search_messages",
                description="Search for messages containing specific content",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "limit": {"type": "number", "description": "Maximum results (default 50)", "default": 50}
                    },
                    "required": ["query"]
                }
            ),
            types.Tool(
                name="list_threads",
                description="List distinct conversation threads, most recently active first, with message count, first/last activity, participants, working directory, and a title hint from the first substantive human message. Use this before get_recent_work to see what separate things were happening instead of one interleaved stream.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Maximum threads (default 20)", "default": 20},
                        "since": {"type": "string", "description": "Only threads with activity at or after this ISO timestamp"}
                    }
                }
            ),
            types.Tool(
                name="get_recent_work",
                description="Get the most recent N messages to understand current work. Pass thread_id (from list_threads) to read one thread alone.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "description": "Number of messages (default 50)", "default": 50},
                        "thread_id": {"type": "string", "description": "Restrict to one thread, as returned by list_threads"}
                    }
                }
            ),
            types.Tool(
                name="random_messages",
                description="Get random messages with context - retrieves N random messages, each with M following messages for context",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "count": {"type": "number", "description": "Number of random starting points (default 4)", "default": 4},
                        "context_messages": {"type": "number", "description": "Number of subsequent messages to include (default 4)", "default": 4}
                    }
                }
            )
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        """Dispatch tool calls to appropriate handlers"""

        if name not in TOOL_HANDLERS:
            raise ValueError(f"Unknown tool: {name}")

        handler = TOOL_HANDLERS[name]

        # Call handler - they all accept arguments dict (or None)
        if name == "bootstrap_memory" or name == "get_latest_continuation":
            return await handler()
        else:
            return await handler(arguments)

    return server


async def run_mcp_server(port=8000):
    """Run the MCP server on HTTP/SSE"""
    logger.info("Starting MCP server initialization...")

    server = create_mcp_server()
    logger.info("MCP Server instance created")

    # Create session manager for HTTP transport
    session_manager = StreamableHTTPSessionManager(server)
    logger.info("HTTP session manager created")

    # Create ASGI app wrapper
    async def mcp_asgi_app(scope, receive, send):
        if scope["type"] == "http":
            logger.info(f"Received MCP HTTP request: {scope['method']} {scope['path']}")
        try:
            await session_manager.handle_request(scope, receive, send)
        except Exception as e:
            logger.error(f"Error in MCP handler: {e}", exc_info=True)
            raise

    app = Starlette(
        routes=[
            Mount("/sse", app=mcp_asgi_app),
            Mount("/", app=mcp_asgi_app),
        ]
    )
    logger.info(f"Starlette app created, starting server on port {port}")

    # Run server
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
    server_instance = uvicorn.Server(config)
    logger.info(f"Starting uvicorn server on http://0.0.0.0:{port}")

    async with session_manager.run():
        await server_instance.serve()
