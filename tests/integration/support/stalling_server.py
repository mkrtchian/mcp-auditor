"""A server whose tools stall, for the ping tests of the client.

`wait_forever` never returns but leaves the event loop free, `block_loop` blocks the loop, and
`echo` answers at once. `--ignore-ping` leaves every ping unanswered, and `--error-ping` answers
it with a JSON-RPC error.
"""

import sys
import time
from typing import Any

import anyio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError
from mcp.types import (
    INTERNAL_ERROR,
    CallToolResult,
    EmptyResult,
    ErrorData,
    PingRequest,
    ServerResult,
    TextContent,
    Tool,
)

BLOCKED_LOOP_SECONDS = 3600
TOOLS = [
    Tool(name=name, inputSchema={"type": "object"})
    for name in ("wait_forever", "block_loop", "echo")
]

server = Server("stalling")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    if name == "wait_forever":
        await anyio.sleep_forever()
    if name == "block_loop":
        time.sleep(BLOCKED_LOOP_SECONDS)
    return CallToolResult(content=[TextContent(type="text", text="ok")])


async def _never_answered(request: PingRequest) -> ServerResult:
    await anyio.sleep_forever()
    return ServerResult(EmptyResult())


async def _answered_with_an_error(request: PingRequest) -> ServerResult:
    raise McpError(ErrorData(code=INTERNAL_ERROR, message="ping refused"))


async def main() -> None:
    if "--ignore-ping" in sys.argv[1:]:
        server.request_handlers[PingRequest] = _never_answered
    if "--error-ping" in sys.argv[1:]:
        server.request_handlers[PingRequest] = _answered_with_an_error
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
