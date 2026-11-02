"""A server that pages `tools/list`, two tools a page, for the client pagination tests.

`tool_5`, on the last page, declares an output schema its answer breaks, so a client that learned
that schema rejects the answer. `--repeat-cursor` makes the second page hand back the cursor the
first page returned.
"""

import sys
from typing import Any

import anyio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    TextContent,
    Tool,
)

PAGE_SIZE = 2
TOOLS = [Tool(name=f"tool_{index}", inputSchema={"type": "object"}) for index in range(1, 5)] + [
    Tool(
        name="tool_5",
        inputSchema={"type": "object"},
        outputSchema={
            "type": "object",
            "properties": {"count": {"type": "integer"}},
            "required": ["count"],
        },
    )
]

server = Server("paginated")
repeat_cursor = "--repeat-cursor" in sys.argv[1:]


@server.list_tools()
async def list_tools(request: ListToolsRequest) -> ListToolsResult:
    # The server calls this with None on a tools/call for a tool it has not cached yet.
    params = getattr(request, "params", None)
    page = int(params.cursor) if params is not None and params.cursor is not None else 0
    start = page * PAGE_SIZE
    next_page = page + 1
    next_cursor = str(next_page) if next_page * PAGE_SIZE < len(TOOLS) else None
    if repeat_cursor and page == 1:
        next_cursor = "1"
    return ListToolsResult(tools=TOOLS[start : start + PAGE_SIZE], nextCursor=next_cursor)


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    if name == "tool_5":
        return CallToolResult(content=[], structuredContent={"count": "not a number"})
    return CallToolResult(content=[TextContent(type="text", text="ok")])


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
