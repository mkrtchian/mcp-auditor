from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from typing import IO, Any, Self

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent, Tool

from mcp_auditor.domain.models import ToolDefinition, ToolResponse


class StdioMCPClient:
    _session: ClientSession

    @classmethod
    @asynccontextmanager
    async def connect(
        cls, command: str, args: list[str], errlog: IO[str] | None = None
    ) -> AsyncIterator[Self]:
        client = cls()
        stack = AsyncExitStack()
        async with stack:
            params = StdioServerParameters(command=command, args=args)
            client_kwargs: dict[str, Any] = {"server": params}
            if errlog is not None:
                client_kwargs["errlog"] = errlog
            read_stream, write_stream = await stack.enter_async_context(
                stdio_client(**client_kwargs)
            )
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()
            client._session = session
            yield client

    async def list_tools(self) -> list[ToolDefinition]:
        result = await self._session.list_tools()
        return [_to_tool_definition(t) for t in result.tools]

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        try:
            result = await self._session.call_tool(name, arguments=args)
        except Exception as exc:
            return ToolResponse(content=str(exc), is_error=True, error_type=type(exc).__name__)
        text = "\n".join(item.text for item in result.content if isinstance(item, TextContent))
        return ToolResponse(content=text, is_error=bool(result.isError))


def _to_tool_definition(tool: Tool) -> ToolDefinition:
    return ToolDefinition(
        name=tool.name,
        description=tool.description,
        input_schema=tool.inputSchema,
    )
