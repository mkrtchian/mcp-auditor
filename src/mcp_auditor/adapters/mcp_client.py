import asyncio
from collections.abc import AsyncGenerator
from contextlib import AsyncExitStack, asynccontextmanager
from typing import IO, Any, Self

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.shared.session import RequestResponder
from mcp.types import ClientResult, ServerNotification, ServerRequest, TextContent, Tool

from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.models import ToolDefinition, ToolResponse

_DEFAULT_TOOL_CALL_TIMEOUT = 30
_INITIALIZE_TIMEOUT = 120

type IncomingMessage = (
    RequestResponder[ServerRequest, ClientResult] | ServerNotification | Exception
)


class StdioMCPClient:
    _session: ClientSession
    _tool_call_timeout: int
    _list_tools_timeout: float
    _non_protocol_lines: int = 0

    @classmethod
    @asynccontextmanager
    async def connect(
        cls,
        launch: ServerLaunch,
        errlog: IO[str] | None = None,
        tool_call_timeout: int = _DEFAULT_TOOL_CALL_TIMEOUT,
        *,
        initialize_timeout: float = _INITIALIZE_TIMEOUT,
    ) -> AsyncGenerator[Self]:
        client = cls()
        client._tool_call_timeout = tool_call_timeout
        client._list_tools_timeout = initialize_timeout
        body_error: BaseException | None = None
        try:
            async with AsyncExitStack() as stack:
                client._session = await client._open_session(stack, launch, errlog)
                async with asyncio.timeout(initialize_timeout):
                    await client._session.initialize()
                try:
                    yield client
                except BaseException as error:
                    body_error = error
                    raise
        except BaseExceptionGroup as group:
            # A server that logs its shutdown to stdout after the session stopped reading makes
            # the SDK's stdout reader raise BrokenResourceError (mcp 1.30.0): not a failure.
            if not _only_broken_streams(group):
                raise
            if body_error is not None:
                # Bare, so the body's own __cause__ is kept.
                raise body_error  # noqa: B904

    @property
    def non_protocol_lines(self) -> int:
        return self._non_protocol_lines

    async def list_tools(self) -> list[ToolDefinition]:
        async with asyncio.timeout(self._list_tools_timeout):
            result = await self._session.list_tools()
        return [_to_tool_definition(t) for t in result.tools]

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        try:
            async with asyncio.timeout(self._tool_call_timeout):
                result = await self._session.call_tool(name, arguments=args)
        except TimeoutError:
            return ToolResponse(
                content=f"Tool call timed out after {self._tool_call_timeout}s",
                is_error=True,
                error_type="TimeoutError",
            )
        except Exception as exc:
            return ToolResponse(content=str(exc), is_error=True, error_type=type(exc).__name__)
        text = "\n".join(item.text for item in result.content if isinstance(item, TextContent))
        return ToolResponse(content=text, is_error=bool(result.isError))

    async def _open_session(
        self, stack: AsyncExitStack, launch: ServerLaunch, errlog: IO[str] | None
    ) -> ClientSession:
        client_kwargs: dict[str, Any] = {"server": _server_parameters(launch)}
        if errlog is not None:
            client_kwargs["errlog"] = errlog
        read_stream, write_stream = await stack.enter_async_context(stdio_client(**client_kwargs))
        return await stack.enter_async_context(
            ClientSession(read_stream, write_stream, message_handler=self._count_non_protocol_line)
        )

    async def _count_non_protocol_line(self, message: IncomingMessage) -> None:
        # The SDK hands the session a line it cannot parse as an Exception.
        if isinstance(message, Exception):
            self._non_protocol_lines += 1


def _only_broken_streams(group: BaseExceptionGroup) -> bool:
    _, rest = group.split(anyio.BrokenResourceError)
    return rest is None


def _server_parameters(launch: ServerLaunch) -> StdioServerParameters:
    environment = launch.spawn_environment
    if environment is None:
        return StdioServerParameters(command=launch.spawn_command, args=launch.spawn_args)
    return StdioServerParameters(
        command=launch.spawn_command,
        args=launch.spawn_args,
        env=get_default_environment() | environment,
    )


def _to_tool_definition(tool: Tool) -> ToolDefinition:
    return ToolDefinition(
        name=tool.name,
        description=tool.description,
        input_schema=tool.inputSchema,
    )
