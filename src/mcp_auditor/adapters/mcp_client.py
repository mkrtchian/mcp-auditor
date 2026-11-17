import asyncio
import os
import subprocess
from collections.abc import AsyncGenerator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager, suppress
from dataclasses import dataclass
from typing import IO, Any, Protocol, Self

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.shared.exceptions import McpError
from mcp.shared.session import RequestResponder
from mcp.types import (
    CONNECTION_CLOSED,
    ClientResult,
    PaginatedRequestParams,
    ServerNotification,
    ServerRequest,
    TextContent,
    Tool,
)

from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.adapters.session_owner import SessionEntry, SessionOwner
from mcp_auditor.domain.confinement import Undecidable, declared_container_name
from mcp_auditor.domain.models import ExecutionRegime, ToolDefinition, ToolResponse
from mcp_auditor.domain.server_watch import PING_TIMEOUT_SECONDS

_DEFAULT_TOOL_CALL_TIMEOUT = 60
_INITIALIZE_TIMEOUT = 120
TEARDOWN_TIMEOUT_SECONDS = 30
# Once the owner has unwound a session whose transport failed, a call reads as a lost connection.
_SESSION_LOST = ToolResponse(
    content="the session with the server is closed",
    is_error=True,
    error_type="ClosedResourceError",
)

type IncomingMessage = (
    RequestResponder[ServerRequest, ClientResult] | ServerNotification | Exception
)


class ServerTeardown(Protocol):
    async def end_server(self) -> None: ...


class StdioMCPClient:
    _owner: SessionOwner
    _session: ClientSession
    _tool_call_timeout: int
    _list_tools_timeout: float
    _declared_container: "_DeclaredContainer | None"
    _teardown: ServerTeardown | None
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
        teardown: ServerTeardown | None = None,
    ) -> AsyncGenerator[Self]:
        client = cls()
        client._tool_call_timeout = tool_call_timeout
        client._list_tools_timeout = initialize_timeout
        client._declared_container = _DeclaredContainer.named_by(launch)
        client._teardown = teardown
        client._owner = SessionOwner(client._session_entry(launch, errlog), initialize_timeout)
        # The body runs outside the SDK's task groups, which the owner's task holds: what it
        # raises leaves bare, and only the opening raises in their groups.
        try:
            client._session = await client._owner.open()
            yield client
        except BaseException:
            with suppress(Exception):  # the opening's or the body's error is the one read
                await client._owner.close()
            raise
        await client._owner.close()

    @property
    def non_protocol_lines(self) -> int:
        return self._non_protocol_lines

    async def list_tools(self) -> list[ToolDefinition]:
        async with asyncio.timeout(self._list_tools_timeout):
            tools = await _list_every_page(self._session)
        return [_to_tool_definition(tool) for tool in tools]

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        if self._owner.lost:
            return _SESSION_LOST
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

    async def ping(self) -> bool:
        if self._owner.lost:
            return False
        try:
            async with asyncio.timeout(PING_TIMEOUT_SECONDS):
                await self._session.send_ping()
        except McpError as error:
            return error.error.code != CONNECTION_CLOSED
        except (TimeoutError, anyio.ClosedResourceError, anyio.BrokenResourceError):
            return False
        return True

    async def relaunch(self) -> bool:
        """Ends the old server, then opens a session on a new one. Logs nothing, since what the
        server or Docker says can quote a relayed value."""
        try:
            async with asyncio.timeout(TEARDOWN_TIMEOUT_SECONDS):
                await self._end_server()
            self._session = await self._owner.replace()
        except Exception:
            return False
        return True

    # A declared container's name is the client's to remove, since only its command names it,
    # and the confined container is the injected teardown's. The end of the session ends an
    # unconfined server's process group.
    async def _end_server(self) -> None:
        if self._declared_container is not None:
            await asyncio.to_thread(self._declared_container.remove)
        if self._teardown is not None:
            await self._teardown.end_server()

    def _session_entry(self, launch: ServerLaunch, errlog: IO[str] | None) -> SessionEntry:
        client_kwargs: dict[str, Any] = {"server": _server_parameters(launch)}
        if errlog is not None:
            client_kwargs["errlog"] = errlog

        async def entered(stack: AsyncExitStack) -> ClientSession:
            streams = await stack.enter_async_context(stdio_client(**client_kwargs))
            return await stack.enter_async_context(
                ClientSession(*streams, message_handler=self._count_non_protocol_line)
            )

        return entered

    async def _count_non_protocol_line(self, message: IncomingMessage) -> None:
        # The SDK hands the session a line it cannot parse as an Exception.
        if isinstance(message, Exception):
            self._non_protocol_lines += 1


@dataclass(frozen=True)
class _DeclaredContainer:
    name: str
    client_env: Mapping[str, str]

    @classmethod
    def named_by(cls, launch: ServerLaunch) -> "_DeclaredContainer | None":
        if launch.regime is not ExecutionRegime.DECLARED_CONTAINER:
            return None
        name = declared_container_name(launch.args)
        if name is None or isinstance(name, Undecidable):
            return None  # left running, as a container the command does not name (ADR 036)
        return cls(name, launch.client_env or {})

    def remove(self) -> None:
        # A non-zero exit fails nothing by itself: a --rm container whose server exited is
        # already gone, and the opening of the next session decides.
        subprocess.run(
            ["docker", "rm", "-f", "-v", self.name],
            env=os.environ | dict(self.client_env),
            capture_output=True,
            check=False,
        )


def _server_parameters(launch: ServerLaunch) -> StdioServerParameters:
    environment = launch.spawn_environment
    if environment is None:
        return StdioServerParameters(command=launch.spawn_command, args=launch.spawn_args)
    return StdioServerParameters(
        command=launch.spawn_command,
        args=launch.spawn_args,
        env=get_default_environment() | environment,
    )


async def _list_every_page(session: ClientSession) -> list[Tool]:
    tools: list[Tool] = []
    seen: set[str] = set()
    cursor: str | None = None
    while True:
        params = None if cursor is None else PaginatedRequestParams(cursor=cursor)
        result = await session.list_tools(params=params)
        tools.extend(result.tools)
        cursor = result.nextCursor
        if cursor is None:
            return tools
        if cursor in seen:
            raise RuntimeError(f"tools/list returned a cursor it had already returned: {cursor}")
        seen.add(cursor)


def _to_tool_definition(tool: Tool) -> ToolDefinition:
    return ToolDefinition(
        name=tool.name,
        description=tool.description,
        input_schema=tool.inputSchema,
    )
