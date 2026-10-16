"""A minimal async MCP client over the `mcp` SDK, free of mcp_auditor.

Parity note: the acceptance twin is the auditor's StdioMCPClient
(src/mcp_auditor/adapters/mcp_client.py) wrapped by evals/cve_recording_client.py. KitResponse
mirrors ToolResponse (content, is_error) and KitTool mirrors ToolDefinition (name, description,
input_schema), so an exploit written against KitClient runs unchanged against MCPClientPort.

No AuditedServer and no destructive-payload guard (ADR 013 does not apply): the workshop runs the
agent's own exploits, not the auditor, and the agent must be free to write the exploit it needs.
Containment is the Docker target and the layout mounts alone.
"""

import asyncio
from collections.abc import AsyncGenerator, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol, Self

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.types import TextContent, Tool

_DEFAULT_TOOL_CALL_TIMEOUT = 30

# The host-side `docker` client variables (not the container's). The MCP SDK passes only a
# minimal environment to the process it spawns, so a rootless DOCKER_HOST would be lost at launch
# without this. Copied from mcp_auditor.adapters.docker.docker_client_env to keep the kit clean.
_DOCKER_CLIENT_VARIABLES = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)


@dataclass(frozen=True)
class KitTool:
    name: str
    description: str | None
    input_schema: Mapping[str, Any]


@dataclass(frozen=True)
class KitResponse:
    content: str
    is_error: bool


class KitClient(Protocol):
    async def list_tools(self) -> list[KitTool]: ...
    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse: ...


def docker_client_env(environ: Mapping[str, str]) -> dict[str, str]:
    return {name: environ[name] for name in _DOCKER_CLIENT_VARIABLES if name in environ}


class KitMCPClient:
    _session: ClientSession
    _tool_call_timeout: int

    @classmethod
    @asynccontextmanager
    async def connect(
        cls,
        command: str,
        args: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        errlog: Any = None,
        tool_call_timeout: int = _DEFAULT_TOOL_CALL_TIMEOUT,
    ) -> AsyncGenerator[Self]:
        client = cls()
        client._tool_call_timeout = tool_call_timeout
        async with AsyncExitStack() as stack:
            params = StdioServerParameters(
                command=command, args=list(args), env=get_default_environment() | dict(env or {})
            )
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

    async def list_tools(self) -> list[KitTool]:
        result = await self._session.list_tools()
        return [_to_kit_tool(tool) for tool in result.tools]

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        try:
            async with asyncio.timeout(self._tool_call_timeout):
                result = await self._session.call_tool(name, arguments=args)
        except TimeoutError:
            return KitResponse(f"Tool call timed out after {self._tool_call_timeout}s", True)
        except Exception as exc:
            return KitResponse(str(exc), True)
        text = "\n".join(item.text for item in result.content if isinstance(item, TextContent))
        return KitResponse(text, bool(result.isError))


def _to_kit_tool(tool: Tool) -> KitTool:
    return KitTool(name=tool.name, description=tool.description, input_schema=tool.inputSchema)
