import asyncio
import os
import pathlib
import sys
import time
from dataclasses import dataclass, field

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

from mcp_auditor.adapters.server_launch import ServerLaunch
from tests.integration.support.docker_on_the_host import removals
from tests.integration.support.support_servers import STALLING_SERVER_PATH


def a_declared_stalling_container(
    *docker_options: str, server_flags: tuple[str, ...] = ()
) -> ServerLaunch:
    args = ["run", *docker_options, sys.executable, str(STALLING_SERVER_PATH), *server_flags]
    return ServerLaunch.declared_container("docker", args, client_env={})


@dataclass
class FakeTeardown:
    """Ends no server: it waits `lasting_seconds`, and records the removals the Docker shim of
    `seeing_removals_in` logged by the time it is called."""

    lasting_seconds: float = 0
    seeing_removals_in: pathlib.Path | None = None
    removals_seen: list[list[str]] = field(default_factory=list[list[str]])

    async def end_server(self) -> None:
        if self.seeing_removals_in is not None:
            self.removals_seen.append(removals(self.seeing_removals_in))
        await asyncio.sleep(self.lasting_seconds)


async def the_process_group_ends(pgid: int, within_seconds: float = 10) -> bool:
    deadline = time.monotonic() + within_seconds
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        await asyncio.sleep(0.1)
    return False


async def the_ping_error_code(*flags: str) -> int | None:
    """The code of the JSON-RPC error the stalling server answers a ping with, None on a plain
    answer, read on a bare SDK session so the client under test plays no part."""
    parameters = StdioServerParameters(
        command=sys.executable, args=[str(STALLING_SERVER_PATH), *flags]
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        try:
            await session.send_ping()
        except McpError as error:
            return error.error.code
    return None
