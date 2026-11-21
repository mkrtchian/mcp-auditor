import asyncio
import os
import pathlib
import sys
import time
from dataclasses import dataclass, field

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import Audit
from mcp_auditor.domain import AttackContext, TestCaseBatch
from tests.fakes import FakeLLM
from tests.integration.support.detection_fake_targets import removals
from tests.integration.support.support_servers import STALLING_SERVER_PATH
from tests.integration.support.unconfined_audit import AuditVariant, an_unconfined_audit
from tests.unit.auditor.support.graph_builders import a_judgment, a_payload


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


# Long enough that a caller made to wait the opening out shows it.
SLOW_OPENING_SECONDS = 60


async def a_session_opened(
    launch: ServerLaunch, initialize_timeout: float = SLOW_OPENING_SECONDS
) -> None:
    async with StdioMCPClient.connect(launch, initialize_timeout=initialize_timeout):
        pass


async def a_relaunch_of(launch: ServerLaunch, relaunching: asyncio.Event) -> None:
    async with StdioMCPClient.connect(launch, initialize_timeout=SLOW_OPENING_SECONDS) as client:
        relaunching.set()
        await client.relaunch()


async def cancelled_after(seconds: float, caller: "asyncio.Task[None]") -> float:
    """How long the caller took to end once cancelled, `seconds` into its run."""
    await asyncio.sleep(seconds)
    started = time.monotonic()
    caller.cancel()
    await asyncio.wait({caller}, timeout=SLOW_OPENING_SECONDS)  # a caller that hangs fails its test
    return time.monotonic() - started


def a_silent_server_writing_its_pid(pid_file: pathlib.Path) -> ServerLaunch:
    """Never answers `initialize`, and outlives the end of its stdin."""
    script = "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(120)"
    return ServerLaunch.unconfined(sys.executable, ["-c", script, str(pid_file)])


async def the_process_ends(pid: int, within_seconds: float = 10) -> bool:
    deadline = time.monotonic() + within_seconds
    while time.monotonic() < deadline:
        if not _running(pid):
            return True
        await asyncio.sleep(0.1)
    return False


async def the_process_group_ends(pgid: int, within_seconds: float = 10) -> bool:
    deadline = time.monotonic() + within_seconds
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        await asyncio.sleep(0.1)
    return False


# A zombie is a process that ended and that its parent has not reaped yet.
def _running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = pathlib.Path(f"/proc/{pid}/stat")
    return not (stat.exists() and stat.read_text().rsplit(")", 1)[1].split()[0] == "Z")


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


def an_audit_of(launch: ServerLaunch, tools: frozenset[str] | None = None) -> Audit:
    # One case per tool, judged and summarized by the same scripted model.
    batch = TestCaseBatch(cases=[a_payload(arguments={"path": "/outside/flag"})])
    llm = FakeLLM([batch, a_judgment(), AttackContext()])
    return an_unconfined_audit(launch, AuditVariant(llm=llm, tools=tools))
