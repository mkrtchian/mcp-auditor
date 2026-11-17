import asyncio
import io
import os
import pathlib
import sys
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from rich.console import Console

import tests.unit.auditor.support.test_graph_given as graph
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.audit import Analysts, Audit, AuditConfig, AuditRunOptions, CIOptions
from mcp_auditor.config import Settings
from mcp_auditor.console import AuditDisplay
from mcp_auditor.domain import AttackContext, TestCaseBatch
from mcp_auditor.report_files import ReportPaths
from mcp_auditor.server_execution import LaunchOptions, ServerExecution
from tests.fakes import FakeContainerRuntime, FakeLLM

READ_SERVER_PATH = pathlib.Path(__file__).resolve().parent / "detection_replay_read_server.py"
STALLING_SERVER_PATH = pathlib.Path(__file__).resolve().parent / "stalling_server.py"


def a_read_server(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(READ_SERVER_PATH), *flags])


def a_stalling_server(*flags: str) -> ServerLaunch:
    return ServerLaunch.unconfined(sys.executable, [str(STALLING_SERVER_PATH), *flags])


def a_command_not_found() -> ServerLaunch:
    return ServerLaunch.unconfined("mcp-auditor-no-such-command", [])


async def the_process_ends(pid: int, within_seconds: float = 10) -> bool:
    deadline = time.monotonic() + within_seconds
    while time.monotonic() < deadline:
        if not _running(pid):
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


def an_audit_of(launch: ServerLaunch) -> Audit:
    # One read case, judged and summarized by the same scripted model, no chain.
    batch = TestCaseBatch(cases=[graph.a_payload(arguments={"path": "/outside/flag"})])
    llm = FakeLLM([batch, graph.a_judgment(), AttackContext()])
    config = AuditConfig(
        run_options=AuditRunOptions(budget=1, chains=0, resume=False, dry_run=False),
        report_paths=ReportPaths(),
        ci=CIOptions(),
        launch=LaunchOptions(unconfined=True, image=None, mounts=()),
    )
    return Audit(
        config=config,
        execution=ServerExecution(launch, FakeContainerRuntime(untouchable=True)),
        analysts=Analysts(llm=llm, judge=llm, settings=Settings()),
        display=AuditDisplay(console=Console(file=io.StringIO(), width=200)),
    )
