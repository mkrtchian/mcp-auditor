import asyncio
import os
import pathlib
import sys
import time

from mcp_auditor.adapters.mcp_client import SessionBounds, StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch

# Long enough that a caller made to wait the opening out shows it.
_SLOW_OPENING_SECONDS = 60
_SLOW_OPENING = SessionBounds(initialize=_SLOW_OPENING_SECONDS)


async def a_session_opened(launch: ServerLaunch, bounds: SessionBounds = _SLOW_OPENING) -> None:
    async with StdioMCPClient.connect(launch, bounds=bounds):
        pass


async def a_relaunch_of(launch: ServerLaunch, relaunching: asyncio.Event) -> None:
    async with StdioMCPClient.connect(launch, bounds=_SLOW_OPENING) as client:
        relaunching.set()
        await client.relaunch()


async def cancelled_after(seconds: float, caller: "asyncio.Task[None]") -> float:
    """How long the caller took to end once cancelled, `seconds` into its run."""
    await asyncio.sleep(seconds)
    started = time.monotonic()
    caller.cancel()
    # A caller that hangs fails its test.
    await asyncio.wait({caller}, timeout=_SLOW_OPENING_SECONDS)
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


# A zombie is a process that ended and that its parent has not reaped yet.
def _running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = pathlib.Path(f"/proc/{pid}/stat")
    return not (stat.exists() and stat.read_text().rsplit(")", 1)[1].split()[0] == "Z")
