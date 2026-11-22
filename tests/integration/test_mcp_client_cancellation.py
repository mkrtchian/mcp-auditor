import asyncio
import gc
import pathlib

import pytest

import tests.integration.support.test_mcp_client_cancellation_given as given
from mcp_auditor.adapters.mcp_client import SessionBounds, StdioMCPClient
from tests.integration.support.support_servers import a_read_server, a_stalling_server


async def test_a_cancelled_caller_leaves_no_server_process_running() -> None:
    pid = asyncio.get_running_loop().create_future()

    async def a_call_that_never_returns() -> None:
        async with StdioMCPClient.connect(a_stalling_server(), tool_call_timeout=3600) as c:
            pid.set_result(int((await c.call_tool("pid", {})).content))
            await c.call_tool("wait_forever", {})

    caller = asyncio.create_task(a_call_that_never_returns())
    server_pid = await asyncio.wait_for(pid, timeout=30)
    caller.cancel()
    await asyncio.gather(caller, return_exceptions=True)

    assert await given.the_process_ends(server_pid)


# The abandoned opening's error has no reader left: it must not reach the asyncio logger, which
# the redacting filter does not cover.
async def test_a_caller_cancelled_while_the_session_opens_ends_at_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    opening = asyncio.create_task(given.a_session_opened(a_read_server("silent_initialize")))

    took = await given.cancelled_after(1, opening)

    assert opening.cancelled()
    assert took < 10
    gc.collect()
    assert "never retrieved" not in caplog.text


async def test_a_caller_cancelled_while_a_relaunch_opens_ends_at_once(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    launch = a_stalling_server("--silent-once-served", str(tmp_path / "served"))
    relaunching = asyncio.Event()
    caller = asyncio.create_task(given.a_relaunch_of(launch, relaunching))
    await asyncio.wait_for(relaunching.wait(), timeout=30)

    took = await given.cancelled_after(3, caller)

    assert caller.cancelled()
    assert took < 10
    gc.collect()
    assert "never retrieved" not in caplog.text


# Its line finds a session that stopped reading, and the SDK's task groups raise that error in
# place of the cancellation of the owner.
async def test_a_caller_cancelled_while_a_server_logging_its_shutdown_opens_ends_at_once() -> None:
    launch = a_stalling_server("--silent-with-noisy-shutdown")
    opening = asyncio.create_task(given.a_session_opened(launch))

    took = await given.cancelled_after(1, opening)

    assert opening.cancelled()
    assert took < 10


# The unwinding of a failed opening is what ends its server, so a close lets it finish.
async def test_a_caller_cancelled_while_a_timed_out_opening_unwinds_leaves_no_server_process(
    tmp_path: pathlib.Path,
) -> None:
    pid_file = tmp_path / "pid"
    launch = given.a_silent_server_writing_its_pid(pid_file)
    opening = asyncio.create_task(given.a_session_opened(launch, SessionBounds(initialize=0.5)))

    took = await given.cancelled_after(1.5, opening)

    assert took < 10
    assert await given.the_process_ends(int(pid_file.read_text()))
