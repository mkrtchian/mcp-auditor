import asyncio
import pathlib
import time

import pytest
from mcp.shared.exceptions import McpError
from mcp.types import CONNECTION_CLOSED, INTERNAL_ERROR

import tests.integration.support.test_mcp_client_transport_given as given
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.domain.server_watch import is_timeout


async def test_a_server_logging_its_shutdown_to_stdout_is_left_cleanly() -> None:
    async with StdioMCPClient.connect(given.a_read_server("noisy_shutdown")) as client:
        response = await client.call_tool("read", {"path": "/any"})

    assert response.content == "ok"


async def test_a_body_error_survives_a_server_logging_its_shutdown_to_stdout() -> None:
    with pytest.raises(ValueError, match=r"^body$"):
        async with StdioMCPClient.connect(given.a_read_server("noisy_shutdown")) as client:
            await client.call_tool("read", {"path": "/any"})
            raise ValueError("body")


async def test_a_non_protocol_line_mid_session_is_counted_and_the_call_answers() -> None:
    async with StdioMCPClient.connect(given.a_read_server("noisy_mid_session")) as client:
        response = await client.call_tool("read", {"path": "/any"})

        assert response.content == "ok"
        assert client.non_protocol_lines == 1


async def test_a_server_that_never_answers_initialize_times_out() -> None:
    started = time.monotonic()
    with pytest.raises(ExceptionGroup) as raised:
        async with StdioMCPClient.connect(
            given.a_read_server("silent_initialize"), initialize_timeout=0.5
        ):
            pass

    matched, _ = raised.value.split(TimeoutError)
    assert matched is not None
    assert time.monotonic() - started < 10


async def test_an_audit_of_a_server_logging_its_shutdown_to_stdout_completes_its_report(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    report = await given.an_audit_of(given.a_read_server("noisy_shutdown")).run()

    assert report is not None
    assert report.is_complete
    assert [t.tool.name for t in report.tool_reports] == ["read"]
    assert len(report.tool_reports[0].cases) == 1


async def test_a_ping_right_after_the_handshake_is_answered() -> None:
    async with StdioMCPClient.connect(given.a_stalling_server()) as client:
        assert await client.ping()


async def test_a_ping_is_answered_while_a_timed_out_call_runs_on_and_the_next_call_is_served() -> (
    None
):
    async with StdioMCPClient.connect(given.a_stalling_server(), tool_call_timeout=1) as client:
        stalled = await client.call_tool("wait_forever", {})

        assert is_timeout(stalled)
        assert await client.ping()
        assert (await client.call_tool("echo", {})).content == "ok"


async def test_a_ping_goes_unanswered_once_a_call_blocked_the_server_loop() -> None:
    async with StdioMCPClient.connect(given.a_stalling_server(), tool_call_timeout=1) as client:
        blocked = await client.call_tool("block_loop", {})

        assert is_timeout(blocked)
        assert not await client.ping()


async def test_a_ping_the_server_ignores_goes_unanswered() -> None:
    async with StdioMCPClient.connect(given.a_stalling_server("--ignore-ping")) as client:
        assert not await client.ping()


async def test_an_error_response_to_the_ping_is_an_answer() -> None:
    assert await given.the_ping_error_code("--error-ping") == INTERNAL_ERROR
    async with StdioMCPClient.connect(given.a_stalling_server("--error-ping")) as client:
        assert await client.ping()


async def test_the_client_does_not_relaunch_its_server() -> None:
    async with StdioMCPClient.connect(given.a_stalling_server()) as client:
        assert not await client.relaunch()


async def test_a_command_not_found_raises_a_bare_os_error() -> None:
    with pytest.raises(FileNotFoundError):
        async with StdioMCPClient.connect(given.a_command_not_found()):
            pass


async def test_a_server_that_exits_before_initialize_closes_the_connection_inside_a_group() -> None:
    with pytest.raises(ExceptionGroup) as raised:
        async with StdioMCPClient.connect(given.a_stalling_server("--exit-before-initialize")):
            pass

    closed, _ = raised.value.split(
        lambda error: isinstance(error, McpError) and error.error.code == CONNECTION_CLOSED
    )
    assert closed is not None


async def test_a_cancelled_caller_leaves_no_server_process_running() -> None:
    pid = asyncio.get_running_loop().create_future()

    async def a_call_that_never_returns() -> None:
        async with StdioMCPClient.connect(given.a_stalling_server(), tool_call_timeout=3600) as c:
            pid.set_result(int((await c.call_tool("pid", {})).content))
            await c.call_tool("wait_forever", {})

    caller = asyncio.create_task(a_call_that_never_returns())
    server_pid = await asyncio.wait_for(pid, timeout=30)
    caller.cancel()
    await asyncio.gather(caller, return_exceptions=True)

    assert await given.the_process_ends(server_pid)
