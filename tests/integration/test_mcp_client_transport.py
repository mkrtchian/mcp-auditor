import time

import pytest
from mcp.shared.exceptions import McpError
from mcp.types import CONNECTION_CLOSED

from mcp_auditor.adapters.mcp_client import SessionBounds, StdioMCPClient
from tests.integration.support.support_servers import (
    A_COMMAND_NOT_FOUND,
    a_read_server,
    a_stalling_server,
)
from tests.integration.support.unconfined_audit import a_scripted_audit_of


async def test_a_server_logging_its_shutdown_to_stdout_is_left_cleanly() -> None:
    async with StdioMCPClient.connect(a_read_server("noisy_shutdown")) as client:
        response = await client.call_tool("read", {"path": "/any"})

    assert response.content == "ok"


async def test_a_body_error_survives_a_server_logging_its_shutdown_to_stdout() -> None:
    with pytest.raises(ValueError, match=r"^body$"):
        async with StdioMCPClient.connect(a_read_server("noisy_shutdown")) as client:
            await client.call_tool("read", {"path": "/any"})
            raise ValueError("body")


async def test_a_non_protocol_line_mid_session_is_counted_and_the_call_answers() -> None:
    async with StdioMCPClient.connect(a_read_server("noisy_mid_session")) as client:
        response = await client.call_tool("read", {"path": "/any"})

        assert response.content == "ok"
        assert client.non_protocol_lines == 1


async def test_a_server_that_never_answers_initialize_times_out() -> None:
    started = time.monotonic()
    with pytest.raises(ExceptionGroup) as raised:
        async with StdioMCPClient.connect(
            a_read_server("silent_initialize"), bounds=SessionBounds(initialize=0.5)
        ):
            pass

    matched, _ = raised.value.split(TimeoutError)
    assert matched is not None
    assert time.monotonic() - started < 10


async def test_an_audit_of_a_server_logging_its_shutdown_to_stdout_completes_its_report() -> None:
    report = await a_scripted_audit_of(a_read_server("noisy_shutdown")).run()

    assert report is not None
    assert report.is_complete
    assert [t.tool.name for t in report.tool_reports] == ["read"]
    assert len(report.tool_reports[0].cases) == 1


async def test_a_command_not_found_raises_a_bare_os_error() -> None:
    with pytest.raises(FileNotFoundError):
        async with StdioMCPClient.connect(A_COMMAND_NOT_FOUND):
            pass


async def test_a_server_that_exits_before_initialize_closes_the_connection_inside_a_group() -> None:
    with pytest.raises(ExceptionGroup) as raised:
        async with StdioMCPClient.connect(a_stalling_server("--exit-before-initialize")):
            pass

    closed, _ = raised.value.split(
        lambda error: isinstance(error, McpError) and error.error.code == CONNECTION_CLOSED
    )
    assert closed is not None
