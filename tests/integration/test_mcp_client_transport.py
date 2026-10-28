import pathlib
import time

import pytest

import tests.integration.support.test_mcp_client_transport_given as given
from mcp_auditor.adapters.mcp_client import StdioMCPClient


async def test_a_server_logging_its_shutdown_to_stdout_is_left_cleanly() -> None:
    async with StdioMCPClient.connect(given.a_stub("noisy_shutdown")) as client:
        response = await client.call_tool("read", {"path": "/any"})

    assert response.content == "ok"


async def test_a_body_error_survives_a_server_logging_its_shutdown_to_stdout() -> None:
    with pytest.raises(ValueError, match=r"^body$"):
        async with StdioMCPClient.connect(given.a_stub("noisy_shutdown")) as client:
            await client.call_tool("read", {"path": "/any"})
            raise ValueError("body")


async def test_a_non_protocol_line_mid_session_is_counted_and_the_call_answers() -> None:
    async with StdioMCPClient.connect(given.a_stub("noisy_mid_session")) as client:
        response = await client.call_tool("read", {"path": "/any"})

        assert response.content == "ok"
        assert client.non_protocol_lines == 1


async def test_a_server_that_never_answers_initialize_times_out() -> None:
    started = time.monotonic()
    with pytest.raises(ExceptionGroup) as raised:
        async with StdioMCPClient.connect(
            given.a_stub("silent_initialize"), initialize_timeout=0.5
        ):
            pass

    matched, _ = raised.value.split(TimeoutError)
    assert matched is not None
    assert time.monotonic() - started < 10


async def test_the_cli_delivers_the_report_of_a_server_logging_its_shutdown_to_stdout(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    report = await given.an_audit_of(given.a_stub("noisy_shutdown")).run()

    assert report is not None
