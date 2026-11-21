import io
import pathlib
import sqlite3

import pytest

import tests.integration.support.test_audit_server_failures_given as given
from mcp_auditor import audit
from tests.integration.support.stalling_server import DYING_WORDS
from tests.integration.support.support_servers import (
    A_COMMAND_NOT_FOUND,
    a_read_server,
    a_stalling_server,
)


@pytest.fixture(autouse=True)
def _a_home_of_its_own(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))


async def test_a_command_not_found_stops_with_the_os_error_alone() -> None:
    output = io.StringIO()

    with pytest.raises(SystemExit) as exited:
        await given.an_audit_of(A_COMMAND_NOT_FOUND, output).run()

    assert exited.value.code == 1
    assert "Error: [Errno 2] No such file or directory" in output.getvalue()
    assert "MCP server failed" not in output.getvalue()


async def test_a_server_dying_under_list_tools_stops_with_the_lost_connection_and_stderr() -> None:
    output = io.StringIO()

    with pytest.raises(SystemExit) as exited:
        await given.an_audit_of(a_stalling_server("--exit-on-list-tools"), output).run()

    assert exited.value.code == 1
    assert "Error: MCP server failed: Connection closed" in output.getvalue()
    assert f"server stderr:\n{DYING_WORDS}" in output.getvalue()


# Whether the session's task groups wrap the graph's exception or let it out bare (they let it
# out bare when the server logs its shutdown to stdout), the operator reads the same message.
@pytest.mark.parametrize("flags", [(), ("noisy_shutdown",)])
async def test_an_exception_out_of_the_graph_stops_with_its_message(flags: tuple[str, ...]) -> None:
    output = io.StringIO()
    audit = given.an_audit_of(a_read_server(*flags), output, given.a_failing_model())

    with pytest.raises(SystemExit) as exited:
        await audit.run()

    assert exited.value.code == 1
    assert f"Error: MCP server failed: {given.PROVIDER_FAILURE}" in output.getvalue()


# An OSError the graph raises (a TimeoutError is one) is not a failure to open the session.
async def test_an_os_error_out_of_the_graph_stops_as_a_server_failure() -> None:
    output = io.StringIO()
    model = given.a_failing_model(ConnectionResetError(given.PROVIDER_FAILURE))
    audit = given.an_audit_of(a_read_server(), output, model)

    with pytest.raises(SystemExit) as exited:
        await audit.run()

    assert exited.value.code == 1
    assert f"Error: MCP server failed: {given.PROVIDER_FAILURE}" in output.getvalue()


async def test_a_local_failure_before_the_session_opens_is_not_blamed_on_the_server(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unopenable = str(tmp_path / "absent" / "checkpoints.db")
    monkeypatch.setattr(audit, "checkpoint_db_path", lambda: unopenable)

    with pytest.raises(sqlite3.OperationalError):
        await given.an_audit_of(a_stalling_server(), io.StringIO()).run()
