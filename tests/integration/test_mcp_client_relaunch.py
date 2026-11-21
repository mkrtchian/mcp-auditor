import pathlib

import pytest
from mcp.types import INTERNAL_ERROR

import tests.integration.support.test_mcp_client_relaunch_given as given
from mcp_auditor.adapters import mcp_client
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.domain.server_liveness import RelaunchCause
from mcp_auditor.domain.server_watch import is_lost_connection, is_timeout
from tests.integration.support.detection_fake_targets import removals
from tests.integration.support.support_servers import a_stalling_server
from tests.integration.support.unconfined_audit import a_scripted_audit_of


async def test_a_ping_right_after_the_handshake_is_answered() -> None:
    async with StdioMCPClient.connect(a_stalling_server()) as client:
        assert await client.ping()


async def test_a_ping_is_answered_while_a_timed_out_call_runs_on_and_the_next_call_is_served() -> (
    None
):
    async with StdioMCPClient.connect(a_stalling_server(), tool_call_timeout=1) as client:
        stalled = await client.call_tool("wait_forever", {})

        assert is_timeout(stalled)
        assert await client.ping()
        assert (await client.call_tool("echo", {})).content == "ok"


async def test_a_ping_goes_unanswered_once_a_call_blocked_the_server_loop() -> None:
    async with StdioMCPClient.connect(a_stalling_server(), tool_call_timeout=1) as client:
        blocked = await client.call_tool("block_loop", {})

        assert is_timeout(blocked)
        assert not await client.ping()


async def test_a_ping_the_server_ignores_goes_unanswered() -> None:
    async with StdioMCPClient.connect(a_stalling_server("--ignore-ping")) as client:
        assert not await client.ping()


async def test_an_error_response_to_the_ping_is_an_answer() -> None:
    assert await given.the_ping_error_code("--error-ping") == INTERNAL_ERROR
    async with StdioMCPClient.connect(a_stalling_server("--error-ping")) as client:
        assert await client.ping()


async def test_a_relaunch_after_a_blocked_loop_ends_the_old_process_group() -> None:
    async with StdioMCPClient.connect(a_stalling_server(), tool_call_timeout=1) as client:
        old_pid = int((await client.call_tool("pid", {})).content)
        assert is_timeout(await client.call_tool("block_loop", {}))

        assert await client.relaunch()

        assert await given.the_process_group_ends(old_pid)
        assert int((await client.call_tool("pid", {})).content) != old_pid


async def test_a_relaunch_after_the_server_exits_serves_the_next_call() -> None:
    async with StdioMCPClient.connect(a_stalling_server()) as client:
        assert is_lost_connection(await client.call_tool("exit", {}))

        assert await client.relaunch()

        assert (await client.call_tool("echo", {})).content == "ok"


async def test_a_relaunch_whose_server_does_not_start_again_returns_false(
    tmp_path: pathlib.Path,
) -> None:
    launch = a_stalling_server("--serve-once", str(tmp_path / "served"))
    async with StdioMCPClient.connect(launch) as client:
        assert is_lost_connection(await client.call_tool("exit", {}))

        assert not await client.relaunch()

        assert is_lost_connection(await client.call_tool("echo", {}))


async def test_a_teardown_past_its_bound_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_client, "TEARDOWN_TIMEOUT_SECONDS", 0.2)
    teardown = given.FakeTeardown(lasting_seconds=5)
    async with StdioMCPClient.connect(a_stalling_server(), teardown=teardown) as client:
        assert not await client.relaunch()


async def test_a_write_to_a_dead_server_gives_a_lost_connection_and_spares_the_caller() -> None:
    async with StdioMCPClient.connect(a_stalling_server(), tool_call_timeout=1) as client:
        assert is_timeout(await client.call_tool("exit_leaving_stdout_open", {}))
        await client.call_tool("echo", {})  # its write finds no reader

        assert is_lost_connection(await client.call_tool("echo", {}))
        assert not await client.ping()
        assert await client.relaunch()
        assert (await client.call_tool("echo", {})).content == "ok"


async def test_a_named_declared_container_is_removed_before_the_injected_teardown_runs(
    docker_on_the_host: pathlib.Path,
) -> None:
    teardown = given.FakeTeardown(seeing_removals_in=docker_on_the_host)
    launch = given.a_declared_stalling_container("--name", "audited-stalling")
    async with StdioMCPClient.connect(launch, teardown=teardown) as client:
        assert await client.relaunch()

        assert (await client.call_tool("echo", {})).content == "ok"
    assert teardown.removals_seen == [["-f -v audited-stalling"]]


async def test_a_declared_container_with_no_name_is_relaunched_with_no_removal(
    docker_on_the_host: pathlib.Path,
) -> None:
    async with StdioMCPClient.connect(given.a_declared_stalling_container()) as client:
        assert await client.relaunch()

        assert (await client.call_tool("echo", {})).content == "ok"
    assert removals(docker_on_the_host) == []


async def test_a_named_declared_container_is_removed_when_its_session_ends(
    docker_on_the_host: pathlib.Path,
) -> None:
    launch = given.a_declared_stalling_container("--name", "audited-stalling")
    async with StdioMCPClient.connect(launch) as client:
        assert (await client.call_tool("echo", {})).content == "ok"

    assert removals(docker_on_the_host) == ["-f -v audited-stalling"]


async def test_a_named_declared_container_is_removed_when_its_session_ends_on_an_error(
    docker_on_the_host: pathlib.Path,
) -> None:
    launch = given.a_declared_stalling_container("--name", "audited-stalling")
    with pytest.raises(ValueError, match=r"^body$"):
        async with StdioMCPClient.connect(launch):
            raise ValueError("body")

    assert removals(docker_on_the_host) == ["-f -v audited-stalling"]


async def test_a_named_declared_container_is_removed_when_its_session_fails_to_open(
    docker_on_the_host: pathlib.Path,
) -> None:
    launch = given.a_declared_stalling_container(
        "--name", "audited-stalling", server_flags=("--exit-before-initialize",)
    )
    with pytest.raises(ExceptionGroup):
        async with StdioMCPClient.connect(launch):
            pass

    assert removals(docker_on_the_host) == ["-f -v audited-stalling"]


async def test_an_audit_relaunches_its_server_from_a_graph_node(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    report = await a_scripted_audit_of(a_stalling_server(), tools=frozenset({"exit"})).run()

    assert report is not None
    assert [(r.tool_name, r.cause, r.succeeded) for r in report.relaunches] == [
        ("exit", RelaunchCause.LOST_CONNECTION, True)
    ]
    assert report.is_complete
