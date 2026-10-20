from pathlib import Path

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver  # type: ignore[import-untyped]

import tests.unit.support.test_checkpointing_given as given
import tests.unit.support.test_checkpointing_then as then
import tests.unit.support.test_graph_given as graph_given
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.checkpointing import (
    CheckpointFromEarlierVersion,
    compute_thread_id,
    resume_or_reset,
)
from mcp_auditor.domain.relayed_environment import RelayedEnvironment, RelayedVariable
from tests.fakes import FakeMCPClient


@pytest.mark.asyncio
async def test_resuming_a_crashed_audit_finishes_without_reauditing(tmp_path: Path):
    client = given.ServerDyingOnCall(
        [graph_given.a_tool("first"), graph_given.a_tool("second")], dies_on_call=2
    )
    fake_llm = graph_given.a_fake_llm_for_multi_tool_audit([1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = graph_given.a_graph_with_checkpointer(fake_llm, client, checkpointer)
        config = {"configurable": {"thread_id": "crashed-audit"}}
        assert not await resume_or_reset(graph, "crashed-audit", requested=False)
        with pytest.raises(ConnectionError):
            await graph_given.invoke_graph_with_config(
                graph, graph_given.an_initial_state(), config
            )
        calls_before_crash = list(client.calls)

        assert await resume_or_reset(graph, "crashed-audit", requested=True)
        result = await graph_given.invoke_graph_with_config(graph, None, config)

    then.each_tool_audited_once(result, ["first", "second"])
    assert len(client.calls) == len(calls_before_crash) + 1


@pytest.mark.asyncio
async def test_resuming_a_completed_audit_runs_a_fresh_one(tmp_path: Path):
    client = FakeMCPClient([graph_given.a_tool("first")])
    fake_llm = graph_given.a_fake_llm_for_multi_tool_audit([1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = graph_given.a_graph_with_checkpointer(fake_llm, client, checkpointer)
        config = {"configurable": {"thread_id": "completed-audit"}}
        assert not await resume_or_reset(graph, "completed-audit", requested=False)
        await graph_given.invoke_graph_with_config(graph, graph_given.an_initial_state(), config)

        assert not await resume_or_reset(graph, "completed-audit", requested=True)
        result = await graph_given.invoke_graph_with_config(
            graph, graph_given.an_initial_state(), config
        )

    then.each_tool_audited_once(result, ["first"])


@pytest.mark.asyncio
async def test_reauditing_the_same_target_does_not_accumulate_the_previous_report(tmp_path: Path):
    client = FakeMCPClient([graph_given.a_tool("first")])
    fake_llm = graph_given.a_fake_llm_for_multi_tool_audit([1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = graph_given.a_graph_with_checkpointer(fake_llm, client, checkpointer)
        config = {"configurable": {"thread_id": "same-target"}}
        await resume_or_reset(graph, "same-target", requested=False)
        await graph_given.invoke_graph_with_config(graph, graph_given.an_initial_state(), config)

        await resume_or_reset(graph, "same-target", requested=False)
        result = await graph_given.invoke_graph_with_config(
            graph, graph_given.an_initial_state(), config
        )

    then.each_tool_audited_once(result, ["first"])


@pytest.mark.asyncio
async def test_wiping_a_thread_on_a_database_that_was_never_written(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "virgin.db")) as checkpointer:
        graph = graph_given.a_graph_with_checkpointer(
            graph_given.a_fake_llm_for_multi_tool_audit([]), FakeMCPClient([]), checkpointer
        )

        assert not await resume_or_reset(graph, "never-audited", requested=False)


@pytest.mark.asyncio
async def test_an_unfinished_thread_is_resumable_and_survives_the_decision(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = await given.a_crashed_audit(checkpointer, "unfinished")

        assert await resume_or_reset(graph, "unfinished", requested=True)
        assert (await graph.aget_state({"configurable": {"thread_id": "unfinished"}})).next


@pytest.mark.asyncio
async def test_an_unfinished_thread_is_wiped_when_resume_was_not_asked(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = await given.a_crashed_audit(checkpointer, "unfinished")

        assert not await resume_or_reset(graph, "unfinished", requested=False)
        assert not (await graph.aget_state({"configurable": {"thread_id": "unfinished"}})).values


@pytest.mark.asyncio
async def test_a_thread_with_nothing_stored_is_not_resumable(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = graph_given.a_graph_with_checkpointer(
            graph_given.a_fake_llm_for_multi_tool_audit([]), FakeMCPClient([]), checkpointer
        )

        assert not await resume_or_reset(graph, "never-audited", requested=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("earlier_channel", ["refused_steps", "chain_step_refused"])
async def test_a_checkpoint_from_an_earlier_version_refuses_to_resume(earlier_channel: str):
    checkpointer = InMemorySaver()
    graph = await given.a_crashed_audit(checkpointer, "earlier")
    await given.a_latest_checkpoint_holding(checkpointer, "earlier", earlier_channel)

    with pytest.raises(
        CheckpointFromEarlierVersion,
        match="checkpoint written by an earlier version, run without --resume",
    ):
        await resume_or_reset(graph, "earlier", requested=True)


@pytest.mark.asyncio
async def test_an_unfinished_checkpoint_without_earlier_channels_resumes():
    checkpointer = InMemorySaver()
    graph = await given.a_crashed_audit(checkpointer, "current")

    assert await resume_or_reset(graph, "current", requested=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("earlier_channel", ["refused_steps", "chain_step_refused"])
async def test_a_checkpoint_from_an_earlier_version_is_wiped_when_resume_was_not_asked(
    earlier_channel: str,
):
    checkpointer = InMemorySaver()
    graph = await given.a_crashed_audit(checkpointer, "earlier")
    await given.a_latest_checkpoint_holding(checkpointer, "earlier", earlier_channel)

    assert not await resume_or_reset(graph, "earlier", requested=False)
    assert not (await graph.aget_state({"configurable": {"thread_id": "earlier"}})).values


def test_an_unconfined_thread_id_is_the_one_audits_used_before_confinement():
    assert compute_thread_id(ServerLaunch.unconfined("python", ["server.py"])) == "7cc34ebdac143b58"


def test_a_declared_container_gets_its_own_thread():
    unconfined = compute_thread_id(ServerLaunch.unconfined("docker", ["run", "img"]))
    declared = compute_thread_id(ServerLaunch.declared_container("docker", ["run", "img"], {}))

    assert unconfined != declared


def test_no_argument_can_forge_another_regimes_thread_id():
    declared = compute_thread_id(ServerLaunch.declared_container("docker", ["run", "img"], {}))
    forged = compute_thread_id(
        ServerLaunch.unconfined("docker", ["run", "img", "declared_container"])
    )

    assert declared != forged


def test_two_equal_launches_share_a_thread():
    first = ServerLaunch.unconfined("npx", ["some-server", "/tmp/data"])
    second = ServerLaunch.unconfined("npx", ["some-server", "/tmp/data"])

    assert compute_thread_id(first) == compute_thread_id(second)


def test_relaying_variables_keeps_the_unconfined_thread_id():
    relayed = RelayedEnvironment((RelayedVariable("GITHUB_TOKEN", "ghp_value", redacted=True),))
    launch = ServerLaunch.unconfined("python", ["server.py"], relayed=relayed)

    assert compute_thread_id(launch) == "7cc34ebdac143b58"
