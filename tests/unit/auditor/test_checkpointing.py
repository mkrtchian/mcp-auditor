from pathlib import Path

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver  # type: ignore[import-untyped]

import tests.unit.auditor.support.test_checkpointing_given as given
import tests.unit.auditor.support.test_checkpointing_then as then
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.checkpointing import (
    CheckpointFromEarlierVersion,
    compute_thread_id,
    resume_or_reset,
)
from mcp_auditor.domain.relayed_environment import RelayedEnvironment, RelayedVariable
from tests.fakes import FakeMCPClient
from tests.unit.auditor.support.graph_builders import (
    a_fake_llm_for_multi_tool_audit,
    a_graph_with_checkpointer,
    a_server_dying_on,
    a_tool,
    an_initial_state,
    invoke_graph_with_config,
)

# Channels a graph of an earlier version declared, under names the graph no longer has.
EARLIER_CHANNELS = [
    "refused_steps",
    "chain_step_refused",
    "target",
    "judged_cases",
    "missed_steps",
    "chain_step_missed",
]


async def test_resuming_a_crashed_audit_finishes_without_reauditing(tmp_path: Path):
    client = given.ServerDyingOnCall([a_tool("first"), a_tool("second")], dies_on_call=2)
    fake_llm = a_fake_llm_for_multi_tool_audit([1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = a_graph_with_checkpointer(fake_llm, client, checkpointer)
        config = {"configurable": {"thread_id": "crashed-audit"}}
        assert not await resume_or_reset(graph, "crashed-audit", requested=False)
        with pytest.raises(ConnectionError):
            await invoke_graph_with_config(graph, an_initial_state(), config)
        calls_before_crash = list(client.calls)

        assert await resume_or_reset(graph, "crashed-audit", requested=True)
        result = await invoke_graph_with_config(graph, None, config)

    then.each_tool_audited_once(result, ["first", "second"])
    assert len(client.calls) == len(calls_before_crash) + 1


async def test_a_resumed_audit_of_a_server_taken_as_down_audits_the_tools_left(tmp_path: Path):
    tools = [a_tool("dies"), a_tool("second")]
    fake_llm = given.an_llm_interrupted_on_the_first_judgment(cases_per_tool=[1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        config = {"configurable": {"thread_id": "taken-as-down"}}
        down = a_server_dying_on(tools, "dies", relaunches=False)
        graph = a_graph_with_checkpointer(fake_llm, down, checkpointer)
        with pytest.raises(given.Interrupted):
            await invoke_graph_with_config(graph, an_initial_state(), config)

        resumed = a_graph_with_checkpointer(fake_llm, FakeMCPClient(tools), checkpointer)
        assert await resume_or_reset(resumed, "taken-as-down", requested=True)
        result = await invoke_graph_with_config(resumed, None, config)

    then.each_tool_audited_once(result, ["dies", "second"])
    then.no_tool_in_a_server_down_gap(result)


async def test_relaunches_recorded_before_an_interruption_stay_in_the_report():
    tools = [a_tool("dies"), a_tool("second")]
    fake_llm = given.an_llm_interrupted_on_the_second_generation(cases_per_tool=[1, 1])
    checkpointer = InMemorySaver()
    graph = a_graph_with_checkpointer(
        fake_llm, a_server_dying_on(tools, "dies", relaunches=True), checkpointer
    )
    config = {"configurable": {"thread_id": "relaunched"}}
    with pytest.raises(given.Interrupted):
        await invoke_graph_with_config(graph, an_initial_state(), config)

    assert await resume_or_reset(graph, "relaunched", requested=True)
    result = await invoke_graph_with_config(graph, None, config)

    then.each_tool_audited_once(result, ["dies", "second"])
    assert [relaunch.tool_name for relaunch in result["audit_report"].relaunches] == ["dies"]


async def test_a_checkpoint_without_the_keys_of_calls_not_sent_resumes_as_before():
    tools = [a_tool("first"), a_tool("second")]
    fake_llm = given.an_llm_interrupted_on_the_second_generation(cases_per_tool=[1, 1])
    checkpointer = InMemorySaver()
    graph = a_graph_with_checkpointer(fake_llm, FakeMCPClient(tools), checkpointer)
    config = {"configurable": {"thread_id": "before-relaunch"}}
    with pytest.raises(given.Interrupted):
        await invoke_graph_with_config(graph, an_initial_state(), config)
    await given.a_latest_checkpoint_without(checkpointer, "before-relaunch", given.RELAUNCH_KEYS)

    assert await resume_or_reset(graph, "before-relaunch", requested=True)
    result = await invoke_graph_with_config(graph, None, config)

    then.each_tool_audited_once(result, ["first", "second"])
    then.no_tool_has_a_gap(result)
    assert result["audit_report"].relaunches == []


async def test_resuming_a_completed_audit_runs_a_fresh_one(tmp_path: Path):
    client = FakeMCPClient([a_tool("first")])
    fake_llm = a_fake_llm_for_multi_tool_audit([1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = a_graph_with_checkpointer(fake_llm, client, checkpointer)
        config = {"configurable": {"thread_id": "completed-audit"}}
        assert not await resume_or_reset(graph, "completed-audit", requested=False)
        await invoke_graph_with_config(graph, an_initial_state(), config)

        assert not await resume_or_reset(graph, "completed-audit", requested=True)
        result = await invoke_graph_with_config(graph, an_initial_state(), config)

    then.each_tool_audited_once(result, ["first"])


async def test_reauditing_the_same_server_does_not_accumulate_the_previous_report(tmp_path: Path):
    client = FakeMCPClient([a_tool("first")])
    fake_llm = a_fake_llm_for_multi_tool_audit([1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = a_graph_with_checkpointer(fake_llm, client, checkpointer)
        config = {"configurable": {"thread_id": "same-server"}}
        await resume_or_reset(graph, "same-server", requested=False)
        await invoke_graph_with_config(graph, an_initial_state(), config)

        await resume_or_reset(graph, "same-server", requested=False)
        result = await invoke_graph_with_config(graph, an_initial_state(), config)

    then.each_tool_audited_once(result, ["first"])


async def test_wiping_a_thread_on_a_database_that_was_never_written(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "virgin.db")) as checkpointer:
        graph = a_graph_with_checkpointer(
            a_fake_llm_for_multi_tool_audit([]), FakeMCPClient([]), checkpointer
        )

        assert not await resume_or_reset(graph, "never-audited", requested=False)


async def test_an_unfinished_thread_is_resumable_and_survives_the_decision(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = await given.a_crashed_audit(checkpointer, "unfinished")

        assert await resume_or_reset(graph, "unfinished", requested=True)
        assert (await graph.aget_state({"configurable": {"thread_id": "unfinished"}})).next


async def test_an_unfinished_thread_is_wiped_when_resume_was_not_asked(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = await given.a_crashed_audit(checkpointer, "unfinished")

        assert not await resume_or_reset(graph, "unfinished", requested=False)
        assert not (await graph.aget_state({"configurable": {"thread_id": "unfinished"}})).values


async def test_a_thread_with_nothing_stored_is_not_resumable(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = a_graph_with_checkpointer(
            a_fake_llm_for_multi_tool_audit([]), FakeMCPClient([]), checkpointer
        )

        assert not await resume_or_reset(graph, "never-audited", requested=True)


@pytest.mark.parametrize("earlier_channel", EARLIER_CHANNELS)
async def test_a_checkpoint_from_an_earlier_version_refuses_to_resume(earlier_channel: str):
    checkpointer = InMemorySaver()
    graph = await given.a_crashed_audit(checkpointer, "earlier")
    await given.a_latest_checkpoint_holding(checkpointer, "earlier", earlier_channel)

    with pytest.raises(
        CheckpointFromEarlierVersion,
        match="checkpoint written by an earlier version, run without --resume",
    ):
        await resume_or_reset(graph, "earlier", requested=True)


async def test_an_unfinished_checkpoint_without_earlier_channels_resumes():
    checkpointer = InMemorySaver()
    graph = await given.a_crashed_audit(checkpointer, "current")

    assert await resume_or_reset(graph, "current", requested=True)


async def test_a_thread_interrupted_before_its_first_checkpoint_under_an_earlier_version_refuses():
    checkpointer = InMemorySaver()
    graph = await given.a_thread_interrupted_before_its_first_checkpoint(
        checkpointer, "earlier", "target"
    )

    with pytest.raises(CheckpointFromEarlierVersion):
        await resume_or_reset(graph, "earlier", requested=True)


async def test_a_thread_interrupted_before_its_first_checkpoint_resumes():
    checkpointer = InMemorySaver()
    graph = await given.a_thread_interrupted_before_its_first_checkpoint(
        checkpointer, "current", "server_command"
    )

    assert await resume_or_reset(graph, "current", requested=True)


async def test_a_checkpoint_holding_the_classes_of_an_earlier_version_refuses_to_resume():
    checkpointer = InMemorySaver()
    graph = await given.a_crashed_audit(checkpointer, "earlier")
    await given.a_latest_checkpoint_holding(
        checkpointer, "earlier", "missed_steps", [given.MISSED_STEP_OF_AN_EARLIER_VERSION]
    )

    with pytest.raises(CheckpointFromEarlierVersion):
        await resume_or_reset(graph, "earlier", requested=True)


@pytest.mark.parametrize("earlier_channel", EARLIER_CHANNELS)
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
