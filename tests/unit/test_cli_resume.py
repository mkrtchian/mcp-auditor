from pathlib import Path
from typing import Any

import pytest
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver  # type: ignore[import-untyped]

import tests.unit.support.test_graph_given as given
from mcp_auditor.cli import resume_or_reset
from mcp_auditor.domain.models import ToolDefinition, ToolResponse
from tests.fakes import FakeMCPClient


class ServerDyingOnCall(FakeMCPClient):
    """Raises once on the nth call_tool, then behaves normally."""

    def __init__(self, tools: list[ToolDefinition], dies_on_call: int):
        super().__init__(tools)
        self._dies_on_call = dies_on_call

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        if len(self.calls) + 1 == self._dies_on_call:
            self._dies_on_call = 0
            raise ConnectionError("server died mid-audit")
        return await super().call_tool(name, args)


@pytest.mark.asyncio
async def test_resuming_a_crashed_audit_finishes_without_reauditing(tmp_path: Path):
    client = ServerDyingOnCall([given.a_tool("first"), given.a_tool("second")], dies_on_call=2)
    fake_llm = given.a_fake_llm_for_multi_tool_audit([1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = given.a_graph_with_checkpointer(fake_llm, client, checkpointer)
        config = {"configurable": {"thread_id": "crashed-audit"}}
        assert not await resume_or_reset(graph, "crashed-audit", requested=False)
        with pytest.raises(ConnectionError):
            await given.invoke_graph_with_config(graph, given.an_initial_state(), config)
        calls_before_crash = list(client.calls)

        assert await resume_or_reset(graph, "crashed-audit", requested=True)
        result = await given.invoke_graph_with_config(graph, None, config)

    then_each_tool_audited_once(result, ["first", "second"])
    assert len(client.calls) == len(calls_before_crash) + 1


@pytest.mark.asyncio
async def test_resuming_a_completed_audit_runs_a_fresh_one(tmp_path: Path):
    client = FakeMCPClient([given.a_tool("first")])
    fake_llm = given.a_fake_llm_for_multi_tool_audit([1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = given.a_graph_with_checkpointer(fake_llm, client, checkpointer)
        config = {"configurable": {"thread_id": "completed-audit"}}
        assert not await resume_or_reset(graph, "completed-audit", requested=False)
        await given.invoke_graph_with_config(graph, given.an_initial_state(), config)

        assert not await resume_or_reset(graph, "completed-audit", requested=True)
        result = await given.invoke_graph_with_config(graph, given.an_initial_state(), config)

    then_each_tool_audited_once(result, ["first"])


@pytest.mark.asyncio
async def test_reauditing_the_same_target_does_not_accumulate_the_previous_report(tmp_path: Path):
    client = FakeMCPClient([given.a_tool("first")])
    fake_llm = given.a_fake_llm_for_multi_tool_audit([1, 1])

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = given.a_graph_with_checkpointer(fake_llm, client, checkpointer)
        config = {"configurable": {"thread_id": "same-target"}}
        await resume_or_reset(graph, "same-target", requested=False)
        await given.invoke_graph_with_config(graph, given.an_initial_state(), config)

        await resume_or_reset(graph, "same-target", requested=False)
        result = await given.invoke_graph_with_config(graph, given.an_initial_state(), config)

    then_each_tool_audited_once(result, ["first"])


@pytest.mark.asyncio
async def test_wiping_a_thread_on_a_database_that_was_never_written(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "virgin.db")) as checkpointer:
        graph = given.a_graph_with_checkpointer(
            given.a_fake_llm_for_multi_tool_audit([]), FakeMCPClient([]), checkpointer
        )

        assert not await resume_or_reset(graph, "never-audited", requested=False)


@pytest.mark.asyncio
async def test_an_unfinished_thread_is_resumable_and_survives_the_decision(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = await given_a_crashed_audit(checkpointer, "unfinished")

        assert await resume_or_reset(graph, "unfinished", requested=True)
        assert (await graph.aget_state({"configurable": {"thread_id": "unfinished"}})).next


@pytest.mark.asyncio
async def test_an_unfinished_thread_is_wiped_when_resume_was_not_asked(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = await given_a_crashed_audit(checkpointer, "unfinished")

        assert not await resume_or_reset(graph, "unfinished", requested=False)
        assert not (await graph.aget_state({"configurable": {"thread_id": "unfinished"}})).values


@pytest.mark.asyncio
async def test_a_thread_with_nothing_stored_is_not_resumable(tmp_path: Path):
    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "checkpoints.db")) as checkpointer:
        graph = given.a_graph_with_checkpointer(
            given.a_fake_llm_for_multi_tool_audit([]), FakeMCPClient([]), checkpointer
        )

        assert not await resume_or_reset(graph, "never-audited", requested=True)


async def given_a_crashed_audit(checkpointer: Any, thread_id: str):
    client = ServerDyingOnCall([given.a_tool("first")], dies_on_call=1)
    graph = given.a_graph_with_checkpointer(
        given.a_fake_llm_for_multi_tool_audit([1]), client, checkpointer
    )
    with pytest.raises(ConnectionError):
        await given.invoke_graph_with_config(
            graph, given.an_initial_state(), {"configurable": {"thread_id": thread_id}}
        )
    return graph


def then_each_tool_audited_once(result: dict[str, Any], tool_names: list[str]) -> None:
    reports = result["audit_report"].tool_reports
    assert [report.tool.name for report in reports] == tool_names
