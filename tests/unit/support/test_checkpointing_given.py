from typing import Any

import pytest
from langgraph.checkpoint.base.id import uuid6
from langgraph.checkpoint.memory import InMemorySaver

import tests.unit.support.test_graph_given as graph_given
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


async def a_crashed_audit(checkpointer: Any, thread_id: str):
    client = ServerDyingOnCall([graph_given.a_tool("first")], dies_on_call=1)
    graph = graph_given.a_graph_with_checkpointer(
        graph_given.a_fake_llm_for_multi_tool_audit([1]), client, checkpointer
    )
    with pytest.raises(ConnectionError):
        await graph_given.invoke_graph_with_config(
            graph, graph_given.an_initial_state(), {"configurable": {"thread_id": thread_id}}
        )
    return graph


async def a_latest_checkpoint_holding(
    checkpointer: InMemorySaver, thread_id: str, channel: str
) -> None:
    latest = await checkpointer.aget_tuple(
        {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
    )
    assert latest is not None
    checkpoint = latest.checkpoint.copy()
    checkpoint["id"] = str(uuid6())
    checkpoint["channel_values"] = {**checkpoint["channel_values"], channel: []}
    checkpoint["channel_versions"] = {**checkpoint["channel_versions"], channel: "1"}
    await checkpointer.aput(latest.config, checkpoint, latest.metadata, {channel: "1"})
