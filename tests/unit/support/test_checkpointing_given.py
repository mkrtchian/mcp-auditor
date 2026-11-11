from enum import StrEnum
from typing import Any

import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import CheckpointMetadata, empty_checkpoint
from langgraph.checkpoint.base.id import uuid6
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import BaseModel

import tests.unit.support.test_graph_given as graph_given
from mcp_auditor.domain.models import MissCause, ToolDefinition, ToolResponse
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
    checkpointer: InMemorySaver, thread_id: str, channel: str, value: Any = None
) -> None:
    latest = await checkpointer.aget_tuple(
        {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
    )
    assert latest is not None
    checkpoint = latest.checkpoint.copy()
    checkpoint["id"] = str(uuid6())
    checkpoint["channel_values"] = {
        **checkpoint["channel_values"],
        channel: [] if value is None else value,
    }
    checkpoint["channel_versions"] = {**checkpoint["channel_versions"], channel: "1"}
    await checkpointer.aput(latest.config, checkpoint, latest.metadata, {channel: "1"})


async def a_thread_interrupted_before_its_first_checkpoint(
    checkpointer: InMemorySaver, thread_id: str, input_channel: str
) -> Any:
    graph = graph_given.a_graph_with_checkpointer(
        graph_given.a_fake_llm_for_multi_tool_audit([]), FakeMCPClient([]), checkpointer
    )
    checkpoint = empty_checkpoint()
    checkpoint["channel_values"] = {"__start__": {input_channel: "python server.py"}}
    checkpoint["channel_versions"] = {"__start__": "1"}
    config: RunnableConfig = {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
    metadata: CheckpointMetadata = {"source": "input", "step": -1, "parents": {}}
    await checkpointer.aput(config, checkpoint, metadata, {"__start__": "1"})
    return graph


class _AuditStepOfAnEarlierVersion(StrEnum):
    JUDGMENT = "judgment"


class _MissedStepOfAnEarlierVersion(BaseModel):
    tool_name: str
    step: _AuditStepOfAnEarlierVersion
    cause: MissCause
    detail: str


# Serialized under the class names an earlier version defined, which no module defines now.
_AuditStepOfAnEarlierVersion.__name__ = "AuditStep"
_MissedStepOfAnEarlierVersion.__name__ = "MissedStep"
for _earlier in (_AuditStepOfAnEarlierVersion, _MissedStepOfAnEarlierVersion):
    _earlier.__module__ = "mcp_auditor.domain.models"

MISSED_STEP_OF_AN_EARLIER_VERSION = _MissedStepOfAnEarlierVersion(
    tool_name="first",
    step=_AuditStepOfAnEarlierVersion.JUDGMENT,
    cause=MissCause.PROVIDER_REFUSAL,
    detail="refused",
)
