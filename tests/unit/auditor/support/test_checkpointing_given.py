from collections.abc import Sequence
from enum import StrEnum
from typing import Any, override

import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import CheckpointMetadata, empty_checkpoint
from langgraph.checkpoint.base.id import uuid6
from langgraph.checkpoint.memory import InMemorySaver
from pydantic import BaseModel

from mcp_auditor.domain.model_calls import MissedCallCause
from mcp_auditor.domain.models import AttackContext, ProviderUsage, ToolDefinition, ToolResponse
from tests.fakes import FakeLLM, FakeMCPClient
from tests.unit.auditor.support.graph_builders import (
    a_complete_batch,
    a_fake_llm_for_multi_tool_audit,
    a_graph_with_checkpointer,
    a_judgment,
    a_tool,
    an_initial_state,
)


class ServerDyingOnCall(FakeMCPClient):
    """Raises once on the nth call_tool, then behaves normally."""

    def __init__(self, tools: list[ToolDefinition], dies_on_call: int):
        super().__init__(tools)
        self._dies_on_call = dies_on_call

    @override
    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        if len(self.calls) + 1 == self._dies_on_call:
            self._dies_on_call = 0
            raise ConnectionError("server died mid-audit")
        return await super().call_tool(name, args)


class Interrupted(Exception):
    """Stands for whatever stops an audit midway: a crash, a kill, a Ctrl-C."""


class InterruptedLLM(FakeLLM):
    """Raises `Interrupted` once, on its nth call, then answers its script."""

    def __init__(self, responses: Sequence[BaseModel], interrupted_on_call: int):
        super().__init__(responses)
        self._interrupted_on_call = interrupted_on_call

    @override
    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        if len(self.prompts) + 1 == self._interrupted_on_call:
            self._interrupted_on_call = 0
            raise Interrupted
        return await super().generate_structured(prompt, output_schema)


def an_llm_interrupted_on_the_first_judgment(cases_per_tool: list[int]) -> InterruptedLLM:
    return _interrupted_on(cases_per_tool, call=2)


def an_llm_interrupted_on_the_second_generation(cases_per_tool: list[int]) -> InterruptedLLM:
    first_tool_calls = cases_per_tool[0] + 2
    return _interrupted_on(cases_per_tool, call=first_tool_calls + 1)


def _interrupted_on(cases_per_tool: list[int], call: int) -> InterruptedLLM:
    script: list[BaseModel] = []
    for num_cases in cases_per_tool:
        judgments = [a_judgment() for _ in range(num_cases)]
        script.extend([a_complete_batch(num_cases), *judgments, AttackContext()])
    return InterruptedLLM(script, interrupted_on_call=call)


# The keys the relaunch of a stopped server added to the graph state.
RELAUNCH_KEYS = ("relaunches", "unsent_cases", "unsent_chains", "unsent_cause")


async def a_latest_checkpoint_without(
    checkpointer: InMemorySaver, thread_id: str, channels: Sequence[str]
) -> None:
    latest = await checkpointer.aget_tuple(
        {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
    )
    assert latest is not None
    checkpoint = latest.checkpoint.copy()
    checkpoint["id"] = str(uuid6())
    # The saver rebuilds the values from the versions, so a channel leaves both.
    for field in ("channel_values", "channel_versions"):
        stored = checkpoint[field]
        checkpoint[field] = {name: value for name, value in stored.items() if name not in channels}
    await checkpointer.aput(latest.config, checkpoint, latest.metadata, {})


async def a_crashed_audit(checkpointer: Any, thread_id: str):
    client = ServerDyingOnCall([a_tool("first")], dies_on_call=1)
    graph = a_graph_with_checkpointer(a_fake_llm_for_multi_tool_audit([1]), client, checkpointer)
    with pytest.raises(ConnectionError):
        await graph.ainvoke(an_initial_state(), config={"configurable": {"thread_id": thread_id}})
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
    graph = a_graph_with_checkpointer(
        a_fake_llm_for_multi_tool_audit([]), FakeMCPClient([]), checkpointer
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
    cause: MissedCallCause
    detail: str


# Serialized under the class names an earlier version defined, which no module defines now.
_AuditStepOfAnEarlierVersion.__name__ = "AuditStep"
_MissedStepOfAnEarlierVersion.__name__ = "MissedStep"
for _earlier in (_AuditStepOfAnEarlierVersion, _MissedStepOfAnEarlierVersion):
    _earlier.__module__ = "mcp_auditor.domain.models"

MISSED_STEP_OF_AN_EARLIER_VERSION = _MissedStepOfAnEarlierVersion(
    tool_name="first",
    step=_AuditStepOfAnEarlierVersion.JUDGMENT,
    cause=MissedCallCause.PROVIDER_REFUSAL,
    detail="refused",
)
