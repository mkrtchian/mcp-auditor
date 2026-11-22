from collections.abc import AsyncIterator
from typing import Any

from tests.unit.auditor.support.graph_builders import (
    a_fake_llm_for_single_tool_with_a_two_step_chain,
    a_graph,
    a_server_echoing,
    a_tool,
    an_initial_state,
)

type StreamEvent = tuple[tuple[str, ...], dict[str, Any]]


async def events_of_a_real_audit_with_one_chain() -> list[StreamEvent]:
    tool = a_tool(name="get_user")
    graph = a_graph(
        a_fake_llm_for_single_tool_with_a_two_step_chain(), a_server_echoing(tool, "user found")
    )
    stream: AsyncIterator[Any] = graph.astream(
        an_initial_state(chain_budget=1), stream_mode="updates", subgraphs=True
    )
    return [event async for event in stream]
