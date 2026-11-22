from typing import Any

from mcp_auditor.adapters.llm import LLM
from mcp_auditor.adapters.llm_throttling import ThrottlePatience
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.graph.builder import build_graph
from tests.fakes import FakeMCPClient
from tests.fakes.chat_model import FakeChatModel, Throttled
from tests.unit.auditor.support.graph_builders import a_tool, an_initial_state
from tests.unit.support.provider_errors import an_openai_rate_limit

TOOL_NAMES = ["get_user", "list_users"]


def a_provider_throttling_twice() -> FakeChatModel:
    return FakeChatModel([Throttled(an_openai_rate_limit()), Throttled(an_openai_rate_limit())])


def a_patience_of(max_total_wait: float) -> ThrottlePatience:
    # No jitter, so the waits are 10 s then 20 s.
    return ThrottlePatience(max_total_wait=max_total_wait, sleep=_no_wait, jitter=lambda: 0.0)


async def _no_wait(_delay: float) -> None:
    return None


async def an_audit_of_two_tools(llm: LLM) -> dict[str, Any]:
    server = AuditedServer(FakeMCPClient([a_tool(name=name) for name in TOOL_NAMES]))
    graph: Any = build_graph(llm, server)
    return await graph.ainvoke(an_initial_state(test_budget=1, chain_budget=1))
