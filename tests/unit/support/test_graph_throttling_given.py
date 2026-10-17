from typing import Any

from mcp_auditor.adapters.llm import LLM, StructuredOutput
from mcp_auditor.adapters.llm_throttling import ThrottlePatience
from mcp_auditor.adapters.throttling import install_throttle_log_handler
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.graph.builder import build_graph
from tests.fakes import FakeMCPClient
from tests.fakes.chat_model import FakeChatModel, Throttled
from tests.unit.support.test_graph_given import a_tool, an_initial_state
from tests.unit.support.test_llm_throttling_given import an_openai_rate_limit

TOOL_NAMES = ["get_user", "list_users"]


async def no_wait(_delay: float) -> None:
    return None


def a_provider_throttling_the_first_generation_past_every_retry() -> FakeChatModel:
    # A 15 s bound: the first wait of 10 s fits, the second of 20 s exhausts the patience.
    return FakeChatModel([Throttled(an_openai_rate_limit()), Throttled(an_openai_rate_limit())])


def an_llm_over(chat_model: FakeChatModel) -> LLM:
    install_throttle_log_handler()
    return LLM(
        chat_model,  # pyright: ignore[reportArgumentType]
        StructuredOutput(method="json_schema", schema_as_dict=True),
        max_parse_attempts=3,
        patience=ThrottlePatience(max_total_wait=15.0, sleep=no_wait, jitter=lambda: 0.0),
    )


async def an_audit_of_two_tools(llm: LLM) -> dict[str, Any]:
    server = AuditedServer(FakeMCPClient([a_tool(name=name) for name in TOOL_NAMES]))
    graph: Any = build_graph(llm, server)
    return await graph.ainvoke(an_initial_state(test_budget=1, chain_budget=1))
