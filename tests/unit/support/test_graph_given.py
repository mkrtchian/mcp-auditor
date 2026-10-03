from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain import (
    AttackContext,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainPlanBatch,
    EvalVerdict,
    Judgment,
    ProviderUsage,
    Severity,
    StepObservation,
    TestCaseBatch,
    ToolDefinition,
    ToolResponse,
)
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.ports import ProviderRefusal
from mcp_auditor.domain.redaction import Redaction
from mcp_auditor.graph.builder import build_dry_run_graph, build_graph
from tests.fakes import FakeLLM, FakeMCPClient


def a_tool(
    name: str = "test_tool",
    description: str = "A test tool",
    input_schema: dict[str, Any] | None = None,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=input_schema or {"type": "object", "properties": {}},
    )


def a_fake_llm_for_single_tool_audit(
    num_cases: int = 1,
    extraction_response: AttackContext | None = None,
) -> FakeLLM:
    batch = a_complete_batch(num_cases)
    judgments = [a_judgment() for _ in range(num_cases)]
    context = extraction_response or AttackContext()
    return FakeLLM([batch, *judgments, context])


def a_fake_llm_for_destructive_and_safe_case() -> FakeLLM:
    batch = TestCaseBatch(
        cases=[
            a_payload(arguments={"command": "rm -rf /"}),
            a_payload(category=AuditCategory.INFO_LEAKAGE, arguments={"input": "malicious"}),
        ]
    )
    return FakeLLM([batch, a_judgment(), AttackContext()])


def a_fake_llm_for_multi_tool_audit(cases_per_tool: list[int]) -> FakeLLM:
    responses: list[BaseModel] = []
    for num_cases in cases_per_tool:
        batch = a_complete_batch(num_cases)
        judgments = [a_judgment() for _ in range(num_cases)]
        responses.extend([batch, *judgments, AttackContext()])
    return FakeLLM(responses)


def a_fake_llm_whose_first_tool_batch_stays_short(cases_per_tool: int) -> FakeLLM:
    short = a_complete_batch(cases_per_tool - 1)
    short_judgments = [a_judgment() for _ in short.cases]
    complete = a_complete_batch(cases_per_tool)
    complete_judgments = [a_judgment() for _ in complete.cases]
    first_tool = [short, short, a_complete_batch(1), *short_judgments, AttackContext()]
    second_tool = [complete, *complete_judgments, AttackContext()]
    return FakeLLM([*first_tool, *second_tool])


def a_fake_dry_run_llm_whose_batch_stays_short(budget: int) -> FakeLLM:
    short = a_complete_batch(budget - 1)
    return FakeLLM([short, short, a_complete_batch(1)])


def a_fake_llm_refusing_the_first_of_two_judgments() -> FakeLLM:
    return FakeLLM([a_complete_batch(2), a_provider_refusal(), a_judgment(), AttackContext()])


def a_fake_llm_refusing_the_first_tool_generation(cases_per_tool: int) -> FakeLLM:
    judgments = [a_judgment() for _ in range(cases_per_tool)]
    first_tool = [a_provider_refusal(), AttackContext()]
    second_tool = [a_complete_batch(cases_per_tool), *judgments, AttackContext()]
    return FakeLLM([*first_tool, *second_tool])


def a_fake_llm_refusing_the_chain_planning() -> FakeLLM:
    return FakeLLM([a_complete_batch(1), a_judgment(), a_provider_refusal(), AttackContext()])


def a_fake_llm_refusing_the_first_chain_observation() -> FakeLLM:
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("first chain"), a_chain_goal("second chain")])
    stop_obs = StepObservation(observation="dead end", should_continue=False)
    first_chain = [a_provider_refusal(), a_judgment()]
    second_chain = [stop_obs, a_judgment()]
    single_step = [a_complete_batch(1), a_judgment()]
    return FakeLLM([*single_step, chain_plan, *first_chain, *second_chain, AttackContext()])


def a_fake_llm_refusing_the_chain_step_planning() -> FakeLLM:
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    continue_obs = StepObservation(observation="promising", should_continue=True)
    chain = [chain_plan, continue_obs, a_provider_refusal(), a_judgment()]
    return FakeLLM([a_complete_batch(1), a_judgment(), *chain, AttackContext()])


def a_provider_refusal() -> ProviderRefusal:
    return ProviderRefusal("flagged by policy", ProviderUsage(input_tokens=7, output_tokens=0))


# The graph wrappers below look trivial but are a typing seam: langgraph's
# CompiledStateGraph is partially unknown under strict pyright, so tests go
# through these Any-typed helpers instead of calling ainvoke directly.
def a_graph(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient):
    return build_graph(fake_llm, AuditedServer(fake_mcp_client))


def a_redacting_graph(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient, secrets: dict[str, str]):
    return build_graph(fake_llm, AuditedServer(fake_mcp_client, Redaction(secrets)))


def a_dry_run_graph(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient):
    return build_dry_run_graph(fake_llm, AuditedServer(fake_mcp_client))


def a_graph_with_checkpointer(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient, checkpointer: Any):
    return build_graph(fake_llm, AuditedServer(fake_mcp_client), checkpointer=checkpointer)


async def invoke_graph(graph: Any, state: dict[str, Any]) -> dict[str, Any]:
    return await graph.ainvoke(state)


async def invoke_graph_with_config(
    graph: Any, state: dict[str, Any] | None, config: dict[str, Any]
) -> dict[str, Any]:
    return await graph.ainvoke(state, config=config)


def an_initial_state(
    test_budget: int = 1,
    chain_budget: int = 0,
    max_chain_steps: int = 3,
) -> dict[str, Any]:
    return {
        "target": "python honeypot_server.py",
        "discovered_tools": [],
        "test_budget": test_budget,
        "current_tool": None,
        "judged_cases": [],
        "tool_reports": [],
        "provider_usage": [],
        "audit_report": None,
        "attack_context": AttackContext(),
        "chain_budget": chain_budget,
        "max_chain_steps": max_chain_steps,
        "completed_chains": [],
    }


def a_fake_llm_for_single_tool_with_chain(num_cases: int = 1) -> FakeLLM:
    batch = a_complete_batch(num_cases)
    judgments = [a_judgment() for _ in range(num_cases)]
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    step_obs = StepObservation(observation="dead end", should_continue=False)
    chain_judgment = a_judgment()
    context = AttackContext()
    return FakeLLM([batch, *judgments, chain_plan, step_obs, chain_judgment, context])


def a_fake_llm_for_single_tool_with_a_two_step_chain() -> FakeLLM:
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    continue_obs = StepObservation(observation="promising", should_continue=True)
    stop_obs = StepObservation(observation="dead end", should_continue=False)
    chain = [chain_plan, continue_obs, a_payload(), stop_obs, a_judgment()]
    return FakeLLM([a_complete_batch(1), a_judgment(), *chain, AttackContext()])


def a_server_echoing(tool: ToolDefinition, content: str) -> FakeMCPClient:
    return FakeMCPClient([tool], {tool.name: ToolResponse(content=content)})


def a_fake_llm_for_single_tool_with_two_chains(num_cases: int = 1) -> FakeLLM:
    batch = a_complete_batch(num_cases)
    judgments = [a_judgment() for _ in range(num_cases)]
    chain_plan = ChainPlanBatch(
        chains=[
            a_chain_goal("first chain"),
            a_chain_goal("second chain", category=AuditCategory.INFO_LEAKAGE),
        ]
    )
    stop_obs = StepObservation(observation="dead end", should_continue=False)
    context = AttackContext()
    return FakeLLM(
        [batch, *judgments, chain_plan, stop_obs, a_judgment(), stop_obs, a_judgment(), context]
    )


def a_complete_batch(num_cases: int) -> TestCaseBatch:
    categories = list(AuditCategory)
    return TestCaseBatch(
        cases=[a_payload(category=categories[i % len(categories)]) for i in range(num_cases)]
    )


def a_chain_goal(
    description: str,
    category: AuditCategory = AuditCategory.INJECTION,
) -> ChainGoal:
    return ChainGoal(
        description=description,
        category=category,
        first_step=a_payload(category=category),
    )


def a_payload(
    category: AuditCategory = AuditCategory.INJECTION,
    arguments: dict[str, Any] | None = None,
) -> AuditPayload:
    return AuditPayload(
        category=category,
        description="test payload",
        arguments=arguments or {"input": "malicious"},
    )


def a_judgment(
    verdict: EvalVerdict = EvalVerdict.FAIL,
    severity: Severity = Severity.MEDIUM,
) -> Judgment:
    return Judgment(
        verdict=verdict,
        justification="test justification",
        severity=severity,
    )
