from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import (
    AttackContext,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainPlanBatch,
    EvalVerdict,
    Judgment,
    Severity,
    StepObservation,
    TestCaseBatch,
    ToolDefinition,
    ToolResponse,
)
from mcp_auditor.domain.redaction import Redaction
from mcp_auditor.graph.builder import build_dry_run_graph, build_graph
from tests.fakes import FakeLLM, FakeMCPClient
from tests.fakes.mcp_client import a_lost_connection_response


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


def a_fake_llm_for_multi_tool_audit(cases_per_tool: list[int]) -> FakeLLM:
    responses: list[BaseModel] = []
    for num_cases in cases_per_tool:
        judgments = [a_judgment() for _ in range(num_cases)]
        responses.extend([a_complete_batch(num_cases), *judgments, AttackContext()])
    return FakeLLM(responses)


def a_fake_llm_for_single_tool_with_a_two_step_chain() -> FakeLLM:
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    continue_obs = StepObservation(observation="promising", should_continue=True)
    stop_obs = StepObservation(observation="dead end", should_continue=False)
    chain = [chain_plan, continue_obs, a_payload(), stop_obs, a_judgment()]
    return FakeLLM([a_complete_batch(1), a_judgment(), *chain, AttackContext()])


def a_server_echoing(tool: ToolDefinition, content: str) -> FakeMCPClient:
    return FakeMCPClient([tool], {tool.name: ToolResponse(content=content)})


def a_server_dying_on(
    tools: list[ToolDefinition], tool_name: str, relaunches: bool
) -> FakeMCPClient:
    """The first call to the tool loses its connection, and the relaunch succeeds or fails."""
    responses = [a_lost_connection_response(), ToolResponse(content="ok")]
    return FakeMCPClient(tools, {tool_name: responses}, relaunch_answers=(relaunches,))


def a_graph(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient):
    return build_graph(fake_llm, AuditedServer(fake_mcp_client))


def a_redacting_graph(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient, secrets: dict[str, str]):
    return build_graph(fake_llm, AuditedServer(fake_mcp_client, Redaction(secrets)))


def a_dry_run_graph(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient):
    return build_dry_run_graph(fake_llm, AuditedServer(fake_mcp_client))


def a_graph_with_checkpointer(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient, checkpointer: Any):
    return build_graph(fake_llm, AuditedServer(fake_mcp_client), checkpointer=checkpointer)


def an_initial_state(
    test_budget: int = 1,
    chain_budget: int = 0,
    max_chain_steps: int = 3,
) -> dict[str, Any]:
    return {
        "server_command": "python honeypot_server.py",
        "discovered_tools": [],
        "test_budget": test_budget,
        "current_tool": None,
        "processed_cases": [],
        "tool_reports": [],
        "provider_usage": [],
        "audit_report": None,
        "attack_context": AttackContext(),
        "chain_budget": chain_budget,
        "max_chain_steps": max_chain_steps,
        "completed_chains": [],
    }


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
