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
    Severity,
    StepObservation,
    TestCaseBatch,
    ToolDefinition,
)
from mcp_auditor.graph.builder import build_graph
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
    batch = TestCaseBatch(cases=[a_payload() for _ in range(num_cases)])
    judgments = [a_judgment() for _ in range(num_cases)]
    context = extraction_response or AttackContext()
    return FakeLLM([batch, *judgments, context])


def a_fake_llm_for_multi_tool_audit(cases_per_tool: list[int]) -> FakeLLM:
    responses: list[BaseModel] = []
    for num_cases in cases_per_tool:
        batch = TestCaseBatch(cases=[a_payload() for _ in range(num_cases)])
        judgments = [a_judgment() for _ in range(num_cases)]
        responses.extend([batch, *judgments, AttackContext()])
    return FakeLLM(responses)


def a_graph(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient):
    return build_graph(fake_llm, fake_mcp_client)


def a_graph_with_checkpointer(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient, checkpointer: Any):
    return build_graph(fake_llm, fake_mcp_client, checkpointer=checkpointer)


async def invoke_graph(graph: Any, state: dict[str, Any]) -> dict[str, Any]:
    return await graph.ainvoke(state)


async def invoke_graph_with_config(
    graph: Any, state: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any]:
    return await graph.ainvoke(state, config=config)


def an_initial_state(
    test_budget: int = 5,
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
        "token_usage": [],
        "audit_report": None,
        "attack_context": AttackContext(),
        "chain_budget": chain_budget,
        "max_chain_steps": max_chain_steps,
        "completed_chains": [],
    }


def a_fake_llm_for_single_tool_with_chain(num_cases: int = 1) -> FakeLLM:
    batch = TestCaseBatch(cases=[a_payload() for _ in range(num_cases)])
    judgments = [a_judgment() for _ in range(num_cases)]
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    step_obs = StepObservation(observation="dead end", should_continue=False)
    chain_judgment = a_judgment()
    context = AttackContext()
    return FakeLLM([batch, *judgments, chain_plan, step_obs, chain_judgment, context])


def a_fake_llm_for_single_tool_with_two_chains(num_cases: int = 1) -> FakeLLM:
    batch = TestCaseBatch(cases=[a_payload() for _ in range(num_cases)])
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


def a_chain_goal(
    description: str,
    category: AuditCategory = AuditCategory.INJECTION,
) -> ChainGoal:
    return ChainGoal(
        description=description,
        category=category,
        first_step=a_payload(category=category),
    )


def a_payload(category: AuditCategory = AuditCategory.INJECTION) -> AuditPayload:
    return AuditPayload(
        category=category,
        description="test payload",
        arguments={"input": "malicious"},
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
