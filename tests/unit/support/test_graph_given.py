from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain import (
    AttackContext,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainPlanBatch,
    EvalResult,
    EvalVerdict,
    Severity,
    StepObservation,
    TestCaseBatch,
    ToolDefinition,
)
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
    tool_name: str = "test_tool",
    num_cases: int = 1,
    extraction_response: AttackContext | None = None,
) -> FakeLLM:
    batch = TestCaseBatch(cases=[_a_payload(tool_name) for _ in range(num_cases)])
    eval_results = [_an_eval_result(tool_name) for _ in range(num_cases)]
    context = extraction_response or AttackContext()
    return FakeLLM([batch, *eval_results, context])


def a_fake_llm_for_multi_tool_audit(
    tool_configs: list[tuple[str, int]],
) -> FakeLLM:
    responses: list[BaseModel] = []
    for tool_name, num_cases in tool_configs:
        batch = TestCaseBatch(cases=[_a_payload(tool_name) for _ in range(num_cases)])
        eval_results = [_an_eval_result(tool_name) for _ in range(num_cases)]
        responses.extend([batch, *eval_results, AttackContext()])
    return FakeLLM(responses)


def a_graph(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient):
    from mcp_auditor.graph.builder import build_graph

    return build_graph(fake_llm, fake_mcp_client)


async def invoke_graph(graph: Any, state: dict[str, Any]) -> dict[str, Any]:
    return await graph.ainvoke(state)


def an_initial_state(
    test_budget: int = 5,
    chain_budget: int = 0,
    max_chain_steps: int = 3,
) -> dict[str, Any]:
    return {
        "target": "python dummy_server.py",
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


def a_fake_llm_for_single_tool_with_chain(
    tool_name: str = "test_tool",
    num_cases: int = 1,
) -> FakeLLM:
    """LLM sequence: generate cases, judge each, chain planning (1 goal),
    observe step (stop), judge chain, extract context."""
    batch = TestCaseBatch(cases=[_a_payload(tool_name) for _ in range(num_cases)])
    eval_results = [_an_eval_result(tool_name) for _ in range(num_cases)]
    chain_plan = ChainPlanBatch(
        chains=[
            ChainGoal(
                description="probe then exploit",
                category=AuditCategory.INJECTION,
                first_step=_a_payload(tool_name),
            ),
        ]
    )
    step_obs = StepObservation(observation="dead end", should_continue=False)
    chain_eval = _an_eval_result(tool_name)
    context = AttackContext()
    return FakeLLM([batch, *eval_results, chain_plan, step_obs, chain_eval, context])


def _a_payload(tool_name: str, category: AuditCategory = AuditCategory.INJECTION) -> AuditPayload:
    return AuditPayload(
        tool_name=tool_name,
        category=category,
        description="test payload",
        arguments={"input": "malicious"},
    )


def _an_eval_result(
    tool_name: str,
    category: AuditCategory = AuditCategory.INJECTION,
) -> EvalResult:
    return EvalResult(
        tool_name=tool_name,
        category=category,
        payload={"input": "malicious"},
        verdict=EvalVerdict.FAIL,
        justification="test justification",
        severity=Severity.MEDIUM,
    )
