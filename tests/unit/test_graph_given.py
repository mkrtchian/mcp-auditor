from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    EvalResult,
    EvalVerdict,
    Severity,
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


def a_fake_llm_for_single_tool_audit(
    tool_name: str = "test_tool",
    num_cases: int = 1,
) -> FakeLLM:
    batch = TestCaseBatch(cases=[_a_payload(tool_name) for _ in range(num_cases)])
    eval_results = [_an_eval_result(tool_name) for _ in range(num_cases)]
    return FakeLLM([batch, *eval_results])


def a_fake_llm_for_multi_tool_audit(
    tool_configs: list[tuple[str, int]],
) -> FakeLLM:
    responses: list[BaseModel] = []
    for tool_name, num_cases in tool_configs:
        batch = TestCaseBatch(cases=[_a_payload(tool_name) for _ in range(num_cases)])
        eval_results = [_an_eval_result(tool_name) for _ in range(num_cases)]
        responses.extend([batch, *eval_results])
    return FakeLLM(responses)


def a_graph(fake_llm: FakeLLM, fake_mcp_client: FakeMCPClient):
    from mcp_auditor.graph.builder import build_graph

    return build_graph(fake_llm, fake_mcp_client)


def an_initial_state(test_budget: int = 5) -> dict[str, Any]:
    return {
        "discovered_tools": [],
        "test_budget": test_budget,
        "current_tool": None,
        "tool_results": [],
        "tool_reports": [],
        "audit_report": None,
    }


async def invoke_graph(graph: Any, state: dict[str, Any]) -> dict[str, Any]:
    return await graph.ainvoke(state)
