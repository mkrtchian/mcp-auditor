from typing import Any

from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
    ToolResponse,
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


def a_payload(
    tool_name: str = "test_tool",
    category: AuditCategory = AuditCategory.INJECTION,
    description: str = "test payload",
    arguments: dict[str, Any] | None = None,
) -> AuditPayload:
    return AuditPayload(
        tool_name=tool_name,
        category=category,
        description=description,
        arguments=arguments or {"input": "malicious"},
    )


def a_test_case(
    tool_name: str = "test_tool",
    category: AuditCategory = AuditCategory.INJECTION,
    response: str | None = None,
    error: str | None = None,
    payload: AuditPayload | None = None,
) -> TestCase:
    return TestCase(
        payload=payload or a_payload(tool_name=tool_name, category=category),
        response=response,
        error=error,
    )


def an_eval_result(
    tool_name: str = "test_tool",
    category: AuditCategory = AuditCategory.INJECTION,
    verdict: EvalVerdict = EvalVerdict.PASS,
    severity: Severity = Severity.LOW,
) -> EvalResult:
    payload = a_payload(tool_name=tool_name, category=category)
    return EvalResult(
        tool_name=tool_name,
        category=category,
        payload=payload.arguments,
        verdict=verdict,
        justification="test justification",
        severity=severity,
    )


def a_fake_llm_returning(*responses: Any) -> FakeLLM:
    return FakeLLM(list(responses))


def a_fake_mcp_client(
    tools: list[ToolDefinition],
    responses: dict[str, ToolResponse] | None = None,
) -> FakeMCPClient:
    return FakeMCPClient(tools, responses)



def a_tool_report(
    tool_name: str = "test_tool",
    num_cases: int = 1,
) -> ToolReport:
    tool = a_tool(name=tool_name)
    cases = [
        a_test_case(tool_name=tool_name, response="some response", error="some error")
        for _ in range(num_cases)
    ]
    return ToolReport(tool=tool, cases=cases)
