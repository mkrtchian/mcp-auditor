from typing import Any

from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    CoverageGap,
    EvalVerdict,
    JudgeResult,
    Judgment,
    ProviderUsage,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)
from mcp_auditor.domain.ports import ProviderRefusal
from mcp_auditor.domain.server_liveness import UnsentCause


def a_judgment(
    verdict: EvalVerdict = EvalVerdict.PASS,
    severity: Severity = Severity.LOW,
) -> Judgment:
    return Judgment(
        verdict=verdict,
        justification="test justification",
        severity=severity,
    )


def a_tool_report(
    tool_name: str = "test_tool",
    num_cases: int = 1,
) -> ToolReport:
    tool = a_tool(name=tool_name)
    cases = [a_test_case(response="some response", error="some error") for _ in range(num_cases)]
    return ToolReport(tool=tool, cases=cases)


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


def a_test_case(
    category: AuditCategory = AuditCategory.INJECTION,
    response: str | None = None,
    error: str | None = None,
    payload: AuditPayload | None = None,
) -> TestCase:
    return TestCase(
        payload=payload or a_payload(category=category),
        response=response,
        error=error,
    )


def a_payload(
    category: AuditCategory = AuditCategory.INJECTION,
    description: str = "test payload",
    arguments: dict[str, Any] | None = None,
) -> AuditPayload:
    return AuditPayload(
        category=category,
        description=description,
        arguments=arguments or {"input": "malicious"},
    )


def a_coverage_gap() -> CoverageGap:
    return CoverageGap(
        requested_cases=5, received_cases=3, missing_categories=[AuditCategory.RESOURCE_ABUSE]
    )


def a_tool_state(
    *,
    unsent_cases: int,
    unsent_chains: int,
    coverage_gap: CoverageGap | None = None,
    test_budget: int = 3,
    sent_cases: int = 2,
) -> dict[str, Any]:
    return {
        "current_tool": a_tool(),
        "processed_cases": [a_judged_case(response="r") for _ in range(sent_cases)],
        "test_budget": test_budget,
        "coverage_gap": coverage_gap,
        "unsent_cases": unsent_cases,
        "unsent_chains": unsent_chains,
        "unsent_cause": UnsentCause.TOOL_TIMING_OUT,
    }


def a_judged_case(response: str) -> TestCase:
    return a_test_case(response=response).model_copy(update={"judge_result": a_judge_result()})


def a_judge_result(
    tool_name: str = "test_tool",
    category: AuditCategory = AuditCategory.INJECTION,
    verdict: EvalVerdict = EvalVerdict.PASS,
    severity: Severity = Severity.LOW,
) -> JudgeResult:
    payload = a_payload(category=category)
    return JudgeResult(
        tool_name=tool_name,
        category=category,
        arguments=payload.arguments,
        verdict=verdict,
        justification="test justification",
        severity=severity,
    )


def a_provider_refusal() -> ProviderRefusal:
    return ProviderRefusal("flagged by policy", ProviderUsage(input_tokens=7, output_tokens=0))
