from typing import Any

from mcp_auditor.domain import (
    AttackContext,
    AuditCategory,
    AuditPayload,
    CoverageGap,
    EvalResult,
    EvalVerdict,
    Judgment,
    Severity,
    TestCase,
    TestCaseBatch,
    ToolDefinition,
    ToolReport,
)


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
    category: AuditCategory = AuditCategory.INJECTION,
    description: str = "test payload",
    arguments: dict[str, Any] | None = None,
) -> AuditPayload:
    return AuditPayload(
        category=category,
        description=description,
        arguments=arguments or {"input": "malicious"},
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


def a_judgment(
    verdict: EvalVerdict = EvalVerdict.PASS,
    severity: Severity = Severity.LOW,
) -> Judgment:
    return Judgment(
        verdict=verdict,
        justification="test justification",
        severity=severity,
    )


def an_eval_result(
    tool_name: str = "test_tool",
    category: AuditCategory = AuditCategory.INJECTION,
    verdict: EvalVerdict = EvalVerdict.PASS,
    severity: Severity = Severity.LOW,
) -> EvalResult:
    payload = a_payload(category=category)
    return EvalResult(
        tool_name=tool_name,
        category=category,
        payload=payload.arguments,
        verdict=verdict,
        justification="test justification",
        severity=severity,
    )


def a_judged_case(response: str) -> TestCase:
    return a_test_case(response=response).model_copy(update={"eval_result": an_eval_result()})


def a_tool_report(
    tool_name: str = "test_tool",
    num_cases: int = 1,
) -> ToolReport:
    tool = a_tool(name=tool_name)
    cases = [a_test_case(response="some response", error="some error") for _ in range(num_cases)]
    return ToolReport(tool=tool, cases=cases)


def a_batch_of(num_cases: int) -> TestCaseBatch:
    categories = list(AuditCategory)
    return TestCaseBatch(
        cases=[a_payload(category=categories[i % len(categories)]) for i in range(num_cases)]
    )


def a_generation_state(test_budget: int) -> dict[str, Any]:
    return {"current_tool": a_tool(), "test_budget": test_budget, "attack_context": AttackContext()}


def a_coverage_gap() -> CoverageGap:
    return CoverageGap(
        requested_cases=5, received_cases=3, missing_categories=[AuditCategory.RESOURCE_ABUSE]
    )
