from typing import Any

from mcp_auditor.domain.models import (
    AuditCategory,
    CoverageGap,
    EvalVerdict,
    JudgeResult,
    Severity,
    TestCase,
    ToolReport,
)
from mcp_auditor.domain.server_liveness import UnsentCause
from tests.unit.auditor.support.graph_builders import a_test_case, a_tool


def a_tool_report(tool_name: str = "test_tool") -> ToolReport:
    case = a_test_case(response="some response", error="some error")
    return ToolReport(tool=a_tool(name=tool_name), cases=[case])


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
    judge_result = JudgeResult(
        tool_name="test_tool",
        category=AuditCategory.INJECTION,
        arguments={"input": "malicious"},
        verdict=EvalVerdict.PASS,
        justification="test justification",
        severity=Severity.LOW,
    )
    return a_test_case(response=response).model_copy(update={"judge_result": judge_result})
