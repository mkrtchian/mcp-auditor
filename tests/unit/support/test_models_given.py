from typing import Any

from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    CoverageGap,
    EvalResult,
    EvalVerdict,
    ProviderUsage,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)
from mcp_auditor.domain.models import AuditStep, RefusedStep


def a_tool(
    name: str = "test_tool",
    input_schema: dict[str, Any] | None = None,
) -> ToolDefinition:
    return ToolDefinition(name=name, description="desc", input_schema=input_schema or {})


def a_payload(**overrides: Any) -> AuditPayload:
    defaults: dict[str, Any] = {
        "category": AuditCategory.INPUT_VALIDATION,
        "description": "test payload",
        "arguments": {},
    }
    return AuditPayload(**(defaults | overrides))


def an_eval_result(**overrides: Any) -> EvalResult:
    defaults: dict[str, Any] = {
        "tool_name": "t",
        "category": AuditCategory.INJECTION,
        "payload": {},
        "verdict": EvalVerdict.FAIL,
        "justification": "vuln",
        "severity": Severity.HIGH,
    }
    return EvalResult(**(defaults | overrides))


def a_report_with_finding(severity: Severity) -> AuditReport:
    case = TestCase(
        payload=a_payload(category=AuditCategory.INJECTION),
        eval_result=an_eval_result(severity=severity),
    )
    return AuditReport(
        target="test",
        tool_reports=[ToolReport(tool=a_tool(), cases=[case])],
        provider_usage=ProviderUsage(),
    )


def a_report(
    refused_steps: list[RefusedStep] | None = None, coverage_gap: CoverageGap | None = None
) -> AuditReport:
    return AuditReport(
        target="test",
        tool_reports=[ToolReport(tool=a_tool(), cases=[], coverage_gap=coverage_gap)],
        provider_usage=ProviderUsage(),
        refused_steps=refused_steps or [],
    )


def a_refused_step(step: AuditStep = AuditStep.JUDGMENT) -> RefusedStep:
    return RefusedStep(tool_name="test_tool", step=step, provider_message="flagged")


def a_coverage_gap() -> CoverageGap:
    return CoverageGap(
        requested_cases=10, received_cases=6, missing_categories=[AuditCategory.INJECTION]
    )
