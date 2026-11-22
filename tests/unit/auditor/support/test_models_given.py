import json
from typing import Any

from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    CoverageGap,
    EvalVerdict,
    JudgeResult,
    MissCause,
    MissedModelCall,
    ModelCallKind,
    ProviderUsage,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)
from mcp_auditor.domain.shown_response import MAX_SHOWN_LENGTH


def a_report_with_finding(severity: Severity) -> AuditReport:
    case = TestCase(
        payload=a_payload(category=AuditCategory.INJECTION),
        judge_result=a_judge_result(severity=severity),
    )
    return AuditReport(
        server_command="test",
        tool_reports=[ToolReport(tool=a_tool(), cases=[case])],
        provider_usage=ProviderUsage(),
    )


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


def a_judge_result(**overrides: Any) -> JudgeResult:
    defaults: dict[str, Any] = {
        "tool_name": "t",
        "category": AuditCategory.INJECTION,
        "arguments": {},
        "verdict": EvalVerdict.FAIL,
        "justification": "vuln",
        "severity": Severity.HIGH,
    }
    return JudgeResult(**(defaults | overrides))


def a_tool_report_with_a_cut_response() -> ToolReport:
    case = TestCase(payload=a_payload(), response="x" * (MAX_SHOWN_LENGTH + 1))
    return ToolReport(tool=a_tool(), cases=[case])


def a_report(
    missed_model_calls: list[MissedModelCall] | None = None, coverage_gap: CoverageGap | None = None
) -> AuditReport:
    return AuditReport(
        server_command="test",
        tool_reports=[ToolReport(tool=a_tool(), cases=[], coverage_gap=coverage_gap)],
        provider_usage=ProviderUsage(),
        missed_model_calls=missed_model_calls or [],
    )


def a_refused_call(kind: ModelCallKind = ModelCallKind.JUDGMENT) -> MissedModelCall:
    return MissedModelCall(
        tool_name="test_tool", kind=kind, cause=MissCause.PROVIDER_REFUSAL, detail="flagged"
    )


def a_coverage_gap() -> CoverageGap:
    return CoverageGap(
        requested_cases=10, received_cases=6, missing_categories=[AuditCategory.INJECTION]
    )


def a_report_written_before_relaunches() -> str:
    gap: dict[str, object] = {
        "requested_cases": 10,
        "received_cases": 6,
        "missing_categories": ["injection"],
    }
    chain: dict[str, object] = {
        "goal": {
            "description": "escalate",
            "category": "injection",
            "first_step": {"category": "injection", "description": "probe", "arguments": {}},
        },
        "steps": [],
    }
    tool_report: dict[str, object] = {
        "tool": {"name": "test_tool", "input_schema": {}},
        "cases": [],
        "chains": [chain],
        "coverage_gap": gap,
    }
    return json.dumps(
        {"server_command": "test", "tool_reports": [tool_report], "provider_usage": {}}
    )
