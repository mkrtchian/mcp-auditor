"""Only tests that validate OUR design choices — enum constraints, union types,
custom methods, serialization of non-trivial types. Does not test that
Pydantic constructors work or that Python lists hold items.
"""

from typing import Any

import pytest

from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    TokenUsage,
    ToolDefinition,
    ToolReport,
    ToolResponse,
)


class TestEnumConstraints:
    def test_rejects_unknown_category(self):
        with pytest.raises(ValueError):
            _a_payload(category="unknown_category")

    def test_rejects_unknown_severity(self):
        with pytest.raises(ValueError):
            EvalResult(
                tool_name="t",
                category=AuditCategory.INJECTION,
                payload={},
                verdict=EvalVerdict.FAIL,
                justification="j",
                severity="unknown",  # type: ignore[arg-type]
            )


class TestToolDefinition:
    def test_roundtrip_serialization(self):
        tool = ToolDefinition(
            name="get_user",
            description="Fetch a user by ID",
            input_schema={"type": "object", "properties": {"id": {"type": "integer"}}},
        )

        rebuilt = ToolDefinition.model_validate_json(tool.model_dump_json())

        assert rebuilt == tool


class TestTestCase:
    def test_response_accepts_dict(self):
        test_case = TestCase(payload=_a_payload(), response={"result": "ok"})

        assert test_case.response == {"result": "ok"}

    def test_response_accepts_string(self):
        test_case = TestCase(payload=_a_payload(), response="raw text")

        assert test_case.response == "raw text"


class TestToolResponse:
    def test_default_is_not_error(self):
        response = ToolResponse(content="ok")

        assert response.is_error is False

    def test_explicit_error_flag(self):
        response = ToolResponse(content="boom", is_error=True)

        assert response.is_error is True


class TestTokenUsage:
    def test_add_accumulates(self):
        a = TokenUsage(input_tokens=100, output_tokens=50)
        b = TokenUsage(input_tokens=200, output_tokens=100)

        total = a.add(b)

        assert total.input_tokens == 300
        assert total.output_tokens == 150

    def test_add_does_not_mutate(self):
        a = TokenUsage(input_tokens=100, output_tokens=50)
        b = TokenUsage(input_tokens=200, output_tokens=100)

        a.add(b)

        assert a.input_tokens == 100
        assert a.output_tokens == 50


class TestSeverityComparison:
    def test_critical_is_greater_than_low(self):
        assert Severity.CRITICAL > Severity.LOW

    def test_low_is_less_than_high(self):
        assert Severity.LOW < Severity.HIGH

    def test_medium_is_greater_or_equal_to_medium(self):
        assert Severity.MEDIUM >= Severity.MEDIUM

    def test_ordering_matches_declaration(self):
        assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


class TestAuditReportFindings:
    def test_detects_findings_at_exact_threshold(self):
        report = _a_report_with_finding(Severity.HIGH)

        assert report.has_findings_at_or_above(Severity.HIGH) is True

    def test_detects_findings_above_threshold(self):
        report = _a_report_with_finding(Severity.CRITICAL)

        assert report.has_findings_at_or_above(Severity.HIGH) is True

    def test_ignores_findings_below_threshold(self):
        report = _a_report_with_finding(Severity.LOW)

        assert report.has_findings_at_or_above(Severity.HIGH) is False

    def test_empty_report_has_no_findings(self):
        report = AuditReport(target="test", tool_reports=[], token_usage=TokenUsage())

        assert report.has_findings_at_or_above(Severity.LOW) is False


def _a_report_with_finding(severity: Severity) -> AuditReport:
    result = EvalResult(
        tool_name="t",
        category=AuditCategory.INJECTION,
        payload={},
        verdict=EvalVerdict.FAIL,
        justification="vuln",
        severity=severity,
    )
    case = TestCase(
        payload=AuditPayload(
            tool_name="t",
            category=AuditCategory.INJECTION,
            description="test",
            arguments={},
        ),
        eval_result=result,
    )
    tool = ToolDefinition(name="t", description="t", input_schema={})
    return AuditReport(
        target="test",
        tool_reports=[ToolReport(tool=tool, cases=[case])],
        token_usage=TokenUsage(),
    )


def _a_payload(**overrides: Any) -> AuditPayload:
    defaults: dict[str, Any] = {
        "tool_name": "test_tool",
        "category": AuditCategory.INPUT_VALIDATION,
        "description": "test payload",
        "arguments": {},
    }
    return AuditPayload(**(defaults | overrides))
