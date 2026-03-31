"""Only tests that validate OUR design choices — enum constraints, union types,
custom methods, serialization of non-trivial types. Does not test that
Pydantic constructors work or that Python lists hold items.
"""

import pytest

import tests.unit.support.test_models_given as given
from mcp_auditor.domain import (
    AuditCategory,
    AuditReport,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    TokenUsage,
)
from mcp_auditor.domain.models import order_tools_for_audit


class TestEnumConstraints:
    def test_rejects_unknown_category(self):
        with pytest.raises(ValueError):
            given.a_payload(category="unknown_category")

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
        tool = given.a_tool(
            name="get_user",
            input_schema={"type": "object", "properties": {"id": {"type": "integer"}}},
        )

        rebuilt = type(tool).model_validate_json(tool.model_dump_json())

        assert rebuilt == tool


class TestTestCase:
    def test_response_accepts_dict(self):
        test_case = TestCase(payload=given.a_payload(), response={"result": "ok"})

        assert test_case.response == {"result": "ok"}

    def test_response_accepts_string(self):
        test_case = TestCase(payload=given.a_payload(), response="raw text")

        assert test_case.response == "raw text"


class TestToolResponse:
    """ToolResponse is a simple model — inline construction is clearer than a builder."""

    def test_default_is_not_error(self):
        from mcp_auditor.domain import ToolResponse

        response = ToolResponse(content="ok")

        assert response.is_error is False

    def test_explicit_error_flag(self):
        from mcp_auditor.domain import ToolResponse

        response = ToolResponse(content="boom", is_error=True)

        assert response.is_error is True

    def test_error_type_defaults_to_none(self):
        from mcp_auditor.domain import ToolResponse

        response = ToolResponse(content="ok")

        assert response.error_type is None

    def test_error_type_captures_exception_class(self):
        from mcp_auditor.domain import ToolResponse

        response = ToolResponse(content="boom", is_error=True, error_type="ConnectionError")

        assert response.error_type == "ConnectionError"


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
        report = given.a_report_with_finding(Severity.HIGH)

        assert report.has_findings_at_or_above(Severity.HIGH) is True

    def test_detects_findings_above_threshold(self):
        report = given.a_report_with_finding(Severity.CRITICAL)

        assert report.has_findings_at_or_above(Severity.HIGH) is True

    def test_ignores_findings_below_threshold(self):
        report = given.a_report_with_finding(Severity.LOW)

        assert report.has_findings_at_or_above(Severity.HIGH) is False

    def test_empty_report_has_no_findings(self):
        report = AuditReport(target="test", tool_reports=[], token_usage=TokenUsage())

        assert report.has_findings_at_or_above(Severity.LOW) is False


class TestOrderToolsForAudit:
    def test_read_like_tools_sort_before_others(self):
        tools = [
            given.a_tool(name="delete_user"),
            given.a_tool(name="get_user"),
            given.a_tool(name="list_items"),
        ]

        result = order_tools_for_audit(tools)

        assert [t.name for t in result] == ["get_user", "list_items", "delete_user"]

    def test_ties_broken_by_parameter_count(self):
        three_params = given.a_tool(
            name="get_details",
            input_schema={
                "type": "object",
                "properties": {"a": {}, "b": {}, "c": {}},
            },
        )
        one_param = given.a_tool(
            name="get_summary",
            input_schema={"type": "object", "properties": {"a": {}}},
        )

        result = order_tools_for_audit([three_params, one_param])

        assert [t.name for t in result] == ["get_summary", "get_details"]

    def test_stable_within_same_group(self):
        tools = [given.a_tool(name="create_x"), given.a_tool(name="update_y")]

        result = order_tools_for_audit(tools)

        assert [t.name for t in result] == ["create_x", "update_y"]

    def test_empty_list(self):
        assert order_tools_for_audit([]) == []

    def test_all_read_prefixes_recognized(self):
        prefixes = [
            "get_",
            "list_",
            "read_",
            "search_",
            "find_",
            "fetch_",
            "show_",
            "describe_",
            "check_",
        ]
        tools = [given.a_tool(name=f"{p}thing") for p in prefixes]
        tools.append(given.a_tool(name="delete_thing"))

        result = order_tools_for_audit(tools)

        assert result[-1].name == "delete_thing"
