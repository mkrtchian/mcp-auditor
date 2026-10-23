"""Only tests that validate OUR design choices — enum constraints, union types,
custom methods, serialization of non-trivial types. Does not test that
Pydantic constructors work or that Python lists hold items.
"""

import pytest

import tests.unit.support.test_models_given as given
from mcp_auditor.domain import (
    AuditReport,
    ProviderUsage,
    Severity,
)
from mcp_auditor.domain.models import AuditStep, order_tools_for_audit


class TestEnumConstraints:
    def test_rejects_unknown_category(self):
        with pytest.raises(ValueError):
            given.a_payload(category="unknown_category")

    def test_rejects_unknown_severity(self):
        with pytest.raises(ValueError):
            given.an_eval_result(severity="unknown")


class TestProviderUsage:
    def test_add_accumulates(self):
        a = ProviderUsage(
            input_tokens=100, output_tokens=50, cached_input_tokens=40, reasoning_tokens=10
        )
        b = ProviderUsage(
            input_tokens=200, output_tokens=100, cached_input_tokens=60, reasoning_tokens=30
        )

        total = a.add(b)

        assert total == ProviderUsage(
            input_tokens=300, output_tokens=150, cached_input_tokens=100, reasoning_tokens=40
        )

    def test_add_does_not_mutate(self):
        a = ProviderUsage(input_tokens=100, output_tokens=50)
        b = ProviderUsage(input_tokens=200, output_tokens=100)

        a.add(b)

        assert a.input_tokens == 100
        assert a.output_tokens == 50

    def test_sub_is_the_field_by_field_inverse_of_add(self):
        a = ProviderUsage(
            input_tokens=100,
            output_tokens=50,
            cached_input_tokens=40,
            reasoning_tokens=10,
            throttled_requests=2,
        )
        b = ProviderUsage(
            input_tokens=30,
            output_tokens=12,
            cached_input_tokens=9,
            reasoning_tokens=3,
            throttled_requests=1,
        )

        assert a.add(b).sub(b) == a

    def test_sub_subtracts_every_field(self):
        a = ProviderUsage(
            input_tokens=300,
            output_tokens=150,
            cached_input_tokens=100,
            reasoning_tokens=40,
            throttled_requests=3,
        )
        b = ProviderUsage(
            input_tokens=200,
            output_tokens=100,
            cached_input_tokens=60,
            reasoning_tokens=30,
            throttled_requests=1,
        )

        assert a.sub(b) == ProviderUsage(
            input_tokens=100,
            output_tokens=50,
            cached_input_tokens=40,
            reasoning_tokens=10,
            throttled_requests=2,
        )

    def test_add_keeps_the_larger_request(self):
        a = ProviderUsage(input_tokens=100, largest_input_tokens=100)
        b = ProviderUsage(input_tokens=500, largest_input_tokens=300)

        assert a.add(b).largest_input_tokens == 300
        assert b.add(a).largest_input_tokens == 300

    def test_sub_keeps_the_minuends_larger_request(self):
        total = ProviderUsage(input_tokens=600, largest_input_tokens=300)
        part = ProviderUsage(input_tokens=500, largest_input_tokens=300)

        assert total.sub(part).largest_input_tokens == 300


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
        report = AuditReport(target="test", tool_reports=[], provider_usage=ProviderUsage())

        assert report.has_findings_at_or_above(Severity.LOW) is False


class TestAuditReportCompleteness:
    def test_a_report_without_refusal_or_gap_is_complete(self):
        report = given.a_report()

        assert report.is_complete is True

    def test_a_refused_step_makes_the_report_incomplete(self):
        report = given.a_report(missed_steps=[given.a_refused_step()])

        assert report.is_complete is False

    def test_a_coverage_gap_makes_the_report_incomplete(self):
        report = given.a_report(coverage_gap=given.a_coverage_gap())

        assert report.is_complete is False

    def test_missed_steps_survive_a_json_roundtrip(self):
        report = given.a_report(missed_steps=[given.a_refused_step(AuditStep.CHAIN_PLANNING)])

        rebuilt = AuditReport.model_validate_json(report.model_dump_json())

        assert rebuilt.missed_steps == report.missed_steps


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
        # delete_thing goes first: a prefix that stopped being recognized would tie with it,
        # and the stable sort would keep it ahead, breaking the assertion.
        tools = [given.a_tool(name="delete_thing")]
        tools.extend(given.a_tool(name=f"{p}thing") for p in prefixes)

        result = order_tools_for_audit(tools)

        assert result[-1].name == "delete_thing"
