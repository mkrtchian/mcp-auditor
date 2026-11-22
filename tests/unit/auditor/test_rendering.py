import json

import tests.unit.auditor.support.test_rendering_given as given
import tests.unit.auditor.support.test_rendering_then as then
from mcp_auditor.domain.models import AuditCategory, AuditReport, CoverageGap
from mcp_auditor.domain.rendering import (
    describe_coverage_gap,
    render_json,
    render_markdown,
    render_summary,
    summarize_tools,
)
from mcp_auditor.domain.shown_response import MAX_SHOWN_LENGTH
from tests.unit.auditor.support.report_builders import (
    a_report_with_a_coverage_gap_on_get_user,
    a_report_with_chain_finding,
    a_report_with_pass_case_and_fail_chain,
    a_two_tool_report,
)


def test_json_carries_the_whole_report():
    report = a_two_tool_report()

    result = render_json(report)

    assert AuditReport.model_validate_json(result) == report


def test_json_includes_owasp_for_mapped_category():
    report = given.a_report_with_injection_finding()

    result = render_json(report)

    then.json_has_owasp_for_category(result, "injection", "MCP-05", "Command Injection & Execution")


def test_json_owasp_is_null_for_unmapped_category():
    report = given.a_report_with_unmapped_finding()

    result = render_json(report)

    then.json_has_null_owasp(result)


def test_json_with_chains_has_owasp():
    report = given.a_report_with_chain_injection_finding()

    result = render_json(report)

    then.json_chain_has_owasp(result, "injection", "MCP-05")


def test_markdown_tool_sections():
    report = a_two_tool_report()

    result = render_markdown(report)

    then.markdown_contains_tool_headings(result, ["get_user", "list_items"])


def test_markdown_finding_details():
    report = a_two_tool_report()

    result = render_markdown(report)

    then.markdown_contains_finding(result, "input_validation", "high", "No input length validation")


def test_markdown_summary_stats():
    report = a_two_tool_report()

    result = render_markdown(report)

    then.markdown_summary_has_counts(
        result, tools=2, findings=2, per_severity_dict={"high": 1, "critical": 1}
    )


def test_markdown_pass_results_included():
    report = a_two_tool_report()

    result = render_markdown(report)

    then.markdown_includes_pass_without_severity(result)


def test_markdown_empty_report():
    report = given.an_empty_report()

    result = render_markdown(report)

    then.markdown_summary_has_counts(result, tools=0, findings=0, per_severity_dict={})


def test_markdown_fail_heading_includes_owasp_label_for_mapped_category():
    report = given.a_report_with_injection_finding()

    result = render_markdown(report)

    assert "injection / MCP-05: Command Injection & Execution" in result


def test_markdown_fail_heading_omits_owasp_for_unmapped_category():
    report = given.a_report_with_unmapped_finding()

    result = render_markdown(report)

    assert "input_validation" in result
    assert "MCP-" not in result


def test_markdown_pass_heading_includes_owasp_label_for_mapped_category():
    report = given.a_report_with_mapped_pass()

    result = render_markdown(report)

    assert "injection / MCP-05: Command Injection & Execution" in result
    assert "(-)" in result


def test_markdown_with_chain_fail():
    report = a_report_with_chain_finding()

    result = render_markdown(report)

    assert "CHAIN:" in result
    assert "probe then exploit" in result
    assert "FAIL" in result
    assert "Chain exploited" in result


def test_markdown_without_chains():
    report = a_two_tool_report()

    result = render_markdown(report)

    assert "CHAIN:" not in result


def test_markdown_summary_counts_chains_apart_from_test_cases():
    report = a_report_with_chain_finding()

    result = render_markdown(report)

    assert "**Test cases**: 0" in result
    assert "**Attack chains**: 1" in result


def test_summary_one_liner():
    report = a_two_tool_report()

    result = render_summary(report)

    assert "\n" not in result
    assert "2 tools" in result
    assert "2 findings" in result


def test_summary_sorts_severity_descending():
    report = given.a_report_with_low_then_critical()

    result = render_summary(report)

    assert result.index("critical") < result.index("low")


def test_summarize_tools_counts_chain_failures():
    report = a_report_with_pass_case_and_fail_chain()

    summaries = summarize_tools(report)

    assert len(summaries) == 1
    assert summaries[0].judged == 2
    assert summaries[0].passed == 1
    assert summaries[0].failed == 1


def test_markdown_renders_a_blocked_case():
    report = given.a_report_with_a_blocked_case()

    result = render_markdown(report)

    assert "### BLOCKED -- injection" in result
    assert "rm -rf /" in result
    assert given.BLOCKED_CASE_REASON in result


def test_reports_of_an_unencodable_blocked_case_encode_as_utf8():
    report = given.a_report_with_an_unencodable_blocked_case()

    render_json(report).encode("utf-8")
    render_markdown(report).encode("utf-8")


def test_markdown_renders_a_blocked_chain_reason():
    report = given.a_report_with_a_blocked_chain()

    result = render_markdown(report)

    assert given.BLOCKED_CHAIN_REASON in result


def test_markdown_summary_counts_blocked_cases_and_chains():
    report = given.a_report_with_a_blocked_case_and_a_blocked_chain()

    result = render_markdown(report)

    assert "**Blocked**: 2" in result


def test_markdown_summary_omits_blocked_when_nothing_was_blocked():
    report = a_two_tool_report()

    result = render_markdown(report)

    assert "**Blocked**:" not in result


def test_markdown_flags_a_coverage_gap_right_under_the_tool_heading():
    report = a_report_with_a_coverage_gap_on_get_user()

    result = render_markdown(report)

    section = result.split("## get_user\n")[1]
    gap_line = section.strip().splitlines()[0]
    assert gap_line.startswith("**Coverage gap**")
    assert "7 cases generated for 10 requested" in gap_line
    assert "injection, resource_abuse" in gap_line


def test_a_coverage_gap_names_its_case_counts_and_missing_categories():
    gap = CoverageGap(
        requested_cases=10, received_cases=7, missing_categories=[AuditCategory.INJECTION]
    )

    assert describe_coverage_gap(gap) == (
        "7 cases generated for 10 requested, missing categories: injection"
    )


def test_a_coverage_gap_without_missing_categories_names_its_case_counts_only():
    gap = CoverageGap(requested_cases=10, received_cases=7, missing_categories=[])

    assert describe_coverage_gap(gap) == "7 cases generated for 10 requested"


def test_markdown_has_no_coverage_gap_line_without_a_gap():
    report = a_two_tool_report()

    result = render_markdown(report)

    assert "Coverage gap" not in result


def test_markdown_tool_section_counts_its_responses_shown_cut():
    report = given.a_report_with_a_cut_response_on_get_user()

    result = render_markdown(report)

    assert (
        f"**Responses shown cut**: 1 response(s) or error(s) over {MAX_SHOWN_LENGTH:,} characters, "
        "shown to the model with their middle cut"
    ) in then.tool_section(result, "get_user")
    assert "Responses shown cut" not in then.tool_section(result, "list_items")


def test_json_carries_the_coverage_gap():
    report = a_report_with_a_coverage_gap_on_get_user()

    tool_reports = json.loads(render_json(report))["tool_reports"]

    assert tool_reports[0]["coverage_gap"] == {
        "requested_cases": 10,
        "received_cases": 7,
        "missing_categories": ["injection", "resource_abuse"],
        "unsent_cases": 0,
        "unsent_chains": 0,
        "unsent_cause": None,
    }
    assert tool_reports[1]["coverage_gap"] is None


def test_markdown_does_not_call_a_blocked_chain_not_judged():
    report = given.a_report_with_a_blocked_chain()

    result = render_markdown(report)

    assert "not judged" not in result


def test_markdown_summary_reports_the_throttled_requests_after_the_token_usage():
    report = given.a_report_throttled(4)

    result = render_markdown(report)

    assert "**Throttled by the model provider**: 4 requests (HTTP 429)\n" in result
    assert result.index("**Token usage**") < result.index("**Throttled by the model provider**")


def test_markdown_summary_omits_throttling_when_nothing_was_throttled():
    report = given.a_report_throttled(0)

    result = render_markdown(report)

    assert "Throttled" not in result


def test_json_carries_the_throttled_requests():
    report = given.a_report_throttled(4)

    result = json.loads(render_json(report))

    assert result["provider_usage"]["throttled_requests"] == 4
