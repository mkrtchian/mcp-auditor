import tests.unit.support.test_rendering_given as given
import tests.unit.support.test_rendering_then as then
from mcp_auditor.domain.rendering import (
    render_json,
    render_markdown,
    render_summary,
    summarize_tools,
)


def test_json_round_trip():
    report = given.a_two_tool_report()

    result = render_json(report)

    then.json_round_trips(result, 2)


def test_json_enum_values():
    report = given.a_two_tool_report()

    result = render_json(report)

    then.json_has_enum_strings(result)


def test_json_includes_owasp_for_mapped_category():
    report = given.a_report_with_injection_finding()

    result = render_json(report)

    then.json_has_owasp_for_category(result, "injection", "MCP-05", "Command Injection & Execution")


def test_json_omits_owasp_for_unmapped_category():
    report = given.a_report_with_unmapped_finding()

    result = render_json(report)

    then.json_has_no_owasp(result)


def test_markdown_tool_sections():
    report = given.a_two_tool_report()

    result = render_markdown(report)

    then.markdown_contains_tool_headings(result, ["get_user", "list_items"])


def test_markdown_finding_details():
    report = given.a_two_tool_report()

    result = render_markdown(report)

    then.markdown_contains_finding(result, "input_validation", "high", "No input length validation")


def test_markdown_summary_stats():
    report = given.a_two_tool_report()

    result = render_markdown(report)

    then.markdown_summary_has_counts(
        result, tools=2, findings=2, per_severity_dict={"high": 1, "critical": 1}
    )


def test_markdown_pass_results_included():
    report = given.a_two_tool_report()

    result = render_markdown(report)

    then.markdown_includes_pass_without_severity(result)


def test_markdown_empty_report():
    report = given.an_empty_report()

    result = render_markdown(report)

    assert "0" in result


def test_summary_one_liner():
    report = given.a_two_tool_report()

    result = render_summary(report)

    assert "\n" not in result
    assert "2 tools" in result
    assert "2 findings" in result


def test_summary_sorts_severity_descending():
    report = given.a_report_with_low_then_critical()

    result = render_summary(report)

    assert result.index("critical") < result.index("low")


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
    report = given.a_report_with_chain_finding()

    result = render_markdown(report)

    assert "CHAIN:" in result
    assert "probe then exploit" in result
    assert "FAIL" in result
    assert "Chain exploited" in result


def test_markdown_without_chains():
    report = given.a_two_tool_report()

    result = render_markdown(report)

    assert "CHAIN:" not in result


def test_json_with_chains_has_owasp():
    report = given.a_report_with_chain_injection_finding()

    result = render_json(report)

    then.json_chain_has_owasp(result, "injection", "MCP-05")


def test_summarize_tools_counts_chain_failures():
    report = given.a_report_with_pass_case_and_fail_chain()

    summaries = summarize_tools(report)

    assert len(summaries) == 1
    assert summaries[0].judged == 2
    assert summaries[0].passed == 1
    assert summaries[0].failed == 1


def test_markdown_summary_counts_chains():
    report = given.a_report_with_chain_finding()

    result = render_markdown(report)

    assert "Test cases" in result or "cases" in result.lower()
