import tests.unit.fixtures.test_rendering_given as given
import tests.unit.fixtures.test_rendering_then as then
from mcp_auditor.domain.rendering import render_json, render_markdown, render_summary


def test_json_round_trip():
    report = given.a_two_tool_report()

    result = render_json(report)

    then.json_round_trips(result, 2)


def test_json_enum_values():
    report = given.a_two_tool_report()

    result = render_json(report)

    then.json_has_enum_strings(result)


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
