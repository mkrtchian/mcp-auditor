import json
import re

import tests.unit.support.test_rendering_given as given
import tests.unit.support.test_rendering_then as then
from mcp_auditor.domain.models import AuditCategory, CoverageGap, ExecutionRecord, ExecutionRegime
from mcp_auditor.domain.rendering import (
    describe_coverage_gap,
    render_json,
    render_markdown,
    render_summary,
    summarize_tools,
)


def test_json_round_trip():
    report = given.a_two_tool_report()

    result = render_json(report)

    then.json_has_expected_structure(result, 2)


def test_json_enum_values():
    report = given.a_two_tool_report()

    result = render_json(report)

    then.json_has_enum_strings(result)


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


def test_markdown_summary_counts_chains():
    report = given.a_report_with_chain_finding()

    result = render_markdown(report)

    assert "**Test cases**: 1" in result


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


def test_summarize_tools_counts_chain_failures():
    report = given.a_report_with_pass_case_and_fail_chain()

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


def test_markdown_renders_a_blocked_chain_reason():
    report = given.a_report_with_a_blocked_chain()

    result = render_markdown(report)

    assert given.BLOCKED_CHAIN_REASON in result


def test_markdown_summary_counts_blocked_cases_and_chains():
    report = given.a_report_with_a_blocked_case_and_a_blocked_chain()

    result = render_markdown(report)

    assert "**Blocked**: 2" in result


def test_markdown_summary_omits_blocked_when_nothing_was_blocked():
    report = given.a_two_tool_report()

    result = render_markdown(report)

    assert "**Blocked**:" not in result


def test_markdown_shows_a_confined_execution_with_a_short_digest():
    report = given.a_report_with_execution(given.a_confined_record())

    result = render_markdown(report)

    assert re.search(
        r"^\*\*Execution\*\*: confined, node:24-bookworm-slim@sha256:[0-9a-f]{12}$",
        result,
        re.MULTILINE,
    )


def test_markdown_shows_the_image_alone_when_the_digest_is_unknown():
    report = given.a_report_with_execution(given.a_confined_record(image_digest=None))

    result = render_markdown(report)

    assert "**Execution**: confined, node:24-bookworm-slim\n" in result
    assert "@" not in result


def test_markdown_places_the_execution_line_right_after_the_target():
    report = given.a_report_with_execution(given.a_confined_record())

    lines = render_markdown(report).splitlines()

    target_index = next(i for i, line in enumerate(lines) if line.startswith("**Target**"))
    assert lines[target_index + 1].startswith("**Execution**")


def test_markdown_shows_a_declared_container_execution_without_mounts():
    record = ExecutionRecord(regime=ExecutionRegime.DECLARED_CONTAINER)
    report = given.a_report_with_execution(record)

    result = render_markdown(report)

    assert "**Execution**: declared container\n" in result
    then.markdown_has_no_confined_lines(result)


def test_markdown_shows_an_unconfined_execution_without_mounts():
    report = given.a_report_with_execution(ExecutionRecord(regime=ExecutionRegime.UNCONFINED))

    result = render_markdown(report)

    assert "**Execution**: unconfined\n" in result
    then.markdown_has_no_confined_lines(result)


def test_markdown_lists_the_writable_paths_of_a_confined_execution():
    record = given.a_confined_record(writable_paths=["/tmp/a", "/tmp/b"])
    report = given.a_report_with_execution(record)

    result = render_markdown(report)

    assert "**Writable on host**: /tmp/a, /tmp/b" in result


def test_markdown_shows_none_when_nothing_is_writable():
    report = given.a_report_with_execution(given.a_confined_record(writable_paths=[]))

    result = render_markdown(report)

    assert "**Writable on host**: none" in result


def test_markdown_lists_the_read_only_paths_when_there_are_some():
    record = given.a_confined_record(read_only_paths=["/data"])
    report = given.a_report_with_execution(record)

    result = render_markdown(report)

    assert "**Read-only on host**: /data" in result


def test_markdown_omits_the_read_only_line_when_there_are_none():
    report = given.a_report_with_execution(given.a_confined_record(read_only_paths=[]))

    result = render_markdown(report)

    assert "**Read-only on host**" not in result


def test_markdown_reports_a_memory_kill():
    report = given.a_report_with_execution(given.a_confined_record(oom_killed=True))

    result = render_markdown(report)

    assert "**Killed on memory**: yes" in result


def test_markdown_reports_an_unreadable_kill_state_as_unknown():
    report = given.a_report_with_execution(given.a_confined_record(oom_killed=None))

    result = render_markdown(report)

    assert "**Killed on memory**: unknown" in result


def test_markdown_omits_the_kill_line_when_the_server_was_not_killed():
    report = given.a_report_with_execution(given.a_confined_record(oom_killed=False))

    result = render_markdown(report)

    assert "**Killed on memory**" not in result


def test_markdown_without_execution_has_no_execution_line():
    report = given.a_two_tool_report()

    result = render_markdown(report)

    assert "**Execution**" not in result


def test_json_carries_the_execution_record_with_the_full_digest():
    report = given.a_report_with_execution(given.a_confined_record())

    execution = json.loads(render_json(report))["execution"]

    assert set(execution) == {
        "regime",
        "image",
        "image_digest",
        "writable_paths",
        "read_only_paths",
        "oom_killed",
    }
    assert execution["regime"] == "confined"
    assert execution["image_digest"] == given.FULL_DIGEST


def test_json_execution_is_null_without_a_record():
    report = given.a_two_tool_report()

    data = json.loads(render_json(report))

    assert data["execution"] is None


def test_markdown_flags_a_coverage_gap_right_under_the_tool_heading():
    report = given.a_report_with_a_coverage_gap_on_get_user()

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
    report = given.a_two_tool_report()

    result = render_markdown(report)

    assert "Coverage gap" not in result


def test_json_carries_the_coverage_gap():
    report = given.a_report_with_a_coverage_gap_on_get_user()

    tool_reports = json.loads(render_json(report))["tool_reports"]

    assert tool_reports[0]["coverage_gap"] == {
        "requested_cases": 10,
        "received_cases": 7,
        "missing_categories": ["injection", "resource_abuse"],
    }
    assert tool_reports[1]["coverage_gap"] is None


def test_markdown_summary_flags_a_refused_step_and_an_incomplete_audit():
    report = given.a_report_with_a_refused_judgment_on_get_user()

    summary = render_markdown(report).split("\n## get_user")[0]

    assert "**Refused by the model provider**: 1 step\n" in summary
    assert "**Audit complete**: no" in summary
    assert summary.index("**Audit complete**") < summary.index("**Findings**")


def test_markdown_summary_flags_a_coverage_gap_alone_as_an_incomplete_audit():
    report = given.a_report_with_a_coverage_gap_on_get_user()

    result = render_markdown(report)

    assert "**Audit complete**: no" in result
    assert "**Refused by the model provider**" not in result


def test_markdown_summary_of_a_complete_audit_has_neither_line():
    report = given.a_two_tool_report()

    result = render_markdown(report)

    assert "**Audit complete**" not in result
    assert "**Refused by the model provider**" not in result


def test_markdown_tool_section_lists_its_refused_step():
    report = given.a_report_with_a_refused_judgment_on_get_user()

    sections = render_markdown(report).split("\n## ")
    get_user_section = next(s for s in sections if s.startswith("get_user"))
    list_items_section = next(s for s in sections if s.startswith("list_items"))

    assert (
        f'**Refused by the model provider**: judgment, "{given.REFUSAL_MESSAGE}"'
        in get_user_section
    )
    assert "Refused" not in list_items_section


def test_markdown_renders_a_case_with_no_verdict_and_no_block_as_not_judged():
    report = given.a_report_with_an_unjudged_case()

    result = render_markdown(report)

    assert "### NOT JUDGED -- injection" in result
    assert "ls; cat /etc/shadow" in result
    assert "the model provider refused the judgment" in result


def test_markdown_renders_a_chain_with_no_verdict_as_not_judged():
    report = given.a_report_with_an_unjudged_chain()

    result = render_markdown(report)

    assert "**Verdict**: not judged" in result


def test_json_carries_the_refused_steps():
    report = given.a_report_with_a_refused_judgment_on_get_user()

    refused_steps = json.loads(render_json(report))["refused_steps"]

    assert refused_steps == [
        {
            "tool_name": "get_user",
            "step": "judgment",
            "provider_message": given.REFUSAL_MESSAGE,
        }
    ]


def test_markdown_does_not_call_a_blocked_chain_not_judged():
    report = given.a_report_with_a_blocked_chain()

    result = render_markdown(report)

    assert "not judged" not in result
