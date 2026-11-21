import json

import tests.unit.auditor.support.test_missed_model_call_rendering_given as given
from mcp_auditor.domain.models import MissCause
from mcp_auditor.domain.rendering import render_json, render_markdown
from tests.unit.auditor.support.report_builders import (
    REFUSAL_MESSAGE,
    a_report_with_a_coverage_gap_on_get_user,
    a_report_with_a_refused_judgment_on_get_user,
    a_two_tool_report,
)


def test_markdown_summary_flags_a_refused_model_call_and_an_incomplete_audit():
    report = a_report_with_a_refused_judgment_on_get_user()

    summary = render_markdown(report).split("\n## get_user")[0]

    assert "**Refused by the model provider**: 1 model call\n" in summary
    assert "**Unreadable answer from the model**" not in summary
    assert "**Audit complete**: no" in summary
    assert summary.index("**Audit complete**") < summary.index("**Findings**")


def test_markdown_summary_counts_each_cause_of_a_missed_model_call_on_its_own_line():
    report = given.a_report_with_missed_judgments_on_get_user(refused=1, unreadable=2)

    summary = render_markdown(report).split("\n## get_user")[0]

    assert "**Refused by the model provider**: 1 model call\n" in summary
    assert "**Unreadable answer from the model**: 2 model calls\n" in summary


def test_markdown_summary_has_no_line_for_a_cause_no_model_call_missed_by():
    report = given.a_report_with_missed_judgments_on_get_user(refused=0, unreadable=1)

    summary = render_markdown(report).split("\n## get_user")[0]

    assert "**Unreadable answer from the model**: 1 model call\n" in summary
    assert "**Refused by the model provider**" not in summary


def test_markdown_summary_flags_a_coverage_gap_alone_as_an_incomplete_audit():
    report = a_report_with_a_coverage_gap_on_get_user()

    result = render_markdown(report)

    assert "**Audit complete**: no" in result
    assert "**Refused by the model provider**" not in result


def test_markdown_summary_of_a_complete_audit_has_neither_line():
    report = a_two_tool_report()

    result = render_markdown(report)

    assert "**Audit complete**" not in result
    assert "**Refused by the model provider**" not in result


def test_markdown_tool_section_lists_its_refused_model_call():
    report = a_report_with_a_refused_judgment_on_get_user()

    sections = render_markdown(report).split("\n## ")
    get_user_section = next(s for s in sections if s.startswith("get_user"))
    list_items_section = next(s for s in sections if s.startswith("list_items"))

    assert f'**Refused by the model provider**: judgment, "{REFUSAL_MESSAGE}"' in get_user_section
    assert "Refused" not in list_items_section


def test_markdown_tool_section_lists_its_unreadable_model_call():
    report = given.a_report_with_missed_judgments_on_get_user(refused=0, unreadable=1)

    sections = render_markdown(report).split("\n## ")
    get_user_section = next(s for s in sections if s.startswith("get_user"))

    assert (
        f'**Unreadable answer from the model**: judgment, "{given.UNREADABLE_DETAIL}"'
        in get_user_section
    )


def test_markdown_names_a_throttled_model_call_in_the_summary_and_its_tool_section():
    report = given.a_report_with_one_missed_judgment_on_get_user(
        MissCause.PROVIDER_THROTTLED, given.THROTTLE_MESSAGE
    )

    summary, get_user_section = render_markdown(report).split("\n## get_user")[:2]

    assert "**Throttled past every retry**: 1 model call\n" in summary
    assert "**Audit complete**: no" in summary
    assert (
        f'**Throttled past every retry**: judgment, "{given.THROTTLE_MESSAGE}"' in get_user_section
    )


def test_markdown_names_a_prompt_too_long_in_the_summary_and_its_tool_section():
    report = given.a_report_with_one_missed_judgment_on_get_user(
        MissCause.PROMPT_TOO_LONG, given.PROMPT_TOO_LONG_MESSAGE
    )

    summary, get_user_section = render_markdown(report).split("\n## get_user")[:2]

    assert "**Prompt longer than the model's context window**: 1 model call\n" in summary
    assert "**Audit complete**: no" in summary
    assert (
        "**Prompt longer than the model's context window**: judgment,"
        f' "{given.PROMPT_TOO_LONG_MESSAGE}"' in get_user_section
    )


def test_markdown_renders_a_case_with_no_verdict_and_no_block_as_not_judged():
    report = given.a_report_with_an_unjudged_case()

    result = render_markdown(report)

    assert "### NOT JUDGED -- injection" in result
    assert "ls; cat /etc/shadow" in result
    assert "the judgment model call was missed, its cause is listed under the tool" in result


def test_markdown_renders_a_chain_with_no_verdict_as_not_judged():
    report = given.a_report_with_an_unjudged_chain()

    result = render_markdown(report)

    assert "**Verdict**: not judged" in result


def test_json_carries_the_missed_model_calls():
    report = a_report_with_a_refused_judgment_on_get_user()

    missed_model_calls = json.loads(render_json(report))["missed_model_calls"]

    assert missed_model_calls == [
        {
            "tool_name": "get_user",
            "kind": "judgment",
            "cause": "provider_refusal",
            "detail": REFUSAL_MESSAGE,
        }
    ]
