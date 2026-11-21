import json

import pytest

import tests.unit.auditor.support.test_relaunch_rendering_given as given
import tests.unit.auditor.support.test_rendering_given as rendering
import tests.unit.auditor.support.test_rendering_then as then
from mcp_auditor.domain.models import AuditCategory, CoverageGap
from mcp_auditor.domain.rendering import describe_coverage_gap, render_json, render_markdown
from mcp_auditor.domain.server_liveness import UnsentCause
from mcp_auditor.domain.server_watch import RELAUNCHES_IN_A_ROW, TIMEOUTS_IN_A_ROW


def test_markdown_summary_counts_the_relaunches():
    report = given.a_report_with_two_relaunches_on_get_user()

    summary = then.summary_of(render_markdown(report))

    assert "**Relaunches**: 2\n" in summary


def test_markdown_summary_says_when_a_relaunch_failed():
    report = given.a_report_with_two_relaunches_on_get_user(last_succeeded=False)

    summary = then.summary_of(render_markdown(report))

    assert "**Relaunches**: 2, 1 failed and the server was taken as down\n" in summary


def test_markdown_summary_counts_a_failed_relaunch_a_resumed_audit_followed_with_another():
    report = given.a_report_with_two_relaunches_on_get_user()
    report.relaunches[0].succeeded = False

    summary = then.summary_of(render_markdown(report))

    assert "**Relaunches**: 2, 1 failed and the server was taken as down\n" in summary


def test_markdown_summary_has_no_relaunch_line_without_a_relaunch():
    report = rendering.a_two_tool_report()

    assert "Relaunch" not in render_markdown(report)


def test_markdown_lists_each_relaunch_under_its_tool_with_the_call_before_it_and_its_cause():
    report = given.a_report_with_two_relaunches_on_get_user(last_succeeded=False)

    result = render_markdown(report)

    get_user, list_items = result.split("\n## get_user\n")[1].split("\n## list_items\n")
    assert (
        f"**Relaunch**: after `{given.LOST_ARGUMENTS}`, "
        "the connection to the server was lost, the server was relaunched"
    ) in get_user
    assert (
        f"**Relaunch**: after `{given.STUCK_ARGUMENTS}`, "
        "the call timed out and the server did not answer the ping, "
        "the relaunch failed and the server was taken as down"
    ) in get_user
    assert "Relaunch" not in list_items


@pytest.mark.parametrize(
    ("cause", "why"),
    [
        (UnsentCause.TOOL_TIMING_OUT, f"the tool timed out {TIMEOUTS_IN_A_ROW} times in a row"),
        (
            UnsentCause.RELAUNCHES_IN_A_ROW,
            f"the tool's calls led to {RELAUNCHES_IN_A_ROW} relaunches in a row",
        ),
        (UnsentCause.SERVER_DOWN, "the server was taken as down"),
    ],
)
def test_a_coverage_gap_names_the_cases_and_chains_not_sent_and_why(cause: UnsentCause, why: str):
    gap = given.a_gap_with_calls_not_sent(cause)

    assert describe_coverage_gap(gap) == (
        f"10 cases generated for 10 requested, 3 cases and 2 chains not sent ({why})"
    )


def test_a_coverage_gap_names_its_calls_not_sent_before_its_missing_categories():
    gap = CoverageGap(
        requested_cases=10,
        received_cases=7,
        missing_categories=[AuditCategory.INJECTION],
        unsent_cases=1,
        unsent_cause=UnsentCause.TOOL_TIMING_OUT,
    )

    assert describe_coverage_gap(gap) == (
        "7 cases generated for 10 requested, 1 case not sent "
        f"(the tool timed out {TIMEOUTS_IN_A_ROW} times in a row), missing categories: injection"
    )


def test_the_coverage_gap_of_a_tool_left_by_a_server_down_names_why():
    gap = CoverageGap(
        requested_cases=10,
        received_cases=0,
        missing_categories=[],
        unsent_cause=UnsentCause.SERVER_DOWN,
    )

    assert describe_coverage_gap(gap) == (
        "0 cases generated for 10 requested (the server was taken as down)"
    )


def test_markdown_labels_a_chain_cut_by_a_relaunch():
    report = given.a_report_with_a_chain_cut_by_a_relaunch()

    result = render_markdown(report)

    chain = result.split("### CHAIN:")[1]
    assert (
        "**Cut by a relaunch**: the server was relaunched after the last step, "
        "the chain is judged on the steps made"
    ) in chain


def test_markdown_does_not_label_a_chain_the_server_answered_to_the_end():
    report = rendering.a_report_with_chain_finding()

    assert "Cut by a relaunch" not in render_markdown(report)


def test_json_carries_the_relaunches_and_the_calls_not_sent():
    report = given.a_report_with_two_relaunches_on_get_user(last_succeeded=False)
    report.tool_reports[0].coverage_gap = given.a_gap_with_calls_not_sent(UnsentCause.SERVER_DOWN)

    data = json.loads(render_json(report))

    assert data["relaunches"][1] == {
        "tool_name": "get_user",
        "arguments": given.STUCK_ARGUMENTS,
        "cause": "unanswered_ping",
        "succeeded": False,
    }
    gap = data["tool_reports"][0]["coverage_gap"]
    assert (gap["unsent_cases"], gap["unsent_chains"], gap["unsent_cause"]) == (
        3,
        2,
        "server_down",
    )
