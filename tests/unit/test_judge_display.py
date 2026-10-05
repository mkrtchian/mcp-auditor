from pathlib import Path

import pytest

import tests.unit.support.test_judge_display_given as given
from evals.judge_display import print_summary

REPORT_PATH = Path("output/judge_eval_report.json")


def test_the_summary_lists_the_cases_that_left_unchanged(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    result = given.a_result_with_a_flip_not_reproduced()

    print_summary(result, given.a_report(), REPORT_PATH, given.the_outcomes_of(result))

    printed = output.getvalue()
    assert "Cases: 1 unchanged, 1 flip_not_reproduced" in printed
    assert f"flip_not_reproduced  {given.FLIPPED_ID}" in printed
    assert "partial:" not in printed


def test_the_summary_explains_a_partial_case(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    result = given.a_result_with_a_partial_case()

    print_summary(result, given.a_report(), REPORT_PATH, given.the_outcomes_of(result))

    printed = output.getvalue()
    assert "Cases: 1 partial" in printed
    assert (
        "partial: wrong in every baseline run, right in some runs of this one, not gated" in printed
    )


def test_the_summary_states_the_throttled_requests_and_the_concurrency(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)
    result = given.a_result_with_a_flip_not_reproduced()
    report = given.a_report(throttled_requests=4, concurrency=30)

    print_summary(result, report, REPORT_PATH, given.the_outcomes_of(result))

    assert "Throttled by the model provider: 4 requests at concurrency 30" in output.getvalue()
