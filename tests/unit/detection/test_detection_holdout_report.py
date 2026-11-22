"""The holdout report model and its markdown: the structural guarantee that a detection holdout run
keeps no proof. The model carries no evidence, no judge input and no per-case verdict field."""

import dataclasses
from datetime import date

import tests.unit.detection.support.test_detection_holdout_report_given as given
from evals.cve.detection.holdout_markdown import render_markdown
from evals.cve.detection.holdout_not_run import NotRunLine
from evals.cve.detection.holdout_report import (
    ConclusionLine,
    CutoffModel,
    HoldoutReport,
    IntervalModel,
    MethodLine,
    RunCutoffModel,
    SideLine,
    build_report,
)
from evals.cve.detection.holdout_results import NotRunCause, NotRunTarget
from evals.cve.detection.holdout_target_line import TargetLine, TargetRunLine
from evals.cve.holdout_statistic import Side
from tests.unit.detection.support.holdout_report_runs import RECORDED_AT, RUNS, a_run_result
from tests.unit.support.coarse_grid import COARSE_GRID


def test_build_report_carries_the_holdout_detection_rate_and_the_split():
    report = build_report(a_run_result(), grid=COARSE_GRID)
    assert report.holdout_detection_rate == (1.0 + 1 / 3) / 2
    sides = {line.side: line for line in report.sides}
    assert set(sides) == {Side.PRE_CUTOFF, Side.POST_CUTOFF}
    assert report.total_cost == 0.06


def test_render_markdown_shows_the_number_ladder_controls_and_cost():
    markdown = render_markdown(build_report(a_run_result(), grid=COARSE_GRID))

    assert "Holdout detection rate: 0.667 (95% Wilson " in markdown
    assert "## Ladder\n- 3 detecting run(s): 1 target(s)\n- 1 detecting run(s): 1 target(s)\n" in (
        markdown
    )
    assert "## Controls\n- clopper_pearson: " in markdown
    assert "- unchecked_as_misses_wilson: " in markdown
    assert "- CVE-C: out of calibration: patched: exploit 0 surfaces" in markdown
    assert f"{given.INCOMPLETE_RUNS}: 1 (CVE-B)" in markdown
    assert markdown.endswith("Total cost: $0.06")


def test_render_markdown_names_the_targets_run_after_a_solo_second_pre_run_pass():
    run = dataclasses.replace(a_run_result(), second_pass=("CVE-B",))

    markdown = render_markdown(build_report(run, grid=COARSE_GRID))

    assert (
        "- CVE-C: out of calibration: patched: exploit 0 surfaces\n"
        "- run after a clean solo second pass of the pre-run check: CVE-B\n"
    ) in markdown


def test_render_markdown_names_no_second_pass_when_every_target_passed_the_first():
    markdown = render_markdown(build_report(a_run_result(), grid=COARSE_GRID))

    assert "second pass" not in markdown


def test_render_markdown_states_the_throttled_requests_after_the_incomplete_runs():
    run = dataclasses.replace(a_run_result(), throttled_requests=12, concurrency=4)

    report = build_report(run, grid=COARSE_GRID)
    markdown = render_markdown(report)

    assert (report.throttled_requests, report.concurrency) == (12, 4)
    assert (
        f"{given.INCOMPLETE_RUNS}: 1 (CVE-B)\n"
        "- provider_refusal: 1 run(s)\n"
        "Throttled by the model provider: 12 requests at concurrency 4\n"
    ) in markdown


def test_render_markdown_leaves_throttling_out_when_nothing_was_throttled():
    markdown = render_markdown(build_report(a_run_result(), grid=COARSE_GRID))

    assert "Throttled" not in markdown


def test_the_not_run_section_counts_the_in_run_drops_per_cause_against_the_targets_launched():
    pre_run = NotRunTarget("CVE-C", "out of calibration: exploit 0", NotRunCause.PRE_RUN_CHECK)
    throttled = "throttled by the model provider past every retry"
    launch_failure = "a run failed to launch after retries"
    run = dataclasses.replace(
        a_run_result(),
        not_run=(
            pre_run,
            NotRunTarget("CVE-D", throttled, NotRunCause.THROTTLED),
            NotRunTarget("CVE-E", throttled, NotRunCause.THROTTLED),
            NotRunTarget("CVE-F", launch_failure, NotRunCause.LAUNCH_FAILURE),
        ),
    )

    markdown = render_markdown(build_report(run, grid=COARSE_GRID))

    assert f"- 2 of the 5 target(s) launched: {throttled}" in markdown
    assert f"- 1 of the 5 target(s) launched: {launch_failure}" in markdown
    assert "- CVE-D: " + throttled in markdown
    assert "- CVE-C: out of calibration: exploit 0" in markdown
    assert "launched: out of calibration" not in markdown


def test_the_not_run_section_counts_nothing_when_no_target_dropped_during_the_run():
    markdown = render_markdown(build_report(a_run_result(), grid=COARSE_GRID))

    assert "target(s) launched" not in markdown


def test_a_target_line_keeps_its_disclosure_date_and_the_facts_of_each_run():
    report = build_report(a_run_result(), grid=COARSE_GRID)

    line = next(line for line in report.targets if line.flaw_id == "CVE-B")

    assert line.disclosure_date == date(2026, 12, 1)
    assert line.class_labels == ["command_execution", "read_outside_scope"]
    assert [
        (run.detected, run.detected_if_unchecked_missed, run.aimed, run.incomplete)
        for run in line.per_run
    ] == [(True, True, True, False), (False, False, False, False), (False, False, False, True)]
    assert [run.missed_call_causes for run in line.per_run] == [[], [], ["provider_refusal"]]


def test_a_target_line_sums_its_health_and_counts_its_replay_and_miss_causes():
    report = build_report(given.a_run_with_incidents(), grid=COARSE_GRID)

    line = next(line for line in report.targets if line.flaw_id == "CVE-A")

    assert (line.non_protocol_lines, line.lost_connection_responses) == (2, 1)
    assert (line.relaunches, line.unsent_calls) == (1, 3)
    assert (line.per_run[0].relaunches, line.per_run[0].unsent_calls) == (1, 3)
    assert (line.cut_responses, line.per_run[0].cut_responses) == (1, 1)
    assert line.unchecked_runs_by_reason == {"no_attempt_decided": 1}
    assert line.replay_attempt_failures_by_cause == {"launch_failed": 2}
    assert line.incomplete_runs_by_cause == {"provider_refusal": 1, "unreadable_answer": 1}
    assert line.per_run[0].replay_attempt_failures == ["launch_failed", "launch_failed"]
    assert line.per_run[1].missed_call_causes == ["provider_refusal", "unreadable_answer"]
    assert report.incomplete_runs_by_cause == {"provider_refusal": 2, "unreadable_answer": 1}


def test_the_markdown_names_each_target_with_a_health_count_or_a_replay_failure():
    markdown = render_markdown(build_report(given.a_run_with_incidents(), grid=COARSE_GRID))

    assert (
        "## Server health and replay\n"
        "- CVE-A: non-protocol lines 2, connection lost on 1 call(s), relaunched 1 time(s),"
        " 3 call(s) not sent, 1 response(s) shown cut, replay unchecked: no_attempt_decided x1,"
        " replay attempt failures: launch_failed x2\n"
    ) in markdown
    assert "- CVE-B: non-protocol" not in markdown


def test_the_markdown_names_a_target_whose_server_was_only_relaunched():
    run = a_run_result()
    first, second = run.targets
    relaunched = dataclasses.replace(first.statuses[0], relaunches=2)
    first = dataclasses.replace(first, statuses=(relaunched, *first.statuses[1:]))

    markdown = render_markdown(
        build_report(dataclasses.replace(run, targets=(first, second)), grid=COARSE_GRID)
    )

    assert "## Server health and replay\n- CVE-A: relaunched 2 time(s)\n" in markdown


def test_the_markdown_splits_the_incomplete_runs_by_cause():
    markdown = render_markdown(build_report(given.a_run_with_incidents(), grid=COARSE_GRID))

    assert (
        f"{given.INCOMPLETE_RUNS}: 2 (CVE-A, CVE-B)\n"
        "- provider_refusal: 2 run(s)\n"
        "- unreadable_answer: 1 run(s)\n"
    ) in markdown


def test_the_markdown_leaves_the_health_section_out_when_nothing_happened():
    markdown = render_markdown(build_report(a_run_result(), grid=COARSE_GRID))

    assert "## Server health and replay" not in markdown


def test_the_recorded_at_line_carries_the_run_timestamp():
    markdown = render_markdown(build_report(a_run_result(), grid=COARSE_GRID))

    assert f"Recorded at: {RECORDED_AT}\n" in markdown


def test_the_report_holds_no_proof_text_fields():
    forbidden = {"evidence", "category", "judge_input", "judge", "verdict", "status", "miss_kind"}
    models = [
        HoldoutReport,
        TargetLine,
        TargetRunLine,
        SideLine,
        MethodLine,
        ConclusionLine,
        NotRunLine,
        CutoffModel,
        RunCutoffModel,
        IntervalModel,
    ]
    for model in models:
        assert set(model.model_fields).isdisjoint(forbidden)
    markdown = render_markdown(build_report(given.a_run_with_incidents(), grid=COARSE_GRID))
    assert "evidence" not in markdown and "verdict" not in markdown


def test_build_report_carries_the_run_conditions_and_provenance():
    report = build_report(a_run_result(), grid=COARSE_GRID)
    assert report.model == "gpt-6-luna"
    assert report.judge_model == "gpt-6-luna"
    assert report.reasoning == "none"
    assert report.runs == RUNS
    assert report.budget == 10
    assert report.chain_budget == 3
    assert report.tool_call_timeout == 30
    assert report.grammar_fingerprint == "grammar-abc"
    assert report.fixture_fingerprints == {"CVE-A": "fa", "CVE-B": "fb"}
    assert report.image_ids == {"vuln": "sha256:1"}
    assert report.recorded_at == RECORDED_AT
    assert report.cutoffs["gpt-6-luna"] == CutoffModel(
        date=date(2026, 5, 18), type="training", source="https://example.test/luna", note=None
    )
