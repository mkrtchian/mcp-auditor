"""The holdout report model and its markdown: the structural guarantee that a holdout run keeps
no proof. The model carries no evidence, no judge input and no per-case verdict field."""

import dataclasses
from datetime import date

from evals.census_draw import Side
from evals.holdout_conditions import Cutoff
from evals.holdout_not_run import NotRunLine
from evals.holdout_report import (
    ConclusionLine,
    CutoffModel,
    HoldoutReport,
    IntervalModel,
    MethodLine,
    SideLine,
    TargetLine,
    build_report,
    render_markdown,
)
from evals.holdout_results import (
    HoldoutRunResult,
    HoldoutTargetResult,
    NotRunCause,
    NotRunTarget,
)

RUN_CUTOFF = date(2026, 5, 18)
RUNS = 3


def _target(cve_id: str, *, disclosure_date: date, detected_runs: int, incomplete_runs: int = 0):
    return HoldoutTargetResult(
        cve_id=cve_id,
        disclosure_date=disclosure_date,
        mechanism_label="command_execution",
        tools_count=5,
        ran_in_fallback=False,
        runs=RUNS,
        detected_runs=detected_runs,
        detection_share=detected_runs / RUNS,
        detected_runs_if_unchecked_missed=detected_runs,
        surfaced_places=[["srv_config"]] * detected_runs + [[]] * (RUNS - detected_runs),
        struck_places=[[] for _ in range(RUNS)],
        unchecked_places=[[] for _ in range(RUNS)],
        aimed_runs=detected_runs,
        fail_without_proof_runs=0,
        incomplete_runs=incomplete_runs,
        run_cost=0.02,
    )


def _run_result() -> HoldoutRunResult:
    targets = [
        _target("CVE-A", disclosure_date=date(2026, 1, 1), detected_runs=3),
        _target("CVE-B", disclosure_date=date(2026, 12, 1), detected_runs=1, incomplete_runs=1),
    ]
    return HoldoutRunResult(
        runs=RUNS,
        budget=10,
        provider="openai",
        model="gpt-6-luna",
        judge_model="gpt-6-luna",
        reasoning="none",
        judge_reasoning="none",
        cutoffs={"gpt-6-luna": Cutoff(date=RUN_CUTOFF, type="training", note=None)},
        chain_budget=3,
        max_chain_steps=5,
        tool_call_timeout=30,
        grammar_fingerprint="grammar-abc",
        fixture_fingerprints={"CVE-A": "fa", "CVE-B": "fb"},
        commit="deadbeef",
        census_commit="cafe1234",
        image_ids={"vuln": "sha256:1"},
        targets=tuple(targets),
        not_run=(
            NotRunTarget(
                cve_id="CVE-C",
                reason="dead condition on the patched version",
                cause=NotRunCause.PRE_RUN_CHECK,
            ),
        ),
        incomplete_run_count=1,
        total_cost=0.06,
        prices_as_of=date(2026, 10, 15),
    )


def test_build_report_carries_the_primary_number_and_the_split():
    report = build_report(_run_result(), RUN_CUTOFF)
    assert report.primary_number == (1.0 + 1 / 3) / 2
    sides = {line.side: line for line in report.sides}
    assert set(sides) == {Side.PRE_CUTOFF, Side.POST_CUTOFF}
    assert report.total_cost == 0.06


def test_render_markdown_shows_the_number_ladder_split_controls_and_cost():
    markdown = render_markdown(build_report(_run_result(), RUN_CUTOFF))
    assert "0.667" in markdown  # the primary number, three decimals
    assert "Ladder" in markdown
    assert "Split" in markdown
    assert "Controls" in markdown
    assert "$0.06" in markdown
    assert "dead condition on the patched version" in markdown  # a not-run reason
    assert (
        "Incomplete runs (a step refused or unreadable): 1 (CVE-B)" in markdown
    )  # the count with the target it touches


def test_the_not_run_section_counts_the_in_run_drops_per_cause_against_the_targets_launched():
    pre_run = NotRunTarget("CVE-C", "dead on a version: exploit 0", NotRunCause.PRE_RUN_CHECK)
    throttled = "throttled by the model provider past every retry"
    launch_failure = "a run failed to launch after retries"
    run = dataclasses.replace(
        _run_result(),
        not_run=(
            pre_run,
            NotRunTarget("CVE-D", throttled, NotRunCause.THROTTLED),
            NotRunTarget("CVE-E", throttled, NotRunCause.THROTTLED),
            NotRunTarget("CVE-F", launch_failure, NotRunCause.LAUNCH_FAILURE),
        ),
    )

    markdown = render_markdown(build_report(run, RUN_CUTOFF))

    assert f"- 2 of the 5 target(s) launched: {throttled}" in markdown
    assert f"- 1 of the 5 target(s) launched: {launch_failure}" in markdown
    assert "- CVE-D: " + throttled in markdown
    assert "- CVE-C: dead on a version: exploit 0" in markdown
    assert "launched: dead on a version" not in markdown


def test_the_not_run_section_counts_nothing_when_no_target_dropped_during_the_run():
    markdown = render_markdown(build_report(_run_result(), RUN_CUTOFF))

    assert "target(s) launched" not in markdown


def test_the_report_holds_no_proof_text_fields():
    forbidden = {"evidence", "category", "judge_input", "judge", "verdict", "status", "miss_class"}
    models = [
        HoldoutReport,
        TargetLine,
        SideLine,
        MethodLine,
        ConclusionLine,
        NotRunLine,
        CutoffModel,
        IntervalModel,
    ]
    for model in models:
        assert set(model.model_fields).isdisjoint(forbidden)


def test_build_report_carries_the_run_conditions_and_provenance():
    report = build_report(_run_result(), RUN_CUTOFF)
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
    assert report.cutoffs["gpt-6-luna"].date == RUN_CUTOFF
