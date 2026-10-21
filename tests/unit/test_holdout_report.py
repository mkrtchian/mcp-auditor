"""The holdout report model and its markdown: the structural guarantee that a holdout run keeps
no proof. The model carries no evidence, no judge input and no per-case verdict field."""

import dataclasses
from datetime import date

from evals.holdout_conditions import Cutoff
from evals.holdout_markdown import render_markdown
from evals.holdout_not_run import NotRunLine
from evals.holdout_report import (
    ConclusionLine,
    CutoffModel,
    HoldoutReport,
    IntervalModel,
    MethodLine,
    RunCutoffModel,
    SideLine,
    TargetLine,
    build_report,
)
from evals.holdout_results import (
    HoldoutRunResult,
    HoldoutTargetResult,
    NotRunCause,
    NotRunTarget,
)
from evals.holdout_statistic import Side

LUNA_CUTOFF = Cutoff(
    date=date(2026, 5, 18), type="training", source="https://example.test/luna", note=None
)
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
        cutoffs={"gpt-6-luna": LUNA_CUTOFF},
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
    report = build_report(_run_result())
    assert report.primary_number == (1.0 + 1 / 3) / 2
    sides = {line.side: line for line in report.sides}
    assert set(sides) == {Side.PRE_CUTOFF, Side.POST_CUTOFF}
    assert report.total_cost == 0.06


def test_render_markdown_shows_the_number_ladder_controls_and_cost():
    markdown = render_markdown(build_report(_run_result()))

    assert "Capability: 0.667 (95% Wilson " in markdown
    assert "## Ladder\n- 3 detecting run(s): 1 target(s)\n- 1 detecting run(s): 1 target(s)\n" in (
        markdown
    )
    assert "## Controls\n- clopper_pearson: " in markdown
    assert "- unchecked_as_misses_wilson: " in markdown
    assert "- CVE-C: dead condition on the patched version" in markdown
    assert "Incomplete runs (a step refused or unreadable): 1 (CVE-B)" in markdown
    assert markdown.endswith("Total cost: $0.06")


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

    markdown = render_markdown(build_report(run))

    assert f"- 2 of the 5 target(s) launched: {throttled}" in markdown
    assert f"- 1 of the 5 target(s) launched: {launch_failure}" in markdown
    assert "- CVE-D: " + throttled in markdown
    assert "- CVE-C: dead on a version: exploit 0" in markdown
    assert "launched: dead on a version" not in markdown


def test_the_not_run_section_counts_nothing_when_no_target_dropped_during_the_run():
    markdown = render_markdown(build_report(_run_result()))

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
        RunCutoffModel,
        IntervalModel,
    ]
    for model in models:
        assert set(model.model_fields).isdisjoint(forbidden)


def test_build_report_carries_the_run_conditions_and_provenance():
    report = build_report(_run_result())
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
    assert report.cutoffs["gpt-6-luna"] == CutoffModel(
        date=date(2026, 5, 18), type="training", source="https://example.test/luna", note=None
    )


EARLIER = Cutoff(
    date=date(2026, 1, 15), type="knowledge cutoff", source="https://a.test", note=None
)
LATER = Cutoff(
    date=date(2026, 6, 30),
    type="training data cutoff",
    source="https://b.test",
    note="the last day of the month is taken",
)


def test_the_run_cutoff_is_the_latest_cutoff_of_the_run_models():
    run = dataclasses.replace(_run_result(), cutoffs={"a": EARLIER, "b": LATER})

    report = build_report(run)

    assert report.run_cutoff == RunCutoffModel(
        model="b",
        date=date(2026, 6, 30),
        type="training data cutoff",
        source="https://b.test",
        note="the last day of the month is taken",
    )


def test_the_split_uses_the_run_cutoff_date():
    targets = (
        _target("CVE-A", disclosure_date=date(2026, 3, 1), detected_runs=3),
        _target("CVE-B", disclosure_date=date(2026, 7, 1), detected_runs=1),
    )
    early_only = dataclasses.replace(_run_result(), targets=targets, cutoffs={"a": EARLIER})
    both = dataclasses.replace(early_only, cutoffs={"a": EARLIER, "b": LATER})

    assert {line.side: line.targets for line in build_report(early_only).sides} == {
        Side.POST_CUTOFF: 2
    }
    assert {line.side: line.targets for line in build_report(both).sides} == {
        Side.PRE_CUTOFF: 1,
        Side.POST_CUTOFF: 1,
    }


def test_on_equal_cutoff_dates_the_first_model_of_the_run_is_named():
    same_day = dataclasses.replace(LATER, type="other wording", source="https://c.test")
    run = dataclasses.replace(_run_result(), cutoffs={"a": same_day, "b": LATER})

    assert build_report(run).run_cutoff.model == "a"


def test_the_split_section_opens_with_the_run_cutoff_line():
    markdown = render_markdown(build_report(_run_result()))

    assert (
        "## Split by cutoff side\n"
        "- run cutoff: 2026-05-18 (training), gpt-6-luna, https://example.test/luna\n"
    ) in markdown


def test_the_run_cutoff_line_carries_the_note_when_set():
    run = dataclasses.replace(_run_result(), cutoffs={"b": LATER})

    markdown = render_markdown(build_report(run))

    assert (
        "- run cutoff: 2026-06-30 (training data cutoff), b, https://b.test, "
        "note: the last day of the month is taken\n"
    ) in markdown
