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
    TargetRunLine,
    build_report,
)
from evals.holdout_results import (
    HoldoutRunResult,
    HoldoutRunStatus,
    HoldoutTargetResult,
    NotRunCause,
    NotRunTarget,
)
from evals.holdout_statistic import Side

LUNA_CUTOFF = Cutoff(
    date=date(2026, 5, 18), type="training", source="https://example.test/luna", note=None
)
RUNS = 3
RECORDED_AT = "2026-10-28T09:30:00+00:00"


def _target(cve_id: str, *, disclosure_date: date, detected_runs: int, incomplete_runs: int = 0):
    return HoldoutTargetResult(
        cve_id=cve_id,
        disclosure_date=disclosure_date,
        mechanism_label="command_execution",
        tools_count=5,
        ran_in_fallback=False,
        statuses=tuple(
            HoldoutRunStatus(
                detected=index < detected_runs,
                detected_if_unchecked_missed=index < detected_runs,
                surfaced_places=["srv_config"] if index < detected_runs else [],
                struck_places=[],
                unchecked_places=[],
                aimed=index < detected_runs,
                fail_without_proof=False,
                incomplete=index >= RUNS - incomplete_runs,
                non_protocol_lines=0,
                lost_connection_responses=0,
                unchecked_reason=None,
                replay_attempt_failures=[],
                miss_causes=["provider_refusal"] if index >= RUNS - incomplete_runs else [],
            )
            for index in range(RUNS)
        ),
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
        recorded_at=RECORDED_AT,
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
        concurrency=6,
        throttled_requests=0,
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


def test_render_markdown_states_the_throttled_requests_after_the_incomplete_runs():
    run = dataclasses.replace(_run_result(), throttled_requests=12, concurrency=4)

    report = build_report(run)
    markdown = render_markdown(report)

    assert (report.throttled_requests, report.concurrency) == (12, 4)
    assert (
        "Incomplete runs (a step refused or unreadable): 1 (CVE-B)\n"
        "- provider_refusal: 1 run(s)\n"
        "Throttled by the model provider: 12 requests at concurrency 4\n"
    ) in markdown


def test_render_markdown_leaves_throttling_out_when_nothing_was_throttled():
    markdown = render_markdown(build_report(_run_result()))

    assert "Throttled" not in markdown


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


def test_a_target_line_keeps_its_disclosure_date_and_the_facts_of_each_run():
    report = build_report(_run_result())

    line = next(line for line in report.targets if line.cve_id == "CVE-B")

    assert line.disclosure_date == date(2026, 12, 1)
    assert line.per_run == [
        TargetRunLine(
            detected=True,
            detected_if_unchecked_missed=True,
            aimed=True,
            fail_without_proof=False,
            incomplete=False,
            non_protocol_lines=0,
            lost_connection_responses=0,
            unchecked_reason=None,
            replay_attempt_failures=[],
            miss_causes=[],
        ),
        TargetRunLine(
            detected=False,
            detected_if_unchecked_missed=False,
            aimed=False,
            fail_without_proof=False,
            incomplete=False,
            non_protocol_lines=0,
            lost_connection_responses=0,
            unchecked_reason=None,
            replay_attempt_failures=[],
            miss_causes=[],
        ),
        TargetRunLine(
            detected=False,
            detected_if_unchecked_missed=False,
            aimed=False,
            fail_without_proof=False,
            incomplete=True,
            non_protocol_lines=0,
            lost_connection_responses=0,
            unchecked_reason=None,
            replay_attempt_failures=[],
            miss_causes=["provider_refusal"],
        ),
    ]


def _with_incidents(target: HoldoutTargetResult) -> HoldoutTargetResult:
    unchecked, refused, clean = target.statuses
    return dataclasses.replace(
        target,
        statuses=(
            dataclasses.replace(
                unchecked,
                non_protocol_lines=2,
                lost_connection_responses=1,
                unchecked_reason="no_attempt_decided",
                replay_attempt_failures=["launch_failed", "launch_failed"],
            ),
            dataclasses.replace(
                refused,
                detected=False,
                detected_if_unchecked_missed=False,
                surfaced_places=[],
                incomplete=True,
                miss_causes=["provider_refusal", "unreadable_answer"],
            ),
            clean,
        ),
    )


def _run_with_incidents() -> HoldoutRunResult:
    run = _run_result()
    first, second = run.targets
    return dataclasses.replace(
        run, targets=(_with_incidents(first), second), incomplete_run_count=2
    )


def test_a_target_line_sums_its_health_and_counts_its_replay_and_miss_causes():
    report = build_report(_run_with_incidents())

    line = next(line for line in report.targets if line.cve_id == "CVE-A")

    assert (line.non_protocol_lines, line.lost_connection_responses) == (2, 1)
    assert line.unchecked_runs_by_reason == {"no_attempt_decided": 1}
    assert line.replay_attempt_failures_by_cause == {"launch_failed": 2}
    assert line.incomplete_runs_by_cause == {"provider_refusal": 1, "unreadable_answer": 1}
    assert line.per_run[0].replay_attempt_failures == ["launch_failed", "launch_failed"]
    assert line.per_run[1].miss_causes == ["provider_refusal", "unreadable_answer"]
    assert report.incomplete_runs_by_cause == {"provider_refusal": 2, "unreadable_answer": 1}


def test_the_markdown_names_each_target_with_a_health_count_or_a_replay_failure():
    markdown = render_markdown(build_report(_run_with_incidents()))

    assert (
        "## Server health and replay\n"
        "- CVE-A: non-protocol lines 2, connection lost on 1 call(s),"
        " replay unchecked: no_attempt_decided x1, replay attempt failures: launch_failed x2\n"
    ) in markdown
    assert "- CVE-B: non-protocol" not in markdown


def test_the_markdown_splits_the_incomplete_runs_by_cause():
    markdown = render_markdown(build_report(_run_with_incidents()))

    assert (
        "Incomplete runs (a step refused or unreadable): 2 (CVE-A, CVE-B)\n"
        "- provider_refusal: 2 run(s)\n"
        "- unreadable_answer: 1 run(s)\n"
    ) in markdown


def test_the_markdown_leaves_the_health_section_out_when_nothing_happened():
    markdown = render_markdown(build_report(_run_result()))

    assert "## Server health and replay" not in markdown


def test_the_recorded_at_line_carries_the_run_timestamp():
    markdown = render_markdown(build_report(_run_result()))

    assert f"Recorded at: {RECORDED_AT}\n" in markdown


def test_the_report_holds_no_proof_text_fields():
    forbidden = {"evidence", "category", "judge_input", "judge", "verdict", "status", "miss_class"}
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
    markdown = render_markdown(build_report(_run_with_incidents()))
    assert "evidence" not in markdown and "verdict" not in markdown


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
    assert report.recorded_at == RECORDED_AT
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
