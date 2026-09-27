"""The gate fed faulted candidates built from the recording refused on 2026-09-27.

These tests pin what the gate does with each fault on the floors of ADR 022, misses included:
recall's floor is one detection per run, precision's and coverage's 0.50. The recording holds
11 detections over its 3 runs, so a fault clears the recall floor unless it takes the
detections under 3.
"""

from dataclasses import dataclass

import pytest

import tests.unit.support.test_eval_fault_injection_given as given
import tests.unit.support.test_eval_fault_injection_then as then
from evals.baseline import Baseline
from evals.gate import (
    Cell,
    CellComparison,
    CellOutcome,
    FlipCause,
    compare,
    count_detections,
    protected_cells,
    settle,
)
from evals.gate_verdict import GateInput, GateMode, GateResult, judge_gate
from evals.honeypots import MERGED_GROUND_TRUTH
from evals.recording import Recording, RecordingRefused, decide_recording
from mcp_auditor.domain.models import AuditCategory

NO_DETECTION = "recall: 0 detection(s) over 3 runs, under one per run"
NO_STABLE_FAIL = (
    "no planted FAIL cell is stable and correct: the gate could not see a lost detection"
)
NO_STABLE_PASS = "no PASS cell is stable and correct: the gate could not see a new false positive"


def test_a_judge_passing_everything_is_caught_by_the_recall_floor_and_the_regressions():
    run = _through_the_gate(given.a_judge_passing_everything(), given.REPRODUCING)

    then.flipped(run.cells, given.STABLE_CORRECT_FAILS, FlipCause.WRONG_VERDICT)
    then.red_on(
        run.paired,
        NO_DETECTION,
        "regression on get_user/error_handling",
        "regression on execute_query/info_leakage",
        "regression on delete_record/input_validation",
    )
    then.red_on(run.floors_only, NO_DETECTION)
    then.refused_on(run.recording, "recall under its floor", NO_STABLE_FAIL)


def test_a_judge_failing_everything_is_caught_by_the_precision_floor_and_the_regressions():
    run = _through_the_gate(given.a_judge_failing_everything(), given.REPRODUCING)

    then.flipped(run.cells, given.EXPECTED_PASSES, FlipCause.WRONG_VERDICT)
    then.settled_as(run.paired, given.EXPECTED_PASSES, CellOutcome.REGRESSION)
    assert run.paired.reasons[0] == "precision 0.22 under its floor 0.50"
    then.red_on(run.floors_only, "precision 0.22 under its floor 0.50")
    then.refused_on(run.recording, "precision under its floor", NO_STABLE_PASS)


def test_a_judge_failing_at_random_seed_0_is_caught_by_precision_but_its_flips_do_not_reproduce():
    run = _through_the_gate(given.a_judge_failing_at_random(seed=0), given.REPRODUCING_TWICE)

    flips = [
        cell for cell in given.STABLE_CORRECT_CELLS if cell not in given.SPARED_BY_THE_RANDOM_JUDGE
    ]
    then.flipped(run.cells, flips, FlipCause.WRONG_VERDICT)
    then.settled_as(run.paired, flips, CellOutcome.FLIP_NOT_REPRODUCED)
    then.red_on(run.paired, "precision 0.19 under its floor 0.50")
    then.red_on(run.floors_only, "precision 0.19 under its floor 0.50")
    then.refused_on(run.recording, "precision under its floor")


def test_no_verdict_flips_every_stable_and_correct_cell_as_uncovered():
    run = _through_the_gate(given.no_verdict(), given.REPRODUCING)

    then.flipped(run.cells, given.STABLE_CORRECT_CELLS, FlipCause.UNCOVERED)
    floors = (NO_DETECTION, "distribution_coverage 0.00 under its floor 0.50")
    assert run.paired.reasons[:2] == list(floors)
    then.settled_as(run.paired, given.STABLE_CORRECT_CELLS, CellOutcome.REGRESSION)
    then.red_on(run.floors_only, *floors)
    then.refused_on(
        run.recording,
        "recall under its floor",
        "distribution_coverage under its floor",
        NO_STABLE_FAIL,
        NO_STABLE_PASS,
    )


@pytest.mark.parametrize(
    "replays", [given.REPRODUCING_TWICE, given.REPRODUCING_THREE_TIMES], ids=["2_of_5", "3_of_5"]
)
def test_half_the_detections_lost_is_missed_by_the_paired_comparison_and_the_floors(
    replays: list[bool],
):
    run = _through_the_gate(given.half_the_detections_lost(seed=0), replays)

    then.flipped(run.cells, given.LOST_BY_THE_HALF_LOSS_DRAW, FlipCause.WRONG_VERDICT)
    then.settled_as(run.paired, given.LOST_BY_THE_HALF_LOSS_DRAW, CellOutcome.FLIP_NOT_REPRODUCED)
    then.green(run.paired)
    then.green(run.floors_only)
    then.accepted(run.recording)


@pytest.mark.parametrize("category", list(AuditCategory))
def test_a_dropped_category_flips_its_stable_and_correct_cells_and_clears_the_coverage_floor(
    category: AuditCategory,
):
    run = _through_the_gate(given.a_generator_dropping(category), given.REPRODUCING)

    dropped = [cell for cell in given.STABLE_CORRECT_CELLS if cell[1] == category]
    then.flipped(run.cells, dropped, FlipCause.UNCOVERED)
    then.settled_as(run.paired, dropped, CellOutcome.REGRESSION)
    assert "distribution_coverage" not in run.floors_only.floor_breaches
    then.accepted(run.recording)


def test_chain_steps_refused_move_no_cell_on_the_chain_only_flaws_and_are_missed():
    run = _through_the_gate(given.chain_steps_refused(), given.REPRODUCING)

    assert run.cells[given.CHAIN_ONLY_FLAWS[0]].outcome == CellOutcome.INCONCLUSIVE
    assert run.cells[given.CHAIN_ONLY_FLAWS[1]].outcome == CellOutcome.UNCHANGED
    then.flipped(run.cells, [], FlipCause.WRONG_VERDICT)
    then.green(run.paired)
    then.green(run.floors_only)
    then.accepted(run.recording)


@dataclass(frozen=True)
class _GateRun:
    cells: dict[Cell, CellComparison]
    paired: GateResult
    floors_only: GateResult
    recording: Baseline | RecordingRefused


def _through_the_gate(candidate: given.FaultedCandidate, replays: list[bool]) -> _GateRun:
    """Every flip settles on the same scripted replays: the fault stays active in them."""
    baseline = given.the_fault_injection_baseline()
    metrics = given.metrics_of(candidate)
    detections = count_detections(candidate.runs, MERGED_GROUND_TRUTH)
    cells = compare(baseline.observation_runs(), candidate.runs, MERGED_GROUND_TRUTH)
    settled = {
        cell: settle(comparison, replays, baseline.replay_rule)
        if comparison.outcome == CellOutcome.FLIP
        else comparison
        for cell, comparison in cells.items()
    }
    paired = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=metrics,
            detections=detections,
            baseline_status=baseline.status,
            cells=settled,
        )
    )
    floors_only = judge_gate(
        GateInput(mode=GateMode.FLOORS_ONLY, metrics=metrics, detections=detections, cells=cells)
    )
    recording = Recording(
        conditions=baseline.conditions,
        commit=baseline.commit,
        recorded_at=baseline.recorded_at,
        runs=candidate.runs,
        metrics=metrics,
        completed_all=True,
        protected=protected_cells(candidate.runs, MERGED_GROUND_TRUTH),
    )
    return _GateRun(cells, paired, floors_only, decide_recording(None, recording, floors_only))
