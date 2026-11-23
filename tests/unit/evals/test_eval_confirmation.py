import math

import tests.unit.evals.support.honeypot_baselines as honeypot_baselines
import tests.unit.evals.support.honeypot_gate_inputs as honeypot_gate_inputs
import tests.unit.evals.support.honeypot_recordings as honeypot_recordings
from evals.baseline import Baseline, BaselineStatus, RecordingRef
from evals.gate import CellOutcome, Observation, ProtectedCells, compare
from evals.ground_truth import cell_key
from evals.recording import (
    RecordingRefused,
    decide_recording,
    gated_set_changes,
)

VULNERABLE_CELL = honeypot_gate_inputs.VULNERABLE_CELL
SAFE_CELL = honeypot_gate_inputs.SAFE_CELL
FAIL, PASS, UNCOVERED = Observation.FAIL, Observation.PASS, Observation.UNCOVERED
_NOT_MADE_AGAIN = "not made again against the same first recording (ADR 023)"


def test_a_second_recording_agreeing_on_stable_cells_confirms_the_first():
    existing = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())
    recording = honeypot_recordings.a_recording()

    result = decide_recording(existing, recording, honeypot_recordings.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.confirms == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.replaces is None
    assert result.observation_runs() == existing.observation_runs() + recording.runs
    assert result.disagreements == []


def test_a_second_recording_disagreeing_on_a_stable_cell_confirms_with_the_cell_unstable():
    ground_truth = honeypot_gate_inputs.a_ground_truth_with_two_cells_of_each_side()
    existing = honeypot_baselines.a_baseline(
        runs=honeypot_recordings.four_cell_runs(), ground_truth=ground_truth
    )
    varying = honeypot_recordings.four_cell_runs(vulnerable=(FAIL, PASS, FAIL))
    recording = honeypot_recordings.a_recording(runs=varying, ground_truth=ground_truth)

    result = decide_recording(existing, recording, honeypot_recordings.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.confirms == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.replaces is None
    assert result.disagreements == [cell_key(VULNERABLE_CELL)]
    assert result.protected is not None
    assert (result.protected.fail_stable_correct, result.protected.unstable) == (1, 1)
    changes = gated_set_changes(existing, result, ground_truth)
    assert changes.leaving == [cell_key(VULNERABLE_CELL)]


def test_a_cell_varying_in_the_first_recording_and_stable_in_the_second_is_never_gated():
    ground_truth = honeypot_gate_inputs.a_ground_truth_with_two_cells_of_each_side()
    first = honeypot_recordings.four_cell_runs(vulnerable=(FAIL, UNCOVERED, FAIL))
    existing = honeypot_baselines.a_baseline(runs=first, ground_truth=ground_truth)
    recording = honeypot_recordings.a_recording(
        runs=honeypot_recordings.four_cell_runs(), ground_truth=ground_truth
    )

    result = decide_recording(existing, recording, honeypot_recordings.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.observation_runs() == first + recording.runs
    assert result.disagreements == []
    assert result.protected is not None
    assert result.protected.unstable == 1
    changes = gated_set_changes(existing, result, ground_truth)
    assert cell_key(VULNERABLE_CELL) not in changes.entering + changes.leaving


def test_a_second_recording_seeing_uncovered_where_the_first_saw_fail_disagrees():
    ground_truth = honeypot_gate_inputs.a_ground_truth_with_two_cells_of_each_side()
    first = honeypot_recordings.four_cell_runs(safe=(FAIL, FAIL, FAIL))
    existing = honeypot_baselines.a_baseline(runs=first, ground_truth=ground_truth)
    uncovered = honeypot_recordings.four_cell_runs(safe=(UNCOVERED, UNCOVERED, UNCOVERED))
    recording = honeypot_recordings.a_recording(runs=uncovered, ground_truth=ground_truth)

    result = decide_recording(existing, recording, honeypot_recordings.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.disagreements == [cell_key(SAFE_CELL)]


def test_combined_runs_leaving_no_stable_and_correct_fail_cell_are_refused():
    existing = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())
    missed = honeypot_baselines.runs_where_vulnerable_cell_is(PASS, PASS, PASS)

    result = decide_recording(
        existing, honeypot_recordings.a_recording(runs=missed), honeypot_recordings.a_gate()
    )

    assert isinstance(result, RecordingRefused)
    assert any(
        "no planted FAIL cell" in reason and "over the runs of both recordings" in reason
        for reason in result.reasons
    )
    assert any(_NOT_MADE_AGAIN in reason for reason in result.reasons)


def test_combined_runs_leaving_no_stable_and_correct_pass_cell_are_refused():
    existing = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())
    false_positives = honeypot_recordings.runs_where_safe_cell_is(FAIL)

    result = decide_recording(
        existing,
        honeypot_recordings.a_recording(runs=false_positives),
        honeypot_recordings.a_gate(),
    )

    assert isinstance(result, RecordingRefused)
    assert any(
        "no PASS cell" in reason and "over the runs of both recordings" in reason
        for reason in result.reasons
    )
    assert any(_NOT_MADE_AGAIN in reason for reason in result.reasons)


def test_a_second_recording_breaching_a_floor_is_not_made_again():
    existing = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())
    gate = honeypot_recordings.a_gate(floor_breaches=["precision"])

    result = decide_recording(existing, honeypot_recordings.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert any("precision" in reason for reason in result.reasons)
    assert any(_NOT_MADE_AGAIN in reason for reason in result.reasons)


def test_a_second_recording_with_a_failed_run_can_be_made_again():
    existing = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())

    result = decide_recording(
        existing, honeypot_recordings.a_recording(completed_all=False), honeypot_recordings.a_gate()
    )

    assert isinstance(result, RecordingRefused)
    assert not any(_NOT_MADE_AGAIN in reason for reason in result.reasons)


def test_a_confirmed_baseline_averages_its_metrics_over_the_runs_of_both_recordings():
    ground_truth = honeypot_gate_inputs.a_ground_truth_with_two_cells_of_each_side()
    existing = honeypot_baselines.a_baseline(
        runs=honeypot_recordings.four_cell_runs(), ground_truth=ground_truth
    )
    one_run_half_wrong = honeypot_recordings.four_cell_runs(
        vulnerable=(PASS, FAIL, FAIL), safe=(FAIL, PASS, PASS)
    )
    recording = honeypot_recordings.a_recording(runs=one_run_half_wrong, ground_truth=ground_truth)

    result = decide_recording(existing, recording, honeypot_recordings.a_gate())

    assert isinstance(result, Baseline)
    assert math.isclose(result.metrics.recall, 11 / 12)
    assert math.isclose(result.metrics.precision, 11 / 12)
    assert math.isclose(result.metrics.consistency, 11 / 12)
    assert math.isclose(
        result.metrics.distribution_coverage,
        (existing.metrics.distribution_coverage + recording.metrics.distribution_coverage) / 2,
    )


def test_a_confirmed_baseline_counts_the_protected_cells_of_the_combined_runs():
    ground_truth = honeypot_gate_inputs.a_ground_truth_with_two_cells_of_each_side()
    existing = honeypot_baselines.a_baseline(
        runs=honeypot_recordings.four_cell_runs(), ground_truth=ground_truth
    )
    varying = honeypot_recordings.four_cell_runs(
        vulnerable=(FAIL, PASS, FAIL), safe=(PASS, PASS, UNCOVERED)
    )
    recording = honeypot_recordings.a_recording(runs=varying, ground_truth=ground_truth)

    result = decide_recording(existing, recording, honeypot_recordings.a_gate())

    assert isinstance(result, Baseline)
    assert result.protected == ProtectedCells(
        fail_stable_correct=1, fail_total=2, pass_stable_correct=1, pass_total=2, unstable=2
    )


def test_a_candidate_compared_to_a_combined_baseline_flips_only_cells_stable_over_both():
    ground_truth = honeypot_gate_inputs.a_ground_truth_with_two_cells_of_each_side()
    existing = honeypot_baselines.a_baseline(
        runs=honeypot_recordings.four_cell_runs(), ground_truth=ground_truth
    )
    varying = honeypot_recordings.four_cell_runs(vulnerable=(FAIL, PASS, FAIL))
    confirmed = decide_recording(
        existing,
        honeypot_recordings.a_recording(runs=varying, ground_truth=ground_truth),
        honeypot_recordings.a_gate(),
    )
    assert isinstance(confirmed, Baseline)
    missing_both = [
        {**run, honeypot_gate_inputs.OTHER_VULNERABLE_CELL: PASS}
        for run in honeypot_recordings.four_cell_runs(vulnerable=(PASS, PASS, PASS))
    ]

    cells = compare(confirmed.observation_runs(), missing_both, ground_truth)

    assert cells[honeypot_gate_inputs.OTHER_VULNERABLE_CELL].outcome == CellOutcome.FLIP
    assert cells[VULNERABLE_CELL].outcome == CellOutcome.INCONCLUSIVE


def test_a_second_recording_at_another_commit_is_refused():
    existing = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())

    result = decide_recording(
        existing, honeypot_recordings.a_recording(commit="4567def"), honeypot_recordings.a_gate()
    )

    assert isinstance(result, RecordingRefused)
    assert any(honeypot_baselines.RECORDED_COMMIT in reason for reason in result.reasons)


def test_a_second_recording_at_other_conditions_is_refused():
    existing = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())

    result = decide_recording(
        existing, honeypot_recordings.a_recording(budget=7), honeypot_recordings.a_gate()
    )

    assert isinstance(result, RecordingRefused)
    assert any(
        "unconfirmed baseline" in reason and "reset the baseline under ADR 020" in reason
        for reason in result.reasons
    )
