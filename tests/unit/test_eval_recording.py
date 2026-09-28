import math

import tests.unit.support.test_eval_recording_given as given
from evals.baseline import Baseline, BaselineStatus, RecordingRef
from evals.gate import CellOutcome, Observation, ProtectedCells, ReplayRule, cell_key, compare
from evals.gate_verdict import GateMode, GateVerdict
from evals.recording import (
    GatedSetChange,
    RecordingRefused,
    decide_recording,
    gated_set_changes,
)

VULNERABLE_CELL = given.VULNERABLE_CELL
SAFE_CELL = given.SAFE_CELL
FAIL, PASS, UNCOVERED = Observation.FAIL, Observation.PASS, Observation.UNCOVERED
_NOT_MADE_AGAIN = "not made again against the same first recording (ADR 023)"


def test_a_first_recording_is_exploratory():
    result = decide_recording(
        None, given.a_recording(), given.a_gate(mode=GateMode.LEGACY_THRESHOLDS)
    )

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.EXPLORATORY
    assert result.replay_rule == ReplayRule()
    assert result.observation_runs() == given.all_correct_runs()


def test_a_first_recording_missing_legacy_thresholds_with_floors_met_is_written():
    gate = given.a_gate(verdict=GateVerdict.RED, mode=GateMode.LEGACY_THRESHOLDS)

    result = decide_recording(None, given.a_recording(), gate)

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.EXPLORATORY


def test_a_first_recording_breaching_a_floor_is_refused():
    gate = given.a_gate(floor_breaches=["precision"], mode=GateMode.LEGACY_THRESHOLDS)

    result = decide_recording(None, given.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert any("precision" in reason for reason in result.reasons)


def test_a_recording_with_no_stable_and_correct_fail_cell_is_refused():
    recording = given.a_recording(protected=given.no_stable_and_correct_fail_cell())

    result = decide_recording(None, recording, given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert result.reasons == [
        "no planted FAIL cell is stable and correct: the gate could not see a lost detection"
    ]


def test_a_recording_with_no_stable_and_correct_pass_cell_is_refused():
    recording = given.a_recording(protected=given.no_stable_and_correct_pass_cell())

    result = decide_recording(None, recording, given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert result.reasons == [
        "no PASS cell is stable and correct: the gate could not see a new false positive"
    ]


def test_a_recording_with_one_stable_and_correct_cell_on_each_side_is_written():
    recording = given.a_recording(protected=given.protected_on_both_sides())

    result = decide_recording(None, recording, given.a_gate())

    assert isinstance(result, Baseline)


def test_a_written_baseline_carries_the_recording_protected_cells():
    protected = given.protected_on_both_sides().model_copy(update={"unstable": 2})

    result = decide_recording(None, given.a_recording(protected=protected), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.protected == protected


def test_a_recording_with_a_failed_run_is_refused():
    result = decide_recording(None, given.a_recording(completed_all=False), given.a_gate())

    assert isinstance(result, RecordingRefused)


def test_a_second_recording_agreeing_on_stable_cells_confirms_the_first():
    existing = given.a_baseline(runs=given.all_correct_runs())
    recording = given.a_recording()

    result = decide_recording(existing, recording, given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.confirms == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.replaces is None
    assert result.observation_runs() == existing.observation_runs() + recording.runs
    assert result.disagreements == []


def test_a_second_recording_disagreeing_on_a_stable_cell_confirms_with_the_cell_unstable():
    ground_truth = given.a_ground_truth_with_two_cells_of_each_side()
    existing = given.a_baseline(runs=given.four_cell_runs(), ground_truth=ground_truth)
    varying = given.four_cell_runs(vulnerable=(FAIL, PASS, FAIL))
    recording = given.a_recording(runs=varying, ground_truth=ground_truth)

    result = decide_recording(existing, recording, given.a_gate())

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
    ground_truth = given.a_ground_truth_with_two_cells_of_each_side()
    first = given.four_cell_runs(vulnerable=(FAIL, UNCOVERED, FAIL))
    existing = given.a_baseline(runs=first, ground_truth=ground_truth)
    recording = given.a_recording(runs=given.four_cell_runs(), ground_truth=ground_truth)

    result = decide_recording(existing, recording, given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.observation_runs() == first + recording.runs
    assert result.disagreements == []
    assert result.protected is not None
    assert result.protected.unstable == 1
    changes = gated_set_changes(existing, result, ground_truth)
    assert cell_key(VULNERABLE_CELL) not in changes.entering + changes.leaving


def test_a_second_recording_seeing_uncovered_where_the_first_saw_fail_disagrees():
    ground_truth = given.a_ground_truth_with_two_cells_of_each_side()
    first = given.four_cell_runs(safe=(FAIL, FAIL, FAIL))
    existing = given.a_baseline(runs=first, ground_truth=ground_truth)
    uncovered = given.four_cell_runs(safe=(UNCOVERED, UNCOVERED, UNCOVERED))
    recording = given.a_recording(runs=uncovered, ground_truth=ground_truth)

    result = decide_recording(existing, recording, given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.disagreements == [cell_key(SAFE_CELL)]


def test_combined_runs_leaving_no_stable_and_correct_fail_cell_are_refused():
    existing = given.a_baseline(runs=given.all_correct_runs())
    missed = given.runs_where_vulnerable_cell_is(PASS, PASS, PASS)

    result = decide_recording(existing, given.a_recording(runs=missed), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any(
        "no planted FAIL cell" in reason and "over the runs of both recordings" in reason
        for reason in result.reasons
    )
    assert any(_NOT_MADE_AGAIN in reason for reason in result.reasons)


def test_combined_runs_leaving_no_stable_and_correct_pass_cell_are_refused():
    existing = given.a_baseline(runs=given.all_correct_runs())
    false_positives = given.runs_where_safe_cell_is(FAIL)

    result = decide_recording(existing, given.a_recording(runs=false_positives), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any(
        "no PASS cell" in reason and "over the runs of both recordings" in reason
        for reason in result.reasons
    )
    assert any(_NOT_MADE_AGAIN in reason for reason in result.reasons)


def test_a_second_recording_breaching_a_floor_is_not_made_again():
    existing = given.a_baseline(runs=given.all_correct_runs())
    gate = given.a_gate(floor_breaches=["precision"])

    result = decide_recording(existing, given.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert any("precision" in reason for reason in result.reasons)
    assert any(_NOT_MADE_AGAIN in reason for reason in result.reasons)


def test_a_second_recording_with_a_failed_run_can_be_made_again():
    existing = given.a_baseline(runs=given.all_correct_runs())

    result = decide_recording(existing, given.a_recording(completed_all=False), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert not any(_NOT_MADE_AGAIN in reason for reason in result.reasons)


def test_a_confirmed_baseline_averages_its_metrics_over_the_runs_of_both_recordings():
    ground_truth = given.a_ground_truth_with_two_cells_of_each_side()
    existing = given.a_baseline(runs=given.four_cell_runs(), ground_truth=ground_truth)
    one_run_half_wrong = given.four_cell_runs(
        vulnerable=(PASS, FAIL, FAIL), safe=(FAIL, PASS, PASS)
    )
    recording = given.a_recording(runs=one_run_half_wrong, ground_truth=ground_truth)

    result = decide_recording(existing, recording, given.a_gate())

    assert isinstance(result, Baseline)
    assert math.isclose(result.metrics.recall, 11 / 12)
    assert math.isclose(result.metrics.precision, 11 / 12)
    assert math.isclose(result.metrics.consistency, 11 / 12)
    assert math.isclose(
        result.metrics.distribution_coverage,
        (existing.metrics.distribution_coverage + recording.metrics.distribution_coverage) / 2,
    )


def test_a_confirmed_baseline_counts_the_protected_cells_of_the_combined_runs():
    ground_truth = given.a_ground_truth_with_two_cells_of_each_side()
    existing = given.a_baseline(runs=given.four_cell_runs(), ground_truth=ground_truth)
    varying = given.four_cell_runs(vulnerable=(FAIL, PASS, FAIL), safe=(PASS, PASS, UNCOVERED))
    recording = given.a_recording(runs=varying, ground_truth=ground_truth)

    result = decide_recording(existing, recording, given.a_gate())

    assert isinstance(result, Baseline)
    assert result.protected == ProtectedCells(
        fail_stable_correct=1, fail_total=2, pass_stable_correct=1, pass_total=2, unstable=2
    )


def test_a_candidate_compared_to_a_combined_baseline_flips_only_cells_stable_over_both():
    ground_truth = given.a_ground_truth_with_two_cells_of_each_side()
    existing = given.a_baseline(runs=given.four_cell_runs(), ground_truth=ground_truth)
    varying = given.four_cell_runs(vulnerable=(FAIL, PASS, FAIL))
    confirmed = decide_recording(
        existing, given.a_recording(runs=varying, ground_truth=ground_truth), given.a_gate()
    )
    assert isinstance(confirmed, Baseline)
    missing_both = [
        {**run, given.OTHER_VULNERABLE_CELL: PASS}
        for run in given.four_cell_runs(vulnerable=(PASS, PASS, PASS))
    ]

    cells = compare(confirmed.observation_runs(), missing_both, ground_truth)

    assert cells[given.OTHER_VULNERABLE_CELL].outcome == CellOutcome.FLIP
    assert cells[VULNERABLE_CELL].outcome == CellOutcome.INCONCLUSIVE


def test_a_second_recording_at_another_commit_is_refused():
    existing = given.a_baseline(runs=given.all_correct_runs())

    result = decide_recording(existing, given.a_recording(commit="4567def"), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any(given.RECORDED_COMMIT in reason for reason in result.reasons)


def test_a_second_recording_at_other_conditions_is_refused():
    existing = given.a_baseline(runs=given.all_correct_runs())

    result = decide_recording(existing, given.a_recording(budget=7), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any(
        "exploratory baseline" in reason and "reset the baseline under ADR 020" in reason
        for reason in result.reasons
    )


def test_recording_over_a_confirmed_baseline_under_a_green_gate_replaces_it():
    rule = ReplayRule(replays=7, required=5)
    existing = given.a_baseline(status=BaselineStatus.CONFIRMED, replay_rule=rule)

    result = decide_recording(existing, given.a_recording(commit="4567def"), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.replaces == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.replay_rule == rule


def test_recording_over_a_confirmed_baseline_under_a_green_gate_with_a_declared_flip_replaces_it():
    existing = given.a_baseline(status=BaselineStatus.CONFIRMED)
    gate = given.a_gate(vulnerable_cell_outcome=CellOutcome.DECLARED)

    result = decide_recording(existing, given.a_recording(commit="4567def"), gate)

    assert isinstance(result, Baseline)
    assert result.replaces == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)


def test_recording_over_a_confirmed_baseline_with_a_gated_flip_not_reproduced_is_refused():
    existing = given.a_baseline(status=BaselineStatus.CONFIRMED)
    gate = given.a_gate(vulnerable_cell_outcome=CellOutcome.FLIP_NOT_REPRODUCED)

    result = decide_recording(existing, given.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert any(cell_key(VULNERABLE_CELL) in reason for reason in result.reasons)


def test_recording_over_a_confirmed_baseline_under_a_red_gate_is_refused():
    existing = given.a_baseline(status=BaselineStatus.CONFIRMED)

    result = decide_recording(existing, given.a_recording(), given.a_gate(GateVerdict.RED))

    assert isinstance(result, RecordingRefused)


def test_recording_over_a_confirmed_baseline_at_other_conditions_points_at_the_reset_procedure():
    existing = given.a_baseline(status=BaselineStatus.CONFIRMED)

    result = decide_recording(existing, given.a_recording(budget=7), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any(
        "confirmed baseline" in reason and "reset the baseline under ADR 020" in reason
        for reason in result.reasons
    )


def test_a_gated_cell_becoming_unstable_leaves_the_gated_set():
    old = given.a_baseline(runs=given.all_correct_runs())
    new = given.a_baseline(
        runs=given.runs_where_vulnerable_cell_is(
            Observation.FAIL, Observation.UNCOVERED, Observation.FAIL
        )
    )

    changes = gated_set_changes(old, new, given.a_ground_truth())

    assert changes == GatedSetChange(entering=[], leaving=[cell_key(VULNERABLE_CELL)])


def test_a_stable_incorrect_cell_becoming_correct_enters_the_gated_set():
    old = given.a_baseline(
        runs=given.runs_where_vulnerable_cell_is(Observation.PASS, Observation.PASS)
    )
    new = given.a_baseline(runs=given.all_correct_runs())

    changes = gated_set_changes(old, new, given.a_ground_truth())

    assert changes == GatedSetChange(entering=[cell_key(VULNERABLE_CELL)], leaving=[])


def test_with_no_previous_baseline_every_gated_cell_enters():
    new = given.a_baseline(runs=given.all_correct_runs())

    changes = gated_set_changes(None, new, given.a_ground_truth())

    assert changes == GatedSetChange(
        entering=sorted([cell_key(VULNERABLE_CELL), cell_key(SAFE_CELL)]), leaving=[]
    )
