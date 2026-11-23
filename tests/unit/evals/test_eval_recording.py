import tests.unit.evals.support.honeypot_baselines as honeypot_baselines
import tests.unit.evals.support.honeypot_gate_inputs as honeypot_gate_inputs
import tests.unit.evals.support.honeypot_recordings as honeypot_recordings
from evals.baseline import Baseline, BaselineStatus, RecordingRef
from evals.gate import CellOutcome, Observation, ProtectedCells, RetestRule
from evals.gate_outcome import GateMode, GateOutcome
from evals.ground_truth import cell_key
from evals.recording import (
    GatedSetChange,
    RecordingRefused,
    decide_recording,
    gated_set_changes,
)

VULNERABLE_CELL = honeypot_gate_inputs.VULNERABLE_CELL
SAFE_CELL = honeypot_gate_inputs.SAFE_CELL
FAIL, PASS, UNCOVERED = Observation.FAIL, Observation.PASS, Observation.UNCOVERED


def test_a_first_recording_is_unconfirmed():
    result = decide_recording(
        None,
        honeypot_recordings.a_recording(),
        honeypot_recordings.a_gate(mode=GateMode.LEGACY_THRESHOLDS),
    )

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.UNCONFIRMED
    assert result.retest_rule == RetestRule()
    assert result.observation_runs() == honeypot_baselines.all_correct_runs()


def test_a_first_recording_missing_legacy_thresholds_with_floors_met_is_written():
    gate = honeypot_recordings.a_gate(outcome=GateOutcome.RED, mode=GateMode.LEGACY_THRESHOLDS)

    result = decide_recording(None, honeypot_recordings.a_recording(), gate)

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.UNCONFIRMED


def test_a_first_recording_breaching_a_floor_is_refused():
    gate = honeypot_recordings.a_gate(floor_breaches=["precision"], mode=GateMode.LEGACY_THRESHOLDS)

    result = decide_recording(None, honeypot_recordings.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert any("precision" in reason for reason in result.reasons)


def test_a_recording_with_no_stable_and_correct_fail_cell_is_refused():
    recording = honeypot_recordings.a_recording(
        runs=honeypot_baselines.runs_where_vulnerable_cell_is(PASS, PASS, PASS)
    )

    result = decide_recording(None, recording, honeypot_recordings.a_gate())

    assert isinstance(result, RecordingRefused)
    assert result.reasons == [
        "no planted FAIL cell is stable and correct: the gate could not see a lost detection"
    ]


def test_a_recording_with_no_stable_and_correct_pass_cell_is_refused():
    recording = honeypot_recordings.a_recording(
        runs=honeypot_recordings.runs_where_safe_cell_is(FAIL)
    )

    result = decide_recording(None, recording, honeypot_recordings.a_gate())

    assert isinstance(result, RecordingRefused)
    assert result.reasons == [
        "no PASS cell is stable and correct: the gate could not see a new false positive"
    ]


def test_a_recording_with_one_stable_and_correct_cell_on_each_side_is_written():
    result = decide_recording(None, honeypot_recordings.a_recording(), honeypot_recordings.a_gate())

    assert isinstance(result, Baseline)


def test_a_written_baseline_carries_the_recording_protected_cells():
    recording = honeypot_recordings.a_recording(
        runs=honeypot_recordings.four_cell_runs(vulnerable=(FAIL, PASS, FAIL)),
        ground_truth=honeypot_gate_inputs.a_ground_truth_with_two_cells_of_each_side(),
    )

    result = decide_recording(None, recording, honeypot_recordings.a_gate())

    assert isinstance(result, Baseline)
    assert result.protected == ProtectedCells(
        fail_stable_correct=1, fail_total=2, pass_stable_correct=2, pass_total=2, unstable=1
    )


def test_a_recording_with_a_failed_run_is_refused():
    result = decide_recording(
        None, honeypot_recordings.a_recording(completed_all=False), honeypot_recordings.a_gate()
    )

    assert isinstance(result, RecordingRefused)


def test_recording_over_a_confirmed_baseline_under_a_green_gate_replaces_it():
    rule = RetestRule(retests=7, required=5)
    existing = honeypot_baselines.a_baseline(status=BaselineStatus.CONFIRMED, retest_rule=rule)

    result = decide_recording(
        existing, honeypot_recordings.a_recording(commit="4567def"), honeypot_recordings.a_gate()
    )

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.replaces == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.retest_rule == rule


def test_recording_over_a_confirmed_baseline_under_a_green_gate_with_a_declared_flip_replaces_it():
    existing = honeypot_baselines.a_baseline(status=BaselineStatus.CONFIRMED)
    gate = honeypot_recordings.a_gate(vulnerable_cell_outcome=CellOutcome.DECLARED)

    result = decide_recording(existing, honeypot_recordings.a_recording(commit="4567def"), gate)

    assert isinstance(result, Baseline)
    assert result.replaces == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)


def test_recording_over_a_confirmed_baseline_with_a_gated_flip_not_reproduced_is_refused():
    existing = honeypot_baselines.a_baseline(status=BaselineStatus.CONFIRMED)
    gate = honeypot_recordings.a_gate(vulnerable_cell_outcome=CellOutcome.FLIP_NOT_REPRODUCED)

    result = decide_recording(existing, honeypot_recordings.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert any(cell_key(VULNERABLE_CELL) in reason for reason in result.reasons)


def test_recording_over_a_confirmed_baseline_under_a_red_gate_is_refused():
    existing = honeypot_baselines.a_baseline(status=BaselineStatus.CONFIRMED)

    result = decide_recording(
        existing, honeypot_recordings.a_recording(), honeypot_recordings.a_gate(GateOutcome.RED)
    )

    assert isinstance(result, RecordingRefused)


def test_recording_over_a_confirmed_baseline_at_other_conditions_points_at_the_reset_procedure():
    existing = honeypot_baselines.a_baseline(status=BaselineStatus.CONFIRMED)

    result = decide_recording(
        existing, honeypot_recordings.a_recording(budget=7), honeypot_recordings.a_gate()
    )

    assert isinstance(result, RecordingRefused)
    assert any(
        "confirmed baseline" in reason and "reset the baseline under ADR 020" in reason
        for reason in result.reasons
    )


def test_a_gated_cell_becoming_unstable_leaves_the_gated_set():
    old = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())
    new = honeypot_baselines.a_baseline(
        runs=honeypot_baselines.runs_where_vulnerable_cell_is(
            Observation.FAIL, Observation.UNCOVERED, Observation.FAIL
        )
    )

    changes = gated_set_changes(old, new, honeypot_gate_inputs.a_ground_truth())

    assert changes == GatedSetChange(entering=[], leaving=[cell_key(VULNERABLE_CELL)])


def test_a_stable_incorrect_cell_becoming_correct_enters_the_gated_set():
    old = honeypot_baselines.a_baseline(
        runs=honeypot_baselines.runs_where_vulnerable_cell_is(Observation.PASS, Observation.PASS)
    )
    new = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())

    changes = gated_set_changes(old, new, honeypot_gate_inputs.a_ground_truth())

    assert changes == GatedSetChange(entering=[cell_key(VULNERABLE_CELL)], leaving=[])


def test_with_no_previous_baseline_every_gated_cell_enters():
    new = honeypot_baselines.a_baseline(runs=honeypot_baselines.all_correct_runs())

    changes = gated_set_changes(None, new, honeypot_gate_inputs.a_ground_truth())

    assert changes == GatedSetChange(
        entering=sorted([cell_key(VULNERABLE_CELL), cell_key(SAFE_CELL)]), leaving=[]
    )
