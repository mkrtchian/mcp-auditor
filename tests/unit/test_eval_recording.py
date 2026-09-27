import tests.unit.support.test_eval_recording_given as given
from evals.baseline import Baseline, BaselineStatus, RecordingRef
from evals.gate import CellOutcome, Observation, ReplayRule, cell_key
from evals.gate_verdict import GateMode, GateVerdict
from evals.recording import (
    GatedSetChange,
    RecordingRefused,
    decide_recording,
    gated_set_changes,
)

VULNERABLE_CELL = given.VULNERABLE_CELL
SAFE_CELL = given.SAFE_CELL


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

    result = decide_recording(existing, given.a_recording(), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.confirms == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.replaces is None


def test_a_second_recording_disagreeing_on_a_stable_cell_stays_exploratory():
    existing = given.a_baseline(runs=given.all_correct_runs())
    unstable = given.runs_where_vulnerable_cell_is(
        Observation.FAIL, Observation.PASS, Observation.FAIL
    )

    result = decide_recording(existing, given.a_recording(runs=unstable), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.EXPLORATORY
    assert result.replaces == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)
    assert result.disagreements == [cell_key(VULNERABLE_CELL)]


def test_a_cell_unstable_in_the_exploratory_baseline_is_no_disagreement():
    existing = given.a_baseline(
        runs=given.runs_where_vulnerable_cell_is(
            Observation.FAIL, Observation.UNCOVERED, Observation.FAIL
        )
    )

    result = decide_recording(existing, given.a_recording(), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.disagreements == []


def test_a_second_recording_seeing_uncovered_where_the_first_saw_fail_disagrees():
    existing = given.a_baseline(runs=given.runs_where_safe_cell_is(Observation.FAIL))
    uncovered = given.runs_where_safe_cell_is(Observation.UNCOVERED)

    result = decide_recording(existing, given.a_recording(runs=uncovered), given.a_gate())

    assert isinstance(result, Baseline)
    assert result.status == BaselineStatus.EXPLORATORY
    assert result.disagreements == [cell_key(SAFE_CELL)]


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
