import tests.unit.support.test_judge_recording_given as given
from evals.baseline import BaselineStatus, RecordingRef
from evals.gate import CellOutcome, Observation, ReplayRule
from evals.gate_verdict import GateMode, GateVerdict
from evals.judge_baseline import JudgeBaseline
from evals.judge_recording import decide_judge_recording, judge_rescore_refusals
from evals.recording import RecordingRefused
from mcp_auditor.domain.models import EvalVerdict

FAIL_ID, PASS_ID = given.FAIL_ID, given.PASS_ID
FAIL, PASS, UNCOVERED = Observation.FAIL, Observation.PASS, Observation.UNCOVERED
_NOT_MADE_AGAIN = "not made again against the same first recording (ADR 023)"


def test_a_first_recording_is_exploratory():
    result = decide_judge_recording(
        None, given.a_recording(), given.a_gate(mode=GateMode.FLOORS_ONLY)
    )

    assert isinstance(result, JudgeBaseline)
    assert result.status == BaselineStatus.EXPLORATORY
    assert result.replay_rule == ReplayRule()
    assert result.runs == given.correct_runs()
    assert result.protected.fail_stable_correct == 1
    assert result.protected.pass_stable_correct == 2


def test_a_second_recording_at_the_same_commit_confirms_with_the_runs_of_both():
    first = given.a_baseline(status=BaselineStatus.EXPLORATORY)
    second = given.runs_where(PASS_ID, PASS, FAIL, PASS)

    result = decide_judge_recording(first, given.a_recording(runs=second), given.a_gate())

    assert isinstance(result, JudgeBaseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.runs == first.runs + second
    assert result.confirms == RecordingRef(commit=first.commit, recorded_at=first.recorded_at)
    assert result.disagreements == [PASS_ID]
    assert result.protected.pass_stable_correct == 1


def test_a_second_recording_at_another_commit_is_refused():
    first = given.a_baseline(status=BaselineStatus.EXPLORATORY)

    result = decide_judge_recording(first, given.a_recording(commit="fedcba9"), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any("recorded at 0123abc, this run at fedcba9" in reason for reason in result.reasons)


def test_a_second_recording_at_other_conditions_is_refused():
    first = given.a_baseline(status=BaselineStatus.EXPLORATORY)

    result = decide_judge_recording(first, given.a_recording(runs_claimed=5), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert any("runs: baseline 3, candidate 5" in reason for reason in result.reasons)


def test_a_second_recording_breaching_a_floor_is_not_made_again():
    first = given.a_baseline(status=BaselineStatus.EXPLORATORY)

    result = decide_judge_recording(
        first, given.a_recording(), given.a_gate(floor_breaches=["recall"])
    )

    assert isinstance(result, RecordingRefused)
    assert "recall under its floor" in result.reasons
    assert any(_NOT_MADE_AGAIN in reason for reason in result.reasons)


def test_a_recording_with_an_uncovered_case_is_refused():
    runs = given.runs_where(PASS_ID, PASS, UNCOVERED, PASS)

    result = decide_judge_recording(None, given.a_recording(runs=runs), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert result.reasons == [
        f"a judge call failed on case {PASS_ID}: a baseline holds a verdict for every case in "
        "every run"
    ]


def test_a_recording_with_no_stable_and_correct_fail_case_is_refused():
    runs = given.runs_where(FAIL_ID, FAIL, PASS, FAIL)

    result = decide_judge_recording(None, given.a_recording(runs=runs), given.a_gate())

    assert isinstance(result, RecordingRefused)
    assert result.reasons == [
        "no FAIL case is stable and correct: the gate could not see a lost detection"
    ]


def test_recording_over_a_confirmed_baseline_under_a_green_gate_replaces_it():
    existing = given.a_baseline()

    result = decide_judge_recording(existing, given.a_recording(), given.a_gate())

    assert isinstance(result, JudgeBaseline)
    assert result.status == BaselineStatus.CONFIRMED
    assert result.replaces == RecordingRef(commit=existing.commit, recorded_at=existing.recorded_at)


def test_recording_over_a_confirmed_baseline_with_a_flip_not_reproduced_is_refused():
    gate = given.a_gate(pass_case_outcome=CellOutcome.FLIP_NOT_REPRODUCED)

    result = decide_judge_recording(given.a_baseline(), given.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert result.reasons == [f"gated case {PASS_ID} flipped in this run (flip_not_reproduced)"]


def test_recording_over_a_confirmed_baseline_with_a_declared_flip_replaces_it():
    gate = given.a_gate(pass_case_outcome=CellOutcome.DECLARED)

    result = decide_judge_recording(given.a_baseline(), given.a_recording(), gate)

    assert isinstance(result, JudgeBaseline)


def test_recording_over_a_confirmed_baseline_under_a_red_gate_is_refused():
    gate = given.a_gate(verdict=GateVerdict.RED)

    result = decide_judge_recording(given.a_baseline(), given.a_recording(), gate)

    assert isinstance(result, RecordingRefused)
    assert result.reasons == ["the gate is red"]


def test_a_relabel_keeping_both_sides_protected_is_not_refused():
    assert judge_rescore_refusals(given.a_baseline(), given.a_ground_truth()) == []


def test_a_relabel_leaving_no_stable_and_correct_fail_case_is_refused():
    relabeled = {**given.a_ground_truth(), FAIL_ID: EvalVerdict.PASS}

    refusals = judge_rescore_refusals(given.a_baseline(), relabeled)

    assert len(refusals) == 1
    assert refusals[0].startswith(
        "under the current labels the baseline holds no stable and correct FAIL case"
    )
