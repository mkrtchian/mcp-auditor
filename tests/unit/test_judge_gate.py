import tests.unit.support.test_judge_gate_given as given
from evals.baseline import BaselineStatus
from evals.gate import CellOutcome, Observation
from evals.gate_verdict import GateMode, GateVerdict
from evals.judge_gate import (
    JudgeGateInput,
    judge_case_gate,
    judge_ci_condition_mismatches,
    judge_floor_breaches,
    observe_case,
)
from mcp_auditor.domain.models import EvalVerdict

FAIL_ID, PASS_ID = given.FAIL_ID, given.PASS_ID
FAIL, PASS, UNCOVERED = Observation.FAIL, Observation.PASS, Observation.UNCOVERED


def test_a_verdict_is_observed_as_itself_and_a_raised_call_as_uncovered():
    assert observe_case(EvalVerdict.FAIL) == FAIL
    assert observe_case(EvalVerdict.PASS) == PASS
    assert observe_case(None) == UNCOVERED


def test_conditions_at_the_ci_defaults_do_not_mismatch():
    assert judge_ci_condition_mismatches(given.conditions()) == []


def test_runs_off_the_ci_default_name_the_field():
    mismatches = judge_ci_condition_mismatches(given.conditions(runs=5))

    assert mismatches == ["runs: CI runs 3, this run 5"]


def test_correct_runs_breach_no_floor():
    assert judge_floor_breaches(given.correct_runs(), given.a_ground_truth()) == []


def test_runs_with_no_detection_breach_the_recall_floor():
    runs = given.runs_where(FAIL_ID, PASS, PASS, PASS)

    assert judge_floor_breaches(runs, given.a_ground_truth()) == ["recall"]


def test_a_judge_failing_every_case_breaches_the_precision_floor_when_fail_cases_are_a_minority():
    breaches = judge_floor_breaches(given.runs_failing_every_case(), given.a_ground_truth())

    assert breaches == ["precision"]


def test_a_floor_breach_is_red_with_no_baseline():
    result = judge_case_gate(
        JudgeGateInput(
            mode=GateMode.FLOORS_ONLY,
            runs=given.runs_where(FAIL_ID, PASS, PASS, PASS),
            ground_truth=given.a_ground_truth(),
        )
    )

    assert result.verdict == GateVerdict.RED
    assert result.floor_breaches == ["recall"]
    assert result.reasons == ["recall: 0 detection(s) over 3 runs, under one per run"]
    assert result.cases == {}


def test_the_precision_breach_reason_gives_the_measured_precision():
    result = judge_case_gate(
        JudgeGateInput(
            mode=GateMode.FLOORS_ONLY,
            runs=given.runs_failing_every_case(),
            ground_truth=given.a_ground_truth(),
        )
    )

    assert result.reasons == ["precision 0.33 under its floor 0.50"]


def test_a_flip_that_reproduces_four_times_out_of_five_is_a_regression_and_red():
    result = judge_case_gate(
        given.a_paired_input(
            runs=given.runs_where(PASS_ID, PASS, FAIL, PASS),
            replays={PASS_ID: [True, False, True, True, True]},
        )
    )

    assert result.cases[PASS_ID].outcome == CellOutcome.REGRESSION
    assert result.verdict == GateVerdict.RED
    assert result.reasons == [f"regression on case {PASS_ID}"]


def test_a_flip_that_does_not_reproduce_is_green():
    result = judge_case_gate(
        given.a_paired_input(
            runs=given.runs_where(PASS_ID, PASS, FAIL, PASS), replays={PASS_ID: [False, False]}
        )
    )

    assert result.cases[PASS_ID].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert result.verdict == GateVerdict.GREEN


def test_a_declared_flip_is_declared_and_green():
    result = judge_case_gate(
        given.a_paired_input(
            runs=given.runs_where(PASS_ID, PASS, FAIL, PASS), declared=frozenset({PASS_ID})
        )
    )

    assert result.cases[PASS_ID].outcome == CellOutcome.DECLARED
    assert result.verdict == GateVerdict.GREEN
    assert result.declared_held == []


def test_a_declared_case_that_holds_is_named():
    result = judge_case_gate(
        given.a_paired_input(runs=given.correct_runs(), declared=frozenset({PASS_ID}))
    )

    assert result.declared_held == [PASS_ID]


def test_a_mismatch_is_not_comparable():
    result = judge_case_gate(
        given.a_paired_input(
            runs=given.correct_runs(), mismatches=["runs: baseline 3, candidate 5"]
        )
    )

    assert result.verdict == GateVerdict.NOT_COMPARABLE
    assert result.reasons == ["runs: baseline 3, candidate 5"]


def test_a_flip_under_an_exploratory_baseline_is_not_red():
    result = judge_case_gate(
        JudgeGateInput(
            mode=GateMode.FLOORS_ONLY,
            runs=given.runs_where(PASS_ID, PASS, FAIL, PASS),
            ground_truth=given.a_ground_truth(),
            baseline=given.a_baseline(status=BaselineStatus.EXPLORATORY),
        )
    )

    assert result.cases[PASS_ID].outcome == CellOutcome.FLIP
    assert result.verdict == GateVerdict.GREEN
    assert result.baseline_status == BaselineStatus.EXPLORATORY


def test_an_unspecified_case_is_outside_the_comparison():
    result = judge_case_gate(
        given.a_paired_input(runs=given.runs_where(given.UNSPECIFIED_ID, FAIL, FAIL, FAIL))
    )

    assert given.UNSPECIFIED_ID not in result.cases
    assert result.verdict == GateVerdict.GREEN


def test_the_protected_cases_are_the_baseline_ones():
    result = judge_case_gate(given.a_paired_input(runs=given.correct_runs()))

    assert result.protected == given.a_baseline().protected
