import pytest
from pydantic import ValidationError

import tests.unit.evals.support.honeypot_gate_inputs as honeypot_gate_inputs
import tests.unit.evals.support.test_eval_gate_given as given
from evals.gate import (
    CellComparison,
    CellOutcome,
    CellState,
    FlipCause,
    Observation,
    ProtectedCells,
    RetestRule,
    apply_retests,
    classify,
    compare,
    observe,
    protected_cells,
)
from evals.ground_truth import cell_key, parse_cell_key
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

FAIL = Observation.FAIL
PASS = Observation.PASS
UNCOVERED = Observation.UNCOVERED
VULNERABLE_CELL = honeypot_gate_inputs.VULNERABLE_CELL
SAFE_CELL = honeypot_gate_inputs.SAFE_CELL


def test_cell_key_round_trips():
    key = cell_key(VULNERABLE_CELL)

    assert key == "get_user/input_validation"
    assert parse_cell_key(key) == VULNERABLE_CELL


def test_a_verdict_is_observed_as_itself_and_no_verdict_as_uncovered():
    assert Observation.of(EvalVerdict.FAIL) == FAIL
    assert Observation.of(EvalVerdict.PASS) == PASS
    assert Observation.of(None) == UNCOVERED


def test_an_observation_reads_back_as_its_verdict_and_uncovered_as_none():
    assert FAIL.verdict == EvalVerdict.FAIL
    assert PASS.verdict == EvalVerdict.PASS
    assert UNCOVERED.verdict is None


def test_observe_reads_each_ground_truth_cell_from_the_verdicts():
    verdicts: VerdictMap = {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.PASS}

    observations = observe(verdicts, honeypot_gate_inputs.a_ground_truth())

    assert observations == {VULNERABLE_CELL: FAIL, SAFE_CELL: PASS}


def test_observe_marks_a_missing_cell_uncovered():
    observations = observe({}, honeypot_gate_inputs.a_ground_truth())

    assert observations == {VULNERABLE_CELL: UNCOVERED, SAFE_CELL: UNCOVERED}


def test_observe_marks_a_cell_without_verdict_uncovered():
    verdicts: VerdictMap = {VULNERABLE_CELL: None}

    observations = observe(verdicts, honeypot_gate_inputs.a_ground_truth())

    assert observations[VULNERABLE_CELL] == UNCOVERED


def test_observe_ignores_verdicts_outside_the_ground_truth():
    verdicts: VerdictMap = {("other_tool", AuditCategory.INJECTION): EvalVerdict.FAIL}

    observations = observe(verdicts, honeypot_gate_inputs.a_ground_truth())

    assert set(observations) == {VULNERABLE_CELL, SAFE_CELL}


@pytest.mark.parametrize(
    ("observations", "expected"),
    [
        ([FAIL, FAIL, FAIL], CellState.STABLE_CORRECT),
        ([PASS, PASS, PASS], CellState.STABLE_INCORRECT),
        ([FAIL, PASS, FAIL], CellState.UNSTABLE),
        ([FAIL, UNCOVERED, FAIL], CellState.UNSTABLE),
    ],
    ids=["correct-in-all", "same-wrong-in-all", "mixed", "uncovered-once"],
)
def test_classify(observations: list[Observation], expected: CellState):
    runs = given.runs_observing(VULNERABLE_CELL, observations)

    states = classify(runs, honeypot_gate_inputs.a_ground_truth())

    assert states[VULNERABLE_CELL] == expected


def test_classify_reads_uncovered_in_every_run_as_stable_incorrect():
    runs = given.runs_observing(VULNERABLE_CELL, [UNCOVERED, UNCOVERED, UNCOVERED])

    states = classify(runs, honeypot_gate_inputs.a_ground_truth())

    assert states[VULNERABLE_CELL] == CellState.STABLE_INCORRECT


def test_classify_leaves_out_a_cell_a_run_did_not_record():
    runs = given.runs_observing(VULNERABLE_CELL, [FAIL, FAIL, FAIL])

    states = classify(runs, honeypot_gate_inputs.a_ground_truth())

    assert SAFE_CELL not in states


def test_protected_cells_count_the_stable_and_correct_cells_on_each_side():
    runs = given.runs_on_two_cells_of_each_side()

    protected = protected_cells(
        runs, honeypot_gate_inputs.a_ground_truth_with_two_cells_of_each_side()
    )

    assert protected == ProtectedCells(
        fail_stable_correct=1, fail_total=2, pass_stable_correct=1, pass_total=2, unstable=1
    )


@pytest.mark.parametrize(
    ("baseline", "candidate", "expected"),
    [
        (
            [FAIL, FAIL, FAIL],
            [FAIL, FAIL, FAIL],
            CellComparison(outcome=CellOutcome.UNCHANGED, cause=None),
        ),
        (
            [FAIL, FAIL, FAIL],
            [FAIL, PASS, FAIL],
            CellComparison(outcome=CellOutcome.FLIP, cause=FlipCause.WRONG_VERDICT),
        ),
        (
            [FAIL, FAIL, FAIL],
            [FAIL, PASS, UNCOVERED],
            CellComparison(outcome=CellOutcome.FLIP, cause=FlipCause.UNCOVERED),
        ),
        (
            [PASS, PASS, PASS],
            [FAIL, FAIL, FAIL],
            CellComparison(outcome=CellOutcome.IMPROVED, cause=None),
        ),
        (
            [PASS, PASS, PASS],
            [PASS, FAIL, PASS],
            CellComparison(outcome=CellOutcome.UNCHANGED, cause=None),
        ),
        (
            [FAIL, PASS, FAIL],
            [FAIL, FAIL, FAIL],
            CellComparison(outcome=CellOutcome.UNCHANGED, cause=None),
        ),
        (
            [FAIL, PASS, FAIL],
            [FAIL, FAIL, PASS],
            CellComparison(outcome=CellOutcome.INCONCLUSIVE, cause=None),
        ),
    ],
    ids=[
        "stable-correct-stays-correct",
        "flip-wrong-verdict",
        "flip-uncovered",
        "stable-incorrect-becomes-correct",
        "stable-incorrect-stays-wrong",
        "unstable-becomes-correct",
        "unstable-stays-not-always-correct",
    ],
)
def test_compare(
    baseline: list[Observation], candidate: list[Observation], expected: CellComparison
):
    comparisons = compare(
        given.runs_observing(VULNERABLE_CELL, baseline),
        given.runs_observing(VULNERABLE_CELL, candidate),
        honeypot_gate_inputs.a_ground_truth(),
    )

    assert comparisons[VULNERABLE_CELL] == expected


def test_compare_marks_a_cell_the_baseline_did_not_record():
    comparisons = compare(
        given.runs_observing(VULNERABLE_CELL, [FAIL, FAIL, FAIL]),
        [{VULNERABLE_CELL: FAIL, SAFE_CELL: PASS} for _ in range(3)],
        honeypot_gate_inputs.a_ground_truth(),
    )

    assert comparisons[SAFE_CELL] == CellComparison(outcome=CellOutcome.NOT_RECORDED)


@pytest.mark.parametrize(
    ("reproduced", "cleared", "expected"),
    [(4, 0, True), (4, 1, True), (0, 2, False), (3, 2, False), (3, 1, None), (0, 1, None)],
)
def test_retest_rule_decides_four_of_five(reproduced: int, cleared: int, expected: bool | None):
    assert RetestRule().decide(reproduced, cleared) is expected


@pytest.mark.parametrize(
    ("retests", "expected"),
    [([True] * 4, True), ([False] * 2, False), ([True] * 3 + [False], None)],
)
def test_retest_rule_decides_a_sequence_of_retests(retests: list[bool], expected: bool | None):
    assert RetestRule().decide_retests(retests) is expected


@pytest.mark.parametrize(("retests", "required"), [(5, 6), (5, 0), (0, 0)])
def test_a_retest_rule_that_could_never_decide_is_rejected(retests: int, required: int):
    with pytest.raises(ValidationError):
        RetestRule(retests=retests, required=required)


def test_applying_retests_turns_a_reproduced_flip_into_a_regression():
    flip = CellComparison(outcome=CellOutcome.FLIP, cause=FlipCause.WRONG_VERDICT)

    retested = apply_retests(flip, [True] * 4, RetestRule())

    assert retested == CellComparison(
        outcome=CellOutcome.REGRESSION, cause=FlipCause.WRONG_VERDICT, retests=[True] * 4
    )


def test_applying_retests_turns_a_cleared_flip_into_not_reproduced():
    flip = CellComparison(outcome=CellOutcome.FLIP, cause=FlipCause.UNCOVERED)

    retested = apply_retests(flip, [False, False], RetestRule())

    assert retested == CellComparison(
        outcome=CellOutcome.FLIP_NOT_REPRODUCED,
        cause=FlipCause.UNCOVERED,
        retests=[False, False],
    )
