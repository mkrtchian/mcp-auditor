import math

import pytest
from pydantic import ValidationError

import tests.unit.support.test_eval_gate_given as given
from evals.gate import (
    FLOORS,
    CellComparison,
    CellOutcome,
    CellState,
    FlipCause,
    Observation,
    ReplayRule,
    cell_key,
    classify,
    compare,
    floor_breaches,
    metric_deltas,
    metric_resolutions,
    observe,
    parse_cell_key,
    settle,
)
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

FAIL = Observation.FAIL
PASS = Observation.PASS
UNCOVERED = Observation.UNCOVERED
VULNERABLE_CELL = given.VULNERABLE_CELL
SAFE_CELL = given.SAFE_CELL


def test_cell_key_round_trips():
    key = cell_key(VULNERABLE_CELL)

    assert key == "get_user/input_validation"
    assert parse_cell_key(key) == VULNERABLE_CELL


def test_observe_reads_each_ground_truth_cell_from_the_verdicts():
    verdicts: VerdictMap = {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.PASS}

    observations = observe(verdicts, given.a_ground_truth())

    assert observations == {VULNERABLE_CELL: FAIL, SAFE_CELL: PASS}


def test_observe_marks_a_missing_cell_uncovered():
    observations = observe({}, given.a_ground_truth())

    assert observations == {VULNERABLE_CELL: UNCOVERED, SAFE_CELL: UNCOVERED}


def test_observe_marks_a_cell_without_verdict_uncovered():
    verdicts: VerdictMap = {VULNERABLE_CELL: None}

    observations = observe(verdicts, given.a_ground_truth())

    assert observations[VULNERABLE_CELL] == UNCOVERED


def test_observe_ignores_verdicts_outside_the_ground_truth():
    verdicts: VerdictMap = {("other_tool", AuditCategory.INJECTION): EvalVerdict.FAIL}

    observations = observe(verdicts, given.a_ground_truth())

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

    states = classify(runs, given.a_ground_truth())

    assert states[VULNERABLE_CELL] == expected


def test_classify_reads_uncovered_in_every_run_as_stable_incorrect():
    runs = given.runs_observing(VULNERABLE_CELL, [UNCOVERED, UNCOVERED, UNCOVERED])

    states = classify(runs, given.a_ground_truth())

    assert states[VULNERABLE_CELL] == CellState.STABLE_INCORRECT


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
        given.a_ground_truth(),
    )

    assert comparisons[VULNERABLE_CELL] == expected


@pytest.mark.parametrize(
    ("reproduced", "cleared", "expected"),
    [(4, 0, True), (4, 1, True), (0, 2, False), (3, 2, False), (3, 1, None), (0, 1, None)],
)
def test_replay_rule_decides_four_of_five(reproduced: int, cleared: int, expected: bool | None):
    assert ReplayRule().decide(reproduced, cleared) is expected


@pytest.mark.parametrize(("replays", "required"), [(5, 6), (5, 0), (0, 0)])
def test_a_replay_rule_that_could_never_decide_is_rejected(replays: int, required: int):
    with pytest.raises(ValidationError):
        ReplayRule(replays=replays, required=required)


@pytest.mark.parametrize(("replays", "required"), [(5, 5), (5, 1)])
def test_a_replay_rule_within_its_bounds_is_accepted(replays: int, required: int):
    assert ReplayRule(replays=replays, required=required).required == required


def test_settle_turns_a_reproduced_flip_into_a_regression():
    flip = CellComparison(outcome=CellOutcome.FLIP, cause=FlipCause.WRONG_VERDICT)

    settled = settle(flip, [True] * 4, ReplayRule())

    assert settled == CellComparison(
        outcome=CellOutcome.REGRESSION, cause=FlipCause.WRONG_VERDICT, replays=[True] * 4
    )


def test_settle_turns_a_cleared_flip_into_not_reproduced():
    flip = CellComparison(outcome=CellOutcome.FLIP, cause=FlipCause.UNCOVERED)

    settled = settle(flip, [False, False], ReplayRule())

    assert settled == CellComparison(
        outcome=CellOutcome.FLIP_NOT_REPRODUCED,
        cause=FlipCause.UNCOVERED,
        replays=[False, False],
    )


@pytest.mark.parametrize("metric", sorted(FLOORS))
def test_floor_breach_names_the_metric(metric: str):
    metrics = given.metrics(**{metric: 0.49})

    assert floor_breaches(metrics) == [metric]


def test_no_floor_breach_when_every_metric_clears_its_floor():
    assert floor_breaches(given.metrics()) == []


def test_consistency_has_no_floor():
    assert floor_breaches(given.metrics(consistency=0.1)) == []


def test_recall_delta_smaller_than_one_case_is_inconclusive():
    resolutions = metric_resolutions(
        given.runs_failing(VULNERABLE_CELL, runs=3), given.a_ground_truth(), 1
    )

    deltas = metric_deltas(given.metrics(recall=0.9), given.metrics(recall=0.8), resolutions)

    assert math.isclose(resolutions["recall"], 1 / 3)
    assert math.isclose(deltas["recall"].value, -0.1)
    assert deltas["recall"].inconclusive


def test_recall_delta_larger_than_one_case_is_conclusive():
    resolutions = metric_resolutions(
        given.runs_failing(VULNERABLE_CELL, runs=3), given.a_ground_truth(), 1
    )

    deltas = metric_deltas(given.metrics(recall=0.9), given.metrics(recall=0.5), resolutions)

    assert not deltas["recall"].inconclusive


def test_deltas_cover_the_gated_metrics_only():
    resolutions = metric_resolutions(
        given.runs_failing(VULNERABLE_CELL, runs=3), given.a_ground_truth(), 1
    )

    deltas = metric_deltas(given.metrics(), given.metrics(), resolutions)

    assert set(deltas) == set(FLOORS)


def test_precision_resolution_counts_a_fail_outside_the_ground_truth():
    outside = ("other_tool", AuditCategory.INJECTION)
    maps: list[VerdictMap] = [
        {VULNERABLE_CELL: EvalVerdict.FAIL, outside: EvalVerdict.FAIL},
        {VULNERABLE_CELL: EvalVerdict.FAIL, outside: EvalVerdict.FAIL},
    ]

    resolutions = metric_resolutions(maps, given.a_ground_truth(), 1)

    assert math.isclose(resolutions["precision"], 1 / (2 * 2))


def test_precision_resolution_without_predicted_fail_is_one():
    maps: list[VerdictMap] = [{SAFE_CELL: EvalVerdict.PASS}]

    resolutions = metric_resolutions(maps, given.a_ground_truth(), 1)

    assert resolutions["precision"] == 1.0


def test_distribution_coverage_resolution_is_one_category_of_one_tool_in_one_run():
    resolutions = metric_resolutions(
        given.runs_failing(VULNERABLE_CELL, runs=3), given.a_ground_truth(), 2
    )

    assert math.isclose(resolutions["distribution_coverage"], 1 / (2 * len(AuditCategory) * 3))
