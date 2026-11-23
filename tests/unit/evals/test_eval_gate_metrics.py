import math

import pytest

import tests.unit.evals.support.honeypot_gate_inputs as honeypot_gate_inputs
import tests.unit.evals.support.test_eval_gate_metrics_given as given
from evals.gate import Observation
from evals.gate_metrics import (
    FLOORS,
    count_detections,
    floor_breaches,
    metric_deltas,
    metric_resolutions,
    recall_floor_breached,
)
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

FAIL = Observation.FAIL
PASS = Observation.PASS
VULNERABLE_CELL = honeypot_gate_inputs.VULNERABLE_CELL
SAFE_CELL = honeypot_gate_inputs.SAFE_CELL


def test_one_detection_per_run_clears_the_recall_floor():
    assert not recall_floor_breached(honeypot_gate_inputs.detections(3, runs=3))


def test_fewer_detections_than_runs_breaches_the_recall_floor():
    assert recall_floor_breached(honeypot_gate_inputs.detections(2, runs=3))


def test_a_recall_floor_breach_is_named_from_the_detection_count():
    assert floor_breaches(
        honeypot_gate_inputs.metrics(recall=0.9), honeypot_gate_inputs.detections(2, runs=3)
    ) == ["recall"]


@pytest.mark.parametrize("metric", sorted(FLOORS))
def test_floor_breach_names_the_metric(metric: str):
    metrics = honeypot_gate_inputs.metrics(**{metric: 0.49})

    assert floor_breaches(metrics, honeypot_gate_inputs.detections(3, runs=3)) == [metric]


def test_no_floor_breach_when_every_metric_clears_its_floor():
    assert (
        floor_breaches(honeypot_gate_inputs.metrics(), honeypot_gate_inputs.detections(3, runs=3))
        == []
    )


def test_consistency_has_no_floor():
    assert (
        floor_breaches(
            honeypot_gate_inputs.metrics(consistency=0.1),
            honeypot_gate_inputs.detections(3, runs=3),
        )
        == []
    )


def test_detections_count_the_planted_cells_observed_fail_over_the_runs():
    runs = [
        {VULNERABLE_CELL: FAIL, SAFE_CELL: FAIL},
        {VULNERABLE_CELL: PASS, SAFE_CELL: FAIL},
        {VULNERABLE_CELL: FAIL, SAFE_CELL: PASS},
    ]

    count = count_detections(runs, honeypot_gate_inputs.a_ground_truth())

    assert (count.detections, count.runs, count.planted) == (2, 3, 1)


def test_recall_delta_smaller_than_one_case_is_inconclusive():
    resolutions = metric_resolutions(
        given.runs_failing(VULNERABLE_CELL, runs=3), honeypot_gate_inputs.a_ground_truth(), 1
    )

    deltas = metric_deltas(
        honeypot_gate_inputs.metrics(recall=0.9),
        honeypot_gate_inputs.metrics(recall=0.8),
        resolutions,
    )

    assert math.isclose(resolutions["recall"], 1 / 3)
    assert math.isclose(deltas["recall"].value, -0.1)
    assert deltas["recall"].inconclusive


def test_recall_delta_larger_than_one_case_is_conclusive():
    resolutions = metric_resolutions(
        given.runs_failing(VULNERABLE_CELL, runs=3), honeypot_gate_inputs.a_ground_truth(), 1
    )

    deltas = metric_deltas(
        honeypot_gate_inputs.metrics(recall=0.9),
        honeypot_gate_inputs.metrics(recall=0.5),
        resolutions,
    )

    assert not deltas["recall"].inconclusive


def test_a_delta_of_exactly_one_case_is_conclusive():
    resolutions = {"recall": 1 / 33, "precision": 1.0, "distribution_coverage": 1.0}

    deltas = metric_deltas(
        honeypot_gate_inputs.metrics(recall=32 / 33),
        honeypot_gate_inputs.metrics(recall=31 / 33),
        resolutions,
    )

    assert not deltas["recall"].inconclusive


def test_a_delta_of_half_a_case_is_inconclusive():
    resolutions = {"recall": 1 / 33, "precision": 1.0, "distribution_coverage": 1.0}

    deltas = metric_deltas(
        honeypot_gate_inputs.metrics(recall=32 / 33),
        honeypot_gate_inputs.metrics(recall=31.5 / 33),
        resolutions,
    )

    assert deltas["recall"].inconclusive


def test_deltas_cover_the_gated_metrics_only():
    resolutions = metric_resolutions(
        given.runs_failing(VULNERABLE_CELL, runs=3), honeypot_gate_inputs.a_ground_truth(), 1
    )

    deltas = metric_deltas(
        honeypot_gate_inputs.metrics(), honeypot_gate_inputs.metrics(), resolutions
    )

    assert set(deltas) == {"recall", "precision", "distribution_coverage"}


def test_precision_resolution_ignores_a_fail_outside_the_ground_truth():
    outside = ("other_tool", AuditCategory.INJECTION)
    maps: list[VerdictMap] = [
        {VULNERABLE_CELL: EvalVerdict.FAIL, outside: EvalVerdict.FAIL},
        {VULNERABLE_CELL: EvalVerdict.FAIL, outside: EvalVerdict.FAIL},
    ]

    resolutions = metric_resolutions(maps, honeypot_gate_inputs.a_ground_truth(), 1)

    assert math.isclose(resolutions["precision"], 1 / (2 * 1))


def test_precision_resolution_is_the_largest_single_case_move_across_runs():
    maps = [given.a_run_failing(fails=1), given.a_run_failing(fails=9)]

    resolutions = metric_resolutions(maps, given.a_ground_truth_failing(33), 1)

    assert math.isclose(resolutions["precision"], 1 / (2 * 1))


def test_precision_resolution_counts_a_run_without_predicted_fail():
    maps = [
        given.a_run_failing(fails=0),
        given.a_run_failing(fails=33),
        given.a_run_failing(fails=33),
    ]

    resolutions = metric_resolutions(maps, given.a_ground_truth_failing(33), 1)

    assert math.isclose(resolutions["precision"], 1 / 3)


def test_precision_resolution_without_predicted_fail_is_one_case_per_run():
    maps = [given.a_run_failing(fails=0), given.a_run_failing(fails=0)]

    resolutions = metric_resolutions(maps, given.a_ground_truth_failing(33), 1)

    assert math.isclose(resolutions["precision"], 1 / 2)


def test_distribution_coverage_resolution_is_one_category_of_one_tool_in_one_run():
    resolutions = metric_resolutions(
        given.runs_failing(VULNERABLE_CELL, runs=3), honeypot_gate_inputs.a_ground_truth(), 2
    )

    assert math.isclose(resolutions["distribution_coverage"], 1 / (2 * len(AuditCategory) * 3))
