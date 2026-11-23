import pytest

import tests.unit.evals.support.honeypot_gate_inputs as honeypot_gate_inputs
import tests.unit.evals.support.test_eval_gate_outcome_given as given
from evals.gate import CellOutcome
from evals.gate_metrics import LEGACY_THRESHOLDS
from evals.gate_outcome import GateMode, GateOutcome, decide_gate


@pytest.mark.parametrize("metric", sorted(LEGACY_THRESHOLDS))
def test_legacy_mode_is_red_on_a_missed_legacy_threshold(metric: str):
    missed = honeypot_gate_inputs.metrics(**{metric: LEGACY_THRESHOLDS[metric] - 0.01})

    result = decide_gate(given.a_gate_input(GateMode.LEGACY_THRESHOLDS, metrics=missed))

    assert result.outcome == GateOutcome.RED
    assert any(metric in reason for reason in result.reasons)


def test_legacy_mode_is_green_when_every_threshold_is_met():
    result = decide_gate(given.a_gate_input(GateMode.LEGACY_THRESHOLDS))

    assert result.outcome == GateOutcome.GREEN
    assert result.reasons == []


def test_legacy_mode_reports_floor_breaches():
    detections = honeypot_gate_inputs.detections(2, runs=3)

    result = decide_gate(given.a_gate_input(GateMode.LEGACY_THRESHOLDS, detections=detections))

    assert result.floor_breaches == ["recall"]


def test_a_recall_breach_reads_as_detections_under_one_per_run():
    detections = honeypot_gate_inputs.detections(2, runs=3)

    result = decide_gate(given.a_gate_input(GateMode.FLOORS_ONLY, detections=detections))

    assert result.outcome == GateOutcome.RED
    assert result.reasons == ["recall: 2 detection(s) over 3 runs, under one per run"]


def test_the_recall_floor_reads_as_one_planted_flaw_in_the_floors():
    result = decide_gate(given.a_gate_input(GateMode.PAIRED))

    assert result.floors == {"recall": 1 / 8, "precision": 0.50, "distribution_coverage": 0.50}


def test_floors_only_mode_ignores_a_regression_cell():
    cells = given.cells_with(CellOutcome.REGRESSION)

    result = decide_gate(given.a_gate_input(GateMode.FLOORS_ONLY, cells=cells))

    assert result.outcome == GateOutcome.GREEN


def test_floors_only_mode_is_red_on_a_floor_breach():
    metrics = honeypot_gate_inputs.metrics(distribution_coverage=0.4)

    result = decide_gate(given.a_gate_input(GateMode.FLOORS_ONLY, metrics=metrics))

    assert result.outcome == GateOutcome.RED


def test_paired_mode_is_red_on_a_regression():
    cells = given.cells_with(CellOutcome.UNCHANGED, CellOutcome.REGRESSION)

    result = decide_gate(given.a_gate_input(GateMode.PAIRED, cells=cells))

    assert result.outcome == GateOutcome.RED
    assert any("tool_1/input_validation" in reason for reason in result.reasons)


def test_paired_mode_is_red_on_a_floor_breach():
    metrics = honeypot_gate_inputs.metrics(precision=0.3)

    result = decide_gate(given.a_gate_input(GateMode.PAIRED, metrics=metrics))

    assert result.outcome == GateOutcome.RED
    assert any("precision" in reason for reason in result.reasons)


def test_paired_mode_is_green_with_only_unreproduced_and_inconclusive_flips():
    cells = given.cells_with(CellOutcome.FLIP_NOT_REPRODUCED, CellOutcome.INCONCLUSIVE)

    result = decide_gate(given.a_gate_input(GateMode.PAIRED, cells=cells))

    assert result.outcome == GateOutcome.GREEN
    assert set(result.cells) == {"tool_0/input_validation", "tool_1/input_validation"}


def test_a_mismatch_makes_the_gate_not_comparable():
    mismatch = "budget: baseline 10, candidate 7"

    result = decide_gate(
        given.a_gate_input(
            GateMode.PAIRED,
            metrics=honeypot_gate_inputs.metrics(recall=0.1),
            cells=given.cells_with(CellOutcome.REGRESSION),
            mismatches=[mismatch],
        )
    )

    assert result.outcome == GateOutcome.NOT_COMPARABLE
    assert result.reasons == [mismatch]


def test_legacy_mode_with_a_mismatch_is_not_comparable():
    mismatch = "2 of 3 runs completed"

    result = decide_gate(given.a_gate_input(GateMode.LEGACY_THRESHOLDS, mismatches=[mismatch]))

    assert result.outcome == GateOutcome.NOT_COMPARABLE
    assert result.reasons == [mismatch]


@pytest.mark.parametrize(
    ("mode", "thresholds"),
    [
        (GateMode.LEGACY_THRESHOLDS, LEGACY_THRESHOLDS),
        (GateMode.FLOORS_ONLY, {}),
        (GateMode.PAIRED, {}),
    ],
)
def test_only_the_legacy_mode_carries_the_legacy_thresholds(
    mode: GateMode, thresholds: dict[str, float]
):
    result = decide_gate(given.a_gate_input(mode))

    assert result.thresholds == thresholds


def test_paired_mode_is_green_when_its_only_flips_are_declared():
    cells = given.cells_with(CellOutcome.UNCHANGED, CellOutcome.DECLARED)
    declared = frozenset({given.cell(1)})

    result = decide_gate(given.a_gate_input(GateMode.PAIRED, cells=cells, declared=declared))

    assert result.outcome == GateOutcome.GREEN
    assert result.declared_held == []


def test_a_declared_cell_that_did_not_flip_is_reported_as_held():
    cells = given.cells_with(CellOutcome.DECLARED, CellOutcome.UNCHANGED, CellOutcome.IMPROVED)
    declared = frozenset({given.cell(0), given.cell(2), given.cell(1)})

    result = decide_gate(given.a_gate_input(GateMode.PAIRED, cells=cells, declared=declared))

    assert result.outcome == GateOutcome.GREEN
    assert result.declared_held == ["tool_1/input_validation", "tool_2/input_validation"]


def test_a_regression_on_an_undeclared_cell_stays_red_beside_a_declared_flip():
    cells = given.cells_with(CellOutcome.DECLARED, CellOutcome.REGRESSION)
    declared = frozenset({given.cell(0)})

    result = decide_gate(given.a_gate_input(GateMode.PAIRED, cells=cells, declared=declared))

    assert result.outcome == GateOutcome.RED
    assert result.reasons == ["regression on tool_1/input_validation"]


def test_each_gate_outcome_has_its_documented_exit_code():
    exit_codes = {outcome: outcome.exit_code for outcome in GateOutcome}

    assert exit_codes == {GateOutcome.GREEN: 0, GateOutcome.RED: 1, GateOutcome.NOT_COMPARABLE: 3}
