import pytest

import tests.unit.support.test_eval_gate_verdict_given as given
from evals.gate import LEGACY_THRESHOLDS, CellOutcome
from evals.gate_verdict import GateInput, GateMode, GateVerdict, judge_gate


@pytest.mark.parametrize("metric", sorted(LEGACY_THRESHOLDS))
def test_legacy_mode_is_red_on_a_missed_legacy_threshold(metric: str):
    missed = LEGACY_THRESHOLDS[metric] - 0.01

    result = judge_gate(
        GateInput(
            mode=GateMode.LEGACY_THRESHOLDS,
            metrics=given.metrics(**{metric: missed}),
            detections=given.detections(),
        )
    )

    assert result.verdict == GateVerdict.RED
    assert any(metric in reason for reason in result.reasons)


def test_legacy_mode_is_green_when_every_threshold_is_met():
    result = judge_gate(
        GateInput(
            mode=GateMode.LEGACY_THRESHOLDS,
            metrics=given.metrics(),
            detections=given.detections(),
        )
    )

    assert result.verdict == GateVerdict.GREEN
    assert result.reasons == []


def test_legacy_mode_reports_floor_breaches():
    result = judge_gate(
        GateInput(
            mode=GateMode.LEGACY_THRESHOLDS,
            metrics=given.metrics(),
            detections=given.detections(2, runs=3),
        )
    )

    assert result.floor_breaches == ["recall"]


def test_a_recall_breach_reads_as_detections_under_one_per_run():
    result = judge_gate(
        GateInput(
            mode=GateMode.FLOORS_ONLY,
            metrics=given.metrics(),
            detections=given.detections(2, runs=3),
        )
    )

    assert result.verdict == GateVerdict.RED
    assert result.reasons == ["recall: 2 detection(s) over 3 runs, under one per run"]


def test_the_recall_floor_reads_as_one_planted_flaw_in_the_floors():
    result = judge_gate(
        GateInput(mode=GateMode.PAIRED, metrics=given.metrics(), detections=given.detections())
    )

    assert result.floors == {"recall": 1 / 8, "precision": 0.50, "distribution_coverage": 0.50}


def test_floors_only_mode_ignores_a_regression_cell():
    result = judge_gate(
        GateInput(
            mode=GateMode.FLOORS_ONLY,
            metrics=given.metrics(),
            detections=given.detections(),
            cells=given.cells_with(CellOutcome.REGRESSION),
        )
    )

    assert result.verdict == GateVerdict.GREEN


def test_floors_only_mode_is_red_on_a_floor_breach():
    result = judge_gate(
        GateInput(
            mode=GateMode.FLOORS_ONLY,
            metrics=given.metrics(distribution_coverage=0.4),
            detections=given.detections(),
        )
    )

    assert result.verdict == GateVerdict.RED


def test_paired_mode_is_red_on_a_regression():
    cells = given.cells_with(CellOutcome.UNCHANGED, CellOutcome.REGRESSION)

    result = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=given.metrics(),
            detections=given.detections(),
            cells=cells,
        )
    )

    assert result.verdict == GateVerdict.RED
    assert any("tool_1/input_validation" in reason for reason in result.reasons)


def test_paired_mode_is_red_on_a_floor_breach():
    result = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=given.metrics(precision=0.3),
            detections=given.detections(),
        )
    )

    assert result.verdict == GateVerdict.RED
    assert any("precision" in reason for reason in result.reasons)


def test_paired_mode_is_green_with_only_unreproduced_and_inconclusive_flips():
    cells = given.cells_with(CellOutcome.FLIP_NOT_REPRODUCED, CellOutcome.INCONCLUSIVE)

    result = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=given.metrics(),
            detections=given.detections(),
            cells=cells,
        )
    )

    assert result.verdict == GateVerdict.GREEN
    assert set(result.cells) == {"tool_0/input_validation", "tool_1/input_validation"}


def test_a_mismatch_makes_the_gate_not_comparable():
    mismatch = "budget: baseline 10, candidate 7"

    result = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=given.metrics(recall=0.1),
            detections=given.detections(),
            cells=given.cells_with(CellOutcome.REGRESSION),
            mismatches=[mismatch],
        )
    )

    assert result.verdict == GateVerdict.NOT_COMPARABLE
    assert result.reasons == [mismatch]


def test_legacy_mode_with_a_mismatch_is_not_comparable():
    mismatch = "2 of 3 runs completed"

    result = judge_gate(
        GateInput(
            mode=GateMode.LEGACY_THRESHOLDS,
            metrics=given.metrics(),
            detections=given.detections(),
            mismatches=[mismatch],
        )
    )

    assert result.verdict == GateVerdict.NOT_COMPARABLE
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
    result = judge_gate(
        GateInput(mode=mode, metrics=given.metrics(), detections=given.detections())
    )

    assert result.thresholds == thresholds


def test_paired_mode_is_green_when_its_only_flips_are_declared():
    cells = given.cells_with(CellOutcome.UNCHANGED, CellOutcome.DECLARED)

    result = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=given.metrics(),
            detections=given.detections(),
            cells=cells,
            declared=frozenset({given.cell(1)}),
        )
    )

    assert result.verdict == GateVerdict.GREEN
    assert result.declared_held == []


def test_a_declared_cell_that_did_not_flip_is_reported_as_held():
    cells = given.cells_with(CellOutcome.DECLARED, CellOutcome.UNCHANGED, CellOutcome.IMPROVED)

    result = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=given.metrics(),
            detections=given.detections(),
            cells=cells,
            declared=frozenset({given.cell(0), given.cell(2), given.cell(1)}),
        )
    )

    assert result.verdict == GateVerdict.GREEN
    assert result.declared_held == ["tool_1/input_validation", "tool_2/input_validation"]


def test_a_regression_on_an_undeclared_cell_stays_red_beside_a_declared_flip():
    cells = given.cells_with(CellOutcome.DECLARED, CellOutcome.REGRESSION)

    result = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=given.metrics(),
            detections=given.detections(),
            cells=cells,
            declared=frozenset({given.cell(0)}),
        )
    )

    assert result.verdict == GateVerdict.RED
    assert result.reasons == ["regression on tool_1/input_validation"]
