import pytest

import tests.unit.support.test_eval_gate_verdict_given as given
from evals.gate import LEGACY_THRESHOLDS, CellOutcome
from evals.gate_verdict import GateInput, GateMode, GateVerdict, judge_gate


@pytest.mark.parametrize("metric", sorted(LEGACY_THRESHOLDS))
def test_legacy_mode_is_red_on_a_missed_legacy_threshold(metric: str):
    missed = LEGACY_THRESHOLDS[metric] - 0.01

    result = judge_gate(
        GateInput(mode=GateMode.LEGACY_THRESHOLDS, metrics=given.metrics(**{metric: missed}))
    )

    assert result.verdict == GateVerdict.RED
    assert any(metric in reason for reason in result.reasons)


def test_legacy_mode_is_green_when_every_threshold_is_met():
    result = judge_gate(
        GateInput(
            mode=GateMode.LEGACY_THRESHOLDS,
            metrics=given.metrics(),
        )
    )

    assert result.verdict == GateVerdict.GREEN
    assert result.reasons == []


def test_legacy_mode_reports_floor_breaches():
    result = judge_gate(
        GateInput(
            mode=GateMode.LEGACY_THRESHOLDS,
            metrics=given.metrics(recall=0.4),
        )
    )

    assert result.floor_breaches == ["recall"]


def test_floors_only_mode_ignores_a_regression_cell():
    result = judge_gate(
        GateInput(
            mode=GateMode.FLOORS_ONLY,
            metrics=given.metrics(),
            cells=given.cells_with(CellOutcome.REGRESSION),
        )
    )

    assert result.verdict == GateVerdict.GREEN


def test_floors_only_mode_is_red_on_a_floor_breach():
    result = judge_gate(
        GateInput(mode=GateMode.FLOORS_ONLY, metrics=given.metrics(distribution_coverage=0.4))
    )

    assert result.verdict == GateVerdict.RED


def test_paired_mode_is_red_on_a_regression():
    cells = given.cells_with(CellOutcome.UNCHANGED, CellOutcome.REGRESSION)

    result = judge_gate(GateInput(mode=GateMode.PAIRED, metrics=given.metrics(), cells=cells))

    assert result.verdict == GateVerdict.RED
    assert any("tool_1/input_validation" in reason for reason in result.reasons)


def test_paired_mode_is_red_on_a_floor_breach():
    result = judge_gate(GateInput(mode=GateMode.PAIRED, metrics=given.metrics(precision=0.3)))

    assert result.verdict == GateVerdict.RED
    assert any("precision" in reason for reason in result.reasons)


def test_paired_mode_is_green_with_only_unreproduced_and_inconclusive_flips():
    cells = given.cells_with(CellOutcome.FLIP_NOT_REPRODUCED, CellOutcome.INCONCLUSIVE)

    result = judge_gate(GateInput(mode=GateMode.PAIRED, metrics=given.metrics(), cells=cells))

    assert result.verdict == GateVerdict.GREEN
    assert set(result.cells) == {"tool_0/input_validation", "tool_1/input_validation"}


def test_a_mismatch_makes_the_gate_not_comparable():
    mismatch = "budget: baseline 10, candidate 7"

    result = judge_gate(
        GateInput(
            mode=GateMode.PAIRED,
            metrics=given.metrics(recall=0.1),
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
    result = judge_gate(GateInput(mode=mode, metrics=given.metrics()))

    assert result.thresholds == thresholds
