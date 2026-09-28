from collections.abc import Callable

from evals.baseline import Baseline
from evals.fault_catalog import NO_STABLE_FAIL_CELL, Expectation
from evals.fault_harness import FaultResult
from evals.gate import CellOutcome, CellState, Observation, cell_key, classify
from evals.gate_verdict import GateVerdict
from evals.honeypots import MERGED_GROUND_TRUTH
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

_FLIPPED = {CellOutcome.FLIP, CellOutcome.REGRESSION, CellOutcome.FLIP_NOT_REPRODUCED}


def expectation_met(result: FaultResult, expectation: Expectation) -> None:
    observed = _summary(result)
    assert result.paired.verdict == expectation.paired, observed
    assert result.floors_only.verdict == expectation.floors_only, observed
    assert bool(result.recording_refusals) == expectation.recording_refused, observed
    reasons = result.paired.reasons + result.floors_only.reasons + result.recording_refusals
    for expected in expectation.reasons:
        assert any(expected in reason for reason in reasons), f"no {expected!r} in {observed}"


def the_fixture_reproduced(result: FaultResult, fixture: Baseline) -> None:
    observed = _summary(result)
    assert result.observations == fixture.runs, observed
    assert result.paired.verdict == GateVerdict.GREEN, observed
    for key in _fixture_cells(fixture, lambda state, _: state != CellState.UNSTABLE):
        assert result.paired.cells[key].outcome == CellOutcome.UNCHANGED, f"{key}: {observed}"


def the_half_loss_obeys_the_rules(result: FaultResult, fixture: Baseline) -> None:
    observed = _summary(result)
    under_one_per_run = _detections(result) < len(result.observations)
    assert (result.floors_only.verdict == GateVerdict.RED) == under_one_per_run, observed
    stable_detections = _fixture_cells(fixture, _stable_detection)
    for key in stable_detections:
        if not _detected_in_every_run(result, key):
            lost = result.paired.cells[key].outcome
            assert lost in {CellOutcome.REGRESSION, CellOutcome.FLIP_NOT_REPRODUCED}, observed
    none_survived = not any(_detected_in_every_run(result, key) for key in stable_detections)
    refused_blind = any(NO_STABLE_FAIL_CELL in reason for reason in result.recording_refusals)
    assert refused_blind == none_survived, observed


def some_pass_cells_flipped(result: FaultResult) -> None:
    pass_cells = _cells_labelled(EvalVerdict.PASS)
    flipped = [key for key in pass_cells if result.paired.cells[key].outcome in _FLIPPED]
    assert flipped, _summary(result)


def only_the_declared_category_flipped(
    result: FaultResult, fixture: Baseline, category: AuditCategory
) -> None:
    observed = _summary(result)
    declared = _fixture_cells(fixture, lambda state, _: state == CellState.STABLE_CORRECT, category)
    assert declared, observed
    for key in declared:
        assert result.paired.cells[key].outcome == CellOutcome.DECLARED, f"{key}: {observed}"
    flipped = [key for key, cell in result.paired.cells.items() if cell.outcome in _FLIPPED]
    assert flipped == [], observed


def _fixture_cells(
    fixture: Baseline,
    keep: Callable[[CellState, EvalVerdict], bool],
    category: AuditCategory | None = None,
) -> list[str]:
    states = classify(fixture.observation_runs(), MERGED_GROUND_TRUTH)
    return [
        cell_key(cell)
        for cell, state in states.items()
        if keep(state, MERGED_GROUND_TRUTH[cell]) and category in (None, cell[1])
    ]


def _stable_detection(state: CellState, label: EvalVerdict) -> bool:
    return state == CellState.STABLE_CORRECT and label == EvalVerdict.FAIL


def _detected_in_every_run(result: FaultResult, key: str) -> bool:
    return all(run[key] == Observation.FAIL for run in result.observations)


def _detections(result: FaultResult) -> int:
    planted = _cells_labelled(EvalVerdict.FAIL)
    return sum(run[key] == Observation.FAIL for run in result.observations for key in planted)


def _cells_labelled(label: EvalVerdict) -> list[str]:
    return [cell_key(cell) for cell, verdict in MERGED_GROUND_TRUTH.items() if verdict == label]


def _summary(result: FaultResult) -> str:
    moved = {
        key: comparison.outcome.value
        for key, comparison in result.paired.cells.items()
        if comparison.outcome != CellOutcome.UNCHANGED
    }
    return (
        f"{result.fault}: paired {result.paired.verdict} {result.paired.reasons}, "
        f"floors_only {result.floors_only.verdict} {result.floors_only.reasons}, "
        f"recording refusals {result.recording_refusals}, cells moved {moved}, "
        f"metrics {result.metrics}"
    )
