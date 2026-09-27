from evals.baseline import Baseline
from evals.gate import Cell, CellComparison, CellOutcome, FlipCause, cell_key
from evals.gate_verdict import GateResult, GateVerdict
from evals.metrics import VerdictMap, aggregate_verdicts
from evals.recording import RecordingRefused
from mcp_auditor.domain.models import AuditReport, EvalVerdict, TokenUsage


def red_on(result: GateResult, *reasons: str) -> None:
    assert result.verdict == GateVerdict.RED
    assert result.reasons == list(reasons)


def green(result: GateResult) -> None:
    assert result.verdict == GateVerdict.GREEN
    assert result.reasons == []


def flipped(cells: dict[Cell, CellComparison], expected: list[Cell], cause: FlipCause) -> None:
    flips = {cell for cell, comparison in cells.items() if comparison.outcome == CellOutcome.FLIP}
    assert flips == set(expected)
    assert {cells[cell].cause for cell in flips} <= {cause}


def settled_as(result: GateResult, expected: list[Cell], outcome: CellOutcome) -> None:
    settled = {key for key, comparison in result.cells.items() if comparison.outcome == outcome}
    assert settled == {cell_key(cell) for cell in expected}


def refused_on(decision: Baseline | RecordingRefused, *reasons: str) -> None:
    assert isinstance(decision, RecordingRefused)
    assert decision.reasons == list(reasons)


def accepted(decision: Baseline | RecordingRefused) -> None:
    assert isinstance(decision, Baseline)


def only_detections_lost(verdicts: VerdictMap, degraded: VerdictMap) -> None:
    turned = {cell for cell in verdicts if degraded[cell] != verdicts[cell]}
    assert turned
    assert {verdicts[cell] for cell in turned} == {EvalVerdict.FAIL}
    assert {degraded[cell] for cell in turned} == {EvalVerdict.PASS}


def merged(verdicts: VerdictMap, report: AuditReport, reports: list[AuditReport]) -> None:
    assert verdicts == {
        cell: verdict for each in reports for cell, verdict in aggregate_verdicts(each).items()
    }
    assert report.tool_reports == [tool for each in reports for tool in each.tool_reports]
    assert report.token_usage == TokenUsage(input_tokens=600, output_tokens=60)
    assert report.refused_steps == [step for each in reports for step in each.refused_steps]
