"""The judge gate (ADR 025): the honeypot gate's rules with the case in place of the
cell, over observations that carry no label."""

from dataclasses import dataclass, field

from pydantic import BaseModel

from evals.baseline import BaselineStatus, verdict_maps_of
from evals.declared_flips import apply_declarations, held_declarations
from evals.gate import (
    CellComparison,
    CellOutcome,
    Observation,
    ProtectedCells,
    apply_retests,
    compare,
    protected_cells,
)
from evals.gate_metrics import (
    FLOORS,
    count_detections,
    floor_breach_reason,
    recall_breach_reason,
    recall_floor_breached,
)
from evals.gate_outcome import GateMode, GateOutcome
from evals.judge.baseline import JudgeBaseline, JudgeConditions, judge_conditions
from evals.metrics import label_scores
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import EvalVerdict

DEFAULT_JUDGE_RUNS = 3

CaseRuns = list[dict[str, Observation]]


class JudgeGateResult(BaseModel):
    mode: GateMode
    outcome: GateOutcome
    reasons: list[str]
    baseline_status: BaselineStatus | None
    cases: dict[str, CellComparison]
    floor_breaches: list[str]
    declared_held: list[str] = []
    protected: ProtectedCells | None = None


@dataclass(frozen=True)
class JudgeGateInput:
    """`baseline` is the one the run read, compared only when there is one. `retests` holds,
    for each flipped case retested, whether each retest reproduced the flip. Mismatches cover
    every reason the run cannot be compared."""

    mode: GateMode
    runs: CaseRuns
    ground_truth: dict[str, EvalVerdict]
    baseline: JudgeBaseline | None = None
    retests: dict[str, list[bool]] = field(default_factory=dict[str, list[bool]])
    declared: frozenset[str] = frozenset()
    mismatches: list[str] = field(default_factory=list[str])


def decide_judge_gate(gate_input: JudgeGateInput) -> JudgeGateResult:
    breaches = judge_floor_breaches(gate_input.runs, gate_input.ground_truth)
    cases = _cases_after_retests(gate_input)
    if gate_input.mismatches:
        outcome, reasons = GateOutcome.NOT_COMPARABLE, list(gate_input.mismatches)
    else:
        reasons = _breach_reasons(gate_input, breaches)
        if gate_input.mode == GateMode.PAIRED:
            reasons += _regressions(cases)
        outcome = GateOutcome.RED if reasons else GateOutcome.GREEN
    baseline = gate_input.baseline
    return JudgeGateResult(
        mode=gate_input.mode,
        outcome=outcome,
        reasons=reasons,
        baseline_status=baseline.status if baseline else None,
        cases=cases,
        floor_breaches=breaches,
        declared_held=sorted(held_declarations(cases, gate_input.declared)),
        protected=protected_cells(baseline.runs, gate_input.ground_truth) if baseline else None,
    )


def _cases_after_retests(gate_input: JudgeGateInput) -> dict[str, CellComparison]:
    baseline = gate_input.baseline
    if baseline is None:
        return {}
    cases = compare_cases(baseline, gate_input.runs, gate_input.ground_truth, gate_input.declared)
    return {
        case: apply_retests(comparison, gate_input.retests[case], baseline.retest_rule)
        if comparison.outcome == CellOutcome.FLIP and case in gate_input.retests
        else comparison
        for case, comparison in cases.items()
    }


def compare_cases(
    baseline: JudgeBaseline,
    runs: CaseRuns,
    ground_truth: dict[str, EvalVerdict],
    declared: frozenset[str],
) -> dict[str, CellComparison]:
    """Before any retest: the cases left in `FLIP` are the ones to retest."""
    return apply_declarations(compare(baseline.runs, runs, ground_truth), declared)


def judge_ci_condition_mismatches(conditions: JudgeConditions) -> list[str]:
    """CI passes no --runs nor MCP_AUDITOR_* override, so it runs at the defaults."""
    expected = judge_conditions(
        Settings.model_construct(), DEFAULT_JUDGE_RUNS, conditions.inputs_fingerprint
    ).model_dump()
    actual = conditions.model_dump()
    return [
        f"{name}: CI runs {value}, this run {actual[name]}"
        for name, value in expected.items()
        if actual[name] != value
    ]


def judge_floor_breaches(runs: CaseRuns, ground_truth: dict[str, EvalVerdict]) -> list[str]:
    recall = ["recall"] if recall_floor_breached(count_detections(runs, ground_truth)) else []
    precision = _precision(runs, ground_truth) < FLOORS["precision"]
    return recall + (["precision"] if precision else [])


def _precision(runs: CaseRuns, ground_truth: dict[str, EvalVerdict]) -> float:
    return label_scores(verdict_maps_of(runs), ground_truth)["precision"]


def _breach_reasons(gate_input: JudgeGateInput, breaches: list[str]) -> list[str]:
    reasons: list[str] = []
    if "recall" in breaches:
        count = count_detections(gate_input.runs, gate_input.ground_truth)
        reasons.append(recall_breach_reason(count))
    if "precision" in breaches:
        precision = _precision(gate_input.runs, gate_input.ground_truth)
        reasons.append(floor_breach_reason("precision", precision))
    return reasons


def _regressions(cases: dict[str, CellComparison]) -> list[str]:
    return [
        f"regression on case {case}"
        for case, comparison in cases.items()
        if comparison.outcome == CellOutcome.REGRESSION
    ]
