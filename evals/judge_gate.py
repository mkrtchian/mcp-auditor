"""The judge isolation gate (ADR 025): the honeypot gate's rules with the case in place of the
cell, over observations that carry no label."""

from dataclasses import dataclass, field

from pydantic import BaseModel

from evals.baseline import BaselineStatus, verdict_maps_of
from evals.declared_flips import apply_declarations
from evals.gate import (
    FLOORS,
    CellComparison,
    CellOutcome,
    Observation,
    ProtectedCells,
    compare,
    count_detections,
    protected_cells,
    recall_floor_breached,
    settle,
)
from evals.gate_verdict import GateMode, GateVerdict
from evals.judge_baseline import JudgeBaseline, JudgeConditions
from evals.metrics import label_scores
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import EvalVerdict

DEFAULT_JUDGE_RUNS = 3

CaseRuns = list[dict[str, Observation]]


class JudgeGateResult(BaseModel):
    mode: GateMode
    verdict: GateVerdict
    reasons: list[str]
    baseline_status: BaselineStatus | None
    cases: dict[str, CellComparison]
    floor_breaches: list[str]
    declared_held: list[str] = []
    protected: ProtectedCells | None = None


@dataclass(frozen=True)
class JudgeGateInput:
    """`baseline` is the one the run read, compared only when there is one. `replays` holds,
    for each flipped case replayed, whether each replay reproduced the flip. Mismatches cover
    every reason the run cannot be compared."""

    mode: GateMode
    runs: CaseRuns
    ground_truth: dict[str, EvalVerdict]
    baseline: JudgeBaseline | None = None
    replays: dict[str, list[bool]] = field(default_factory=dict[str, list[bool]])
    declared: frozenset[str] = frozenset()
    mismatches: list[str] = field(default_factory=list[str])


def judge_case_gate(gate_input: JudgeGateInput) -> JudgeGateResult:
    breaches = judge_floor_breaches(gate_input.runs, gate_input.ground_truth)
    cases = _settled_cases(gate_input)
    if gate_input.mismatches:
        verdict, reasons = GateVerdict.NOT_COMPARABLE, list(gate_input.mismatches)
    else:
        reasons = _breach_reasons(gate_input, breaches)
        if gate_input.mode == GateMode.PAIRED:
            reasons += _regressions(cases)
        verdict = GateVerdict.RED if reasons else GateVerdict.GREEN
    baseline = gate_input.baseline
    return JudgeGateResult(
        mode=gate_input.mode,
        verdict=verdict,
        reasons=reasons,
        baseline_status=baseline.status if baseline else None,
        cases=cases,
        floor_breaches=breaches,
        declared_held=_declared_held(gate_input.declared, cases),
        protected=protected_cells(baseline.runs, gate_input.ground_truth) if baseline else None,
    )


def compare_cases(
    baseline: JudgeBaseline,
    runs: CaseRuns,
    ground_truth: dict[str, EvalVerdict],
    declared: frozenset[str],
) -> dict[str, CellComparison]:
    """Before any replay: the cases left in `FLIP` are the ones to replay."""
    return apply_declarations(compare(baseline.runs, runs, ground_truth), declared)


def _settled_cases(gate_input: JudgeGateInput) -> dict[str, CellComparison]:
    baseline = gate_input.baseline
    if baseline is None:
        return {}
    cases = compare_cases(baseline, gate_input.runs, gate_input.ground_truth, gate_input.declared)
    return {
        case: settle(comparison, gate_input.replays[case], baseline.replay_rule)
        if comparison.outcome == CellOutcome.FLIP and case in gate_input.replays
        else comparison
        for case, comparison in cases.items()
    }


def observe_case(verdict: EvalVerdict | None) -> Observation:
    return Observation.UNCOVERED if verdict is None else Observation(verdict.value)


def judge_ci_condition_mismatches(conditions: JudgeConditions) -> list[str]:
    """CI passes no --runs nor MCP_AUDITOR_* override, so it runs at the defaults."""
    defaults = Settings.model_construct()
    judge_model = defaults.resolve_judge_model()
    expected = {
        "runs": DEFAULT_JUDGE_RUNS,
        "provider": defaults.provider,
        "judge_model": judge_model,
        "judge_reasoning": defaults.resolve_reasoning(judge_model),
    }
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
        reasons.append(
            f"recall: {count.detections} detection(s) over {count.runs} runs, under one per run"
        )
    if "precision" in breaches:
        precision = _precision(gate_input.runs, gate_input.ground_truth)
        reasons.append(f"precision {precision:.2f} under its floor {FLOORS['precision']:.2f}")
    return reasons


def _regressions(cases: dict[str, CellComparison]) -> list[str]:
    return [
        f"regression on case {case}"
        for case, comparison in cases.items()
        if comparison.outcome == CellOutcome.REGRESSION
    ]


def _declared_held(declared: frozenset[str], cases: dict[str, CellComparison]) -> list[str]:
    return sorted(
        case for case in declared if case in cases and cases[case].outcome != CellOutcome.DECLARED
    )
