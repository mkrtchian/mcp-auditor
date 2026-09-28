from collections import Counter
from collections.abc import Sequence
from typing import Protocol

from pydantic import BaseModel

from evals.cve_baseline import CVERunConditions
from evals.cve_gate import CVEGateResult, TargetComparison
from evals.cve_grammar import CVEStatus, GradedTarget, MechanismClass, MissClass, RunGrade, resolve
from mcp_auditor.domain.models import AuditCategory


class TargetInfo(GradedTarget, Protocol):
    """Descriptive slice of a CVE target the pure oracle reads."""

    @property
    def cve_id(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def awaited_capability(self) -> str | None: ...
    @property
    def note(self) -> str: ...


class OutOfScopeInfo(Protocol):
    """A CVE tracked but never run (only catchable with instrumentation)."""

    @property
    def cve_id(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def reason(self) -> str: ...


class CVEResult(BaseModel):
    cve_id: str
    severity: str
    note: str
    mechanism: MechanismClass | None = None
    status: CVEStatus
    miss_class: MissClass | None = None
    awaited_capability: str | None = None
    runs: int = 0
    detected_runs: int = 0
    surfaced_runs: int = 0
    aimed_runs: int = 0
    fail_without_proof_runs: int = 0
    budget: int = 0
    evidence: str | None = None
    category: AuditCategory | None = None


class CVEBenchmarkReport(BaseModel):
    conditions: CVERunConditions
    results: list[CVEResult]
    gate: CVEGateResult | None = None
    recording_refused: list[str] = []


def result_for(target: TargetInfo, grades: Sequence[RunGrade], budget: int) -> CVEResult:
    resolution = resolve(grades)
    return CVEResult(
        cve_id=target.cve_id,
        severity=target.severity,
        note=target.note,
        mechanism=target.mechanism,
        status=resolution.status,
        miss_class=resolution.miss_class,
        awaited_capability=target.awaited_capability,
        runs=len(grades),
        detected_runs=resolution.detected_runs,
        surfaced_runs=resolution.surfaced_runs,
        aimed_runs=resolution.aimed_runs,
        fail_without_proof_runs=resolution.fail_without_proof_runs,
        budget=budget,
        evidence=resolution.evidence,
        category=resolution.category,
    )


def not_run(target: TargetInfo) -> CVEResult:
    return CVEResult(
        cve_id=target.cve_id,
        severity=target.severity,
        note=target.note,
        mechanism=target.mechanism,
        status=CVEStatus.NOT_RUN,
        awaited_capability=target.awaited_capability,
    )


def out_of_scope_results(cves: Sequence[OutOfScopeInfo]) -> list[CVEResult]:
    return [
        CVEResult(
            cve_id=cve.cve_id,
            severity=cve.severity,
            note=cve.reason,
            status=CVEStatus.OUT_OF_SCOPE,
        )
        for cve in cves
    ]


def render_markdown(report: CVEBenchmarkReport) -> str:
    header = (
        "| CVE | CVSS | Class | Status | Detected | Miss class | Aimed | FAIL without proof "
        "| Awaited capability (hypothesis) | Note |"
    )
    separator = "|---|---|---|---|---|---|---|---|---|---|"
    rows = [_render_row(result) for result in report.results]
    # A single detected/total ratio would pool targets whose traces have been read with
    # targets that have not, and those two carry different claims. See ADR 015.
    counts = Counter(result.status for result in report.results)
    tally = ", ".join(f"{counts[status]} {status.value}" for status in CVEStatus if counts[status])
    gate = [] if report.gate is None else ["", *_render_gate(report.gate)]
    refusal = [f"- {reason}" for reason in report.recording_refused]
    if refusal:
        refusal = ["", "Recording refused, no baseline written:", *refusal]
    return "\n".join(
        [
            _render_conditions(report.conditions),
            "",
            header,
            separator,
            *rows,
            "",
            f"Statuses: {tally}.",
            *gate,
            *refusal,
        ]
    )


def _render_conditions(conditions: CVERunConditions) -> str:
    model = _with_reasoning(conditions.model, conditions.reasoning)
    judge = _with_reasoning(conditions.judge_model, conditions.judge_reasoning)
    tools = "tools filtered" if conditions.tools_filtered else "all tools"
    return (
        f"Conditions: {conditions.provider}, model {model}, judge {judge}, "
        f"{conditions.runs} runs, budget {conditions.budget}, {tools}, "
        f"grammar {conditions.grammar_fingerprint[:12]}."
    )


def _render_gate(gate: CVEGateResult) -> list[str]:
    return [
        f"Gate: {gate.verdict.value}.",
        *(f"- {reason}" for reason in gate.reasons),
        "",
        "Targets:",
        *(_render_comparison(comparison) for comparison in gate.targets),
    ]


def _render_comparison(comparison: TargetComparison) -> str:
    detail = f" ({comparison.detail})" if comparison.detail else ""
    runs = ", ".join(status.value for status in comparison.candidate_runs) or "none"
    line = f"- {comparison.cve_id}: {comparison.outcome.value}{detail}. Runs: {runs}."
    if not comparison.replays:
        return line
    replays = ", ".join("reproduced" if replay else "cleared" for replay in comparison.replays)
    return f"{line} Replays: {replays}."


def _with_reasoning(model: str, reasoning: str | None) -> str:
    return f"{model} (reasoning {reasoning or 'default'})"


def _render_row(result: CVEResult) -> str:
    cells = [
        result.cve_id,
        result.severity,
        result.mechanism or "-",
        result.status.value,
        _fraction(result.detected_runs, result.runs),
        result.miss_class or "-",
        _fraction(result.aimed_runs, result.runs),
        _fraction(result.fail_without_proof_runs, result.runs),
        result.awaited_capability or "-",
        result.note,
    ]
    return f"| {' | '.join(cells)} |"


def _fraction(count: int, runs: int) -> str:
    return f"{count}/{runs}" if runs else "-"
