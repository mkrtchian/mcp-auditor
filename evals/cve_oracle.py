from collections import Counter
from collections.abc import Sequence
from datetime import date
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel

from evals.cell_grid import replay_fraction
from evals.cve_baseline import CVERunConditions
from evals.cve_costs import TargetCost, render_cost_table
from evals.cve_gate import CVEGateResult, TargetComparison
from evals.cve_grammar import CVEStatus, MechanismClass, MissClass, RunGrade, resolve
from evals.cve_measurement import MeasurementSettings, render_measurement
from evals.cve_units import JudgeCategory
from mcp_auditor.domain.models import ProviderUsage


class UngradedStatus(StrEnum):
    NOT_RUN = "not_run"
    OUT_OF_SCOPE = "out_of_scope"


type TargetStatus = CVEStatus | UngradedStatus


class TargetInfo(Protocol):
    """Descriptive slice of a CVE target the pure oracle reads. It never grades, so it reads
    no nonce or aim."""

    @property
    def cve_id(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def mechanism(self) -> MechanismClass | None: ...
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
    status: TargetStatus
    miss_class: MissClass | None = None
    awaited_capability: str | None = None
    runs: int = 0
    detected_runs: int = 0
    surfaced_runs: int = 0
    aimed_runs: int = 0
    fail_without_proof_runs: int = 0
    budget: int = 0
    evidence: str | None = None
    category: JudgeCategory | None = None
    not_run_conditions: list[str] = []  # the pre-run check's dead conditions, when NOT_RUN
    surfaced_places: list[list[str]] = []  # per run: the places whose nonce surfaced
    struck_places: list[list[str]] = []  # per run: the credits the replay refused
    unchecked_places: list[list[str]] = []  # per run: the credits the replay could not check


class CVEBenchmarkReport(BaseModel):
    conditions: CVERunConditions
    concurrency: int  # an execution setting, never compared nor recorded in a baseline
    throttled_requests: int = 0  # an execution observation, never compared nor recorded
    provider_usage: ProviderUsage = ProviderUsage()  # every attempt billed, replays included
    commit: str
    dirty: bool
    results: list[CVEResult]
    gate: CVEGateResult | None = None
    recording_refused: list[str] = []
    measurement: MeasurementSettings | None = None  # forced settings, never compared
    costs: list[TargetCost] = []  # ungated runs priced from evals/holdout_conditions.json only
    prices_as_of: date | None = None


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
        surfaced_places=resolution.surfaced_places,
        struck_places=resolution.struck_places,
        unchecked_places=resolution.unchecked_places,
    )


def not_run(target: TargetInfo, conditions: list[str] | None = None) -> CVEResult:
    return CVEResult(
        cve_id=target.cve_id,
        severity=target.severity,
        note=target.note,
        mechanism=target.mechanism,
        status=UngradedStatus.NOT_RUN,
        awaited_capability=target.awaited_capability,
        not_run_conditions=conditions or [],
    )


def out_of_scope_results(cves: Sequence[OutOfScopeInfo]) -> list[CVEResult]:
    return [
        CVEResult(
            cve_id=cve.cve_id,
            severity=cve.severity,
            note=cve.reason,
            status=UngradedStatus.OUT_OF_SCOPE,
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
    gate = [] if report.gate is None else ["", *_render_gate(report.gate)]
    refusal = [f"- {reason}" for reason in report.recording_refused]
    if refusal:
        refusal = ["", "Recording refused, no baseline written:", *refusal]
    return "\n".join(
        [
            render_conditions(report),
            *_render_measurement(report),
            "",
            header,
            separator,
            *rows,
            "",
            render_tally(report.results),
            *_render_throttled(report),
            *render_not_run(report.results),
            *render_replay_credits(report.results),
            *_render_costs(report),
            *gate,
            *refusal,
        ]
    )


def render_tally(results: Sequence[CVEResult]) -> str:
    # A single detected/total ratio would pool targets whose traces have been read with
    # targets that have not, and those two carry different claims. See ADR 015.
    counts = Counter(result.status for result in results)
    tally = ", ".join(
        f"{counts[status]} {status.value}"
        for status in (*CVEStatus, *UngradedStatus)
        if counts[status]
    )
    return f"Statuses: {tally}."


def _render_throttled(report: CVEBenchmarkReport) -> list[str]:
    if report.throttled_requests == 0:
        return []
    return [
        "",
        f"Throttled by the model provider: {report.throttled_requests} requests "
        f"at concurrency {report.concurrency}",
    ]


def _render_measurement(report: CVEBenchmarkReport) -> list[str]:
    return [] if report.measurement is None else [render_measurement(report.measurement)]


def _render_costs(report: CVEBenchmarkReport) -> list[str]:
    # A target with no report was billed nothing, so it has no row.
    if not report.costs:
        return []
    title = f"Cost per target, all attempts, dollars at the prices as of {report.prices_as_of}:"
    return ["", title, "", *render_cost_table(report.costs)]


def render_replay_credits(results: Sequence[CVEResult]) -> list[str]:
    # The strike and the unchecked credits go in a section after the table, place ids only.
    lines = [line for result in results if (line := _replay_credits_line(result)) is not None]
    return ["", "Replay credits (place ids):", *lines] if lines else []


def _replay_credits_line(result: CVEResult) -> str | None:
    refused = sorted({place for run in result.struck_places for place in run})
    unchecked = sorted({place for run in result.unchecked_places for place in run})
    if not refused and not unchecked:
        return None
    parts = [f"refused ({', '.join(refused)})"] if refused else []
    parts += [f"unchecked ({', '.join(unchecked)})"] if unchecked else []
    return f"- {result.cve_id}: {', '.join(parts)}"


def render_not_run(results: Sequence[CVEResult]) -> list[str]:
    # A line between two rows would end the table, so the conditions go in a section after it.
    lines = [
        f"- {result.cve_id}: {', '.join(result.not_run_conditions)}"
        for result in results
        if result.not_run_conditions
    ]
    return ["", "Not run, pre-run check failed:", *lines] if lines else []


def render_conditions(report: CVEBenchmarkReport) -> str:
    conditions = report.conditions
    model = _with_reasoning(conditions.model, conditions.reasoning)
    judge = _with_reasoning(conditions.judge_model, conditions.judge_reasoning)
    every_tool = report.measurement is not None and report.measurement.every_tool
    tools = "tools filtered" if conditions.tools_filtered and not every_tool else "all tools"
    usage = report.provider_usage
    return (
        f"Conditions: {conditions.provider}, model {model}, judge {judge}, "
        f"{conditions.runs} runs, budget {conditions.budget}, {tools}, "
        f"grammar {conditions.grammar_fingerprint[:12]}, {report.concurrency} audits at once, "
        f"{usage.input_tokens} input tokens, {usage.output_tokens} output tokens."
    )


def _render_gate(gate: CVEGateResult) -> list[str]:
    return [
        f"Gate: {gate.verdict.value}.",
        *(f"- {reason}" for reason in gate.reasons),
        "",
        "| Target | Outcome | Baseline | Run | Replays | Detail |",
        "|---|---|---|---|---|---|",
        *(_render_gate_row(comparison) for comparison in gate.targets),
        "",
        GATE_LEGEND,
    ]


GATE_LEGEND = (
    "Runs: D detected, J reached but judged PASS, M missed. "
    "Baseline: every run its file holds, both recordings once confirmed. "
    "Replays: the miss reproduced in k of n replays."
)


def _render_gate_row(comparison: TargetComparison) -> str:
    cells = [
        comparison.cve_id,
        comparison.outcome.value,
        status_letters(comparison.baseline_runs) or "-",
        status_letters(comparison.candidate_runs) or "-",
        replay_fraction(comparison.replays),
        (comparison.detail or "-").replace("|", "\\|"),
    ]
    return f"| {' | '.join(cells)} |"


def status_letters(statuses: Sequence[CVEStatus]) -> str:
    return "".join(_STATUS_LETTERS[status] for status in statuses)


_STATUS_LETTERS = {
    CVEStatus.DETECTED: "D",
    CVEStatus.REACHED_BUT_JUDGED_PASS: "J",
    CVEStatus.MISSED: "M",
}


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
