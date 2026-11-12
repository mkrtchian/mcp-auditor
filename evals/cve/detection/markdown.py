"""The markdown of a detection suite report, and the pieces of it the console summary reuses."""

from collections import Counter
from collections.abc import Sequence

from evals.cell_grid import retest_fraction
from evals.cve.detection.costs import render_cost_table
from evals.cve.detection.gate import DetectionGateResult, TargetComparison
from evals.cve.detection.measurement import render_measurement
from evals.cve.detection.oracle import DetectionReport, TargetResult, UngradedStatus
from evals.cve.grammar import TargetStatus


def render_markdown(report: DetectionReport) -> str:
    header = (
        "| Flaw | CVSS | Class | Status | Detected | Miss kind | Aimed | FAIL without proof "
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
            *render_measurement_lines(report),
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


def render_tally(results: Sequence[TargetResult]) -> str:
    # A single detected/total ratio would pool targets whose traces have been read with
    # targets that have not, and those two carry different claims. See ADR 015.
    counts = Counter(result.status for result in results)
    tally = ", ".join(
        f"{counts[status]} {status.value}"
        for status in (*TargetStatus, *UngradedStatus)
        if counts[status]
    )
    return f"Statuses: {tally}."


def _render_throttled(report: DetectionReport) -> list[str]:
    if report.throttled_requests == 0:
        return []
    return [
        "",
        f"Throttled by the model provider: {report.throttled_requests} requests "
        f"at concurrency {report.concurrency}",
    ]


def render_measurement_lines(report: DetectionReport) -> list[str]:
    return [] if report.measurement is None else [render_measurement(report.measurement)]


def _render_costs(report: DetectionReport) -> list[str]:
    # A target with no report was billed nothing, so it has no row.
    if not report.costs:
        return []
    return ["", render_cost_title(report), "", *render_cost_table(report.costs)]


def render_cost_title(report: DetectionReport) -> str:
    return f"Cost per target, all attempts, dollars at the prices as of {report.prices_as_of}:"


def render_replay_credits(results: Sequence[TargetResult]) -> list[str]:
    # The struck and the unchecked credits go in a section after the table, place ids only.
    lines = [line for result in results if (line := _replay_credits_line(result)) is not None]
    return ["", "Replay credits (place ids):", *lines] if lines else []


def _replay_credits_line(result: TargetResult) -> str | None:
    struck = sorted({place for run in result.struck_places for place in run})
    unchecked = sorted({place for run in result.unchecked_places for place in run})
    if not struck and not unchecked:
        return None
    parts = [f"struck ({', '.join(struck)})"] if struck else []
    parts += [f"unchecked ({', '.join(unchecked)})"] if unchecked else []
    return f"- {result.flaw_id}: {', '.join(parts)}"


def render_not_run(results: Sequence[TargetResult]) -> list[str]:
    # A line between two rows would end the table, so the reasons go in a section after it.
    lines = [
        f"- {result.flaw_id}: {', '.join(result.not_run_reasons)}"
        for result in results
        if result.not_run_reasons
    ]
    return ["", "Not run, pre-run check failed:", *lines] if lines else []


def render_conditions(report: DetectionReport) -> str:
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


def _render_gate(gate: DetectionGateResult) -> list[str]:
    return [
        f"Gate: {gate.outcome.value}.",
        *(f"- {reason}" for reason in gate.reasons),
        "",
        "| Target | Outcome | Baseline | Run | Retests | Detail |",
        "|---|---|---|---|---|---|",
        *(_render_gate_row(comparison) for comparison in gate.targets),
        "",
        GATE_LEGEND,
    ]


GATE_LEGEND = (
    "Runs: D detected, J reached but judged PASS, M missed. "
    "Baseline: every run its file holds, both recordings once confirmed. "
    "Retests: the miss reproduced in k of n retests."
)


def _render_gate_row(comparison: TargetComparison) -> str:
    cells = [
        comparison.flaw_id,
        comparison.outcome.value,
        status_letters(comparison.baseline_runs) or "-",
        status_letters(comparison.candidate_runs) or "-",
        retest_fraction(comparison.retests),
        (comparison.detail or "-").replace("|", "\\|"),
    ]
    return f"| {' | '.join(cells)} |"


def status_letters(statuses: Sequence[TargetStatus]) -> str:
    return "".join(_STATUS_LETTERS[status] for status in statuses)


_STATUS_LETTERS = {
    TargetStatus.DETECTED: "D",
    TargetStatus.REACHED_BUT_JUDGED_PASS: "J",
    TargetStatus.MISSED: "M",
}


def _with_reasoning(model: str, reasoning: str | None) -> str:
    return f"{model} (reasoning {reasoning or 'default'})"


def _render_row(result: TargetResult) -> str:
    cells = [
        result.flaw_id,
        result.severity,
        ", ".join(result.classes) or "-",
        result.status.value,
        run_fraction(result.detected_runs, result.runs),
        result.miss_kind or "-",
        run_fraction(result.aimed_runs, result.runs),
        run_fraction(result.fail_without_proof_runs, result.runs),
        result.awaited_capability or "-",
        result.note,
    ]
    return f"| {' | '.join(cells)} |"


def run_fraction(count: int, runs: int) -> str:
    return f"{count}/{runs}" if runs else "-"
