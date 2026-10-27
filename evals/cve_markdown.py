"""The markdown of a CVE benchmark report, and the pieces of it the console summary reuses."""

from collections import Counter
from collections.abc import Sequence

from evals.cell_grid import replay_fraction
from evals.cve_costs import render_cost_table
from evals.cve_gate import CVEGateResult, TargetComparison
from evals.cve_grammar import CVEStatus
from evals.cve_measurement import render_measurement
from evals.cve_oracle import CVEBenchmarkReport, CVEResult, UngradedStatus


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


def render_measurement_lines(report: CVEBenchmarkReport) -> list[str]:
    return [] if report.measurement is None else [render_measurement(report.measurement)]


def _render_costs(report: CVEBenchmarkReport) -> list[str]:
    # A target with no report was billed nothing, so it has no row.
    if not report.costs:
        return []
    return ["", render_cost_title(report), "", *render_cost_table(report.costs)]


def render_cost_title(report: CVEBenchmarkReport) -> str:
    return f"Cost per target, all attempts, dollars at the prices as of {report.prices_as_of}:"


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
        run_fraction(result.detected_runs, result.runs),
        result.miss_class or "-",
        run_fraction(result.aimed_runs, result.runs),
        run_fraction(result.fail_without_proof_runs, result.runs),
        result.awaited_capability or "-",
        result.note,
    ]
    return f"| {' | '.join(cells)} |"


def run_fraction(count: int, runs: int) -> str:
    return f"{count}/{runs}" if runs else "-"
