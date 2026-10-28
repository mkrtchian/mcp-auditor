"""The markdown of a holdout report, rendered from the proof-free report model alone."""

from collections.abc import Mapping, Sequence

from evals.holdout_not_run import not_run_section
from evals.holdout_report import (
    ConclusionLine,
    HoldoutReport,
    IntervalModel,
    RunCutoffModel,
    TargetLine,
)


def render_markdown(report: HoldoutReport) -> str:
    return "\n".join(
        [
            "# Holdout capability",
            "",
            f"Recorded at: {report.recorded_at}",
            "",
            f"Capability: {report.primary_number:.3f} (95% Wilson {_span(report.cited_interval)})",
            "",
            *_ladder_section(report),
            *_split_section(report),
            *_controls_section(report),
            *not_run_section(report.not_run, len(report.targets)),
            *_health_section(report.targets),
            *_incomplete_runs_lines(report),
            *_throttled_lines(report),
            f"Total cost: ${report.total_cost:.2f}",
        ]
    )


def _ladder_section(report: HoldoutReport) -> list[str]:
    lines = [
        f"- {detected} detecting run(s): {count} target(s)"
        for detected, count in sorted(report.ladder.items(), reverse=True)
    ]
    return ["## Ladder", *lines, ""]


def _split_section(report: HoldoutReport) -> list[str]:
    lines = [_run_cutoff_line(report.run_cutoff)]
    lines += [
        f"- {line.side.value}: {line.number:.3f} ({_span(line.interval)}), {line.targets} target(s)"
        for line in report.sides
    ]
    if report.contrast is None:
        lines.append("- contrast: not computed (a side has fewer than 5 targets)")
    else:
        lines.append(f"- contrast: {_span(report.contrast)}")
        lines.append(f"- conclusion: {_conclusion_text(report.conclusion)}")
    return ["## Split by cutoff side", *lines, ""]


def _run_cutoff_line(cutoff: RunCutoffModel) -> str:
    line = f"- run cutoff: {cutoff.date} ({cutoff.type}), {cutoff.model}, {cutoff.source}"
    return line if cutoff.note is None else f"{line}, note: {cutoff.note}"


def _conclusion_text(conclusion: ConclusionLine | None) -> str:
    if conclusion is None:
        return "none"
    if conclusion.inconclusive:
        methods = ", ".join(method.method for method in conclusion.disagreeing)
        return f"inconclusive (disagreeing: {methods})"
    return f"{conclusion.placement} zero"


def _controls_section(report: HoldoutReport) -> list[str]:
    lines = [f"- {name}: {_span(interval)}" for name, interval in sorted(report.controls.items())]
    return ["## Controls", *lines, ""]


def _health_section(targets: Sequence[TargetLine]) -> list[str]:
    """Report-only: one line per target whose server misbehaved or whose replay failed."""
    lines = [f"- {line.cve_id}: {facts}" for line in targets if (facts := _health_facts(line))]
    return ["## Server health and replay", *lines, ""] if lines else []


def _health_facts(line: TargetLine) -> str:
    facts: list[str] = []
    if line.non_protocol_lines:
        facts.append(f"non-protocol lines {line.non_protocol_lines}")
    if line.lost_connection_responses:
        facts.append(f"connection lost on {line.lost_connection_responses} call(s)")
    if line.unchecked_runs_by_reason:
        facts.append(f"replay unchecked: {_by_cause(line.unchecked_runs_by_reason)}")
    if line.replay_attempt_failures_by_cause:
        facts.append(f"replay attempt failures: {_by_cause(line.replay_attempt_failures_by_cause)}")
    return ", ".join(facts)


def _by_cause(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{cause} x{count}" for cause, count in sorted(counts.items()))


_INCOMPLETE_RUNS = "Incomplete runs (a step refused or unreadable)"


def _incomplete_runs_lines(report: HoldoutReport) -> list[str]:
    """The count with the targets it touches (holdout-rule.md:249), derived from the per-target
    incomplete-run counts, then one line per cause."""
    touched = [target.cve_id for target in report.targets if target.incomplete_runs > 0]
    count = f"{_INCOMPLETE_RUNS}: {report.incomplete_run_count}"
    by_cause = [
        f"- {cause}: {runs} run(s)"
        for cause, runs in sorted(report.incomplete_runs_by_cause.items())
    ]
    return [f"{count} ({', '.join(touched)})" if touched else count, *by_cause]


def _throttled_lines(report: HoldoutReport) -> list[str]:
    if report.throttled_requests == 0:
        return []
    return [
        f"Throttled by the model provider: {report.throttled_requests} requests"
        f" at concurrency {report.concurrency}"
    ]


def _span(interval: IntervalModel) -> str:
    return f"{interval.low:.3f} to {interval.high:.3f}"
