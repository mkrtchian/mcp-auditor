"""The markdown of a holdout report, rendered from the proof-free report model alone."""

from collections.abc import Mapping, Sequence

from evals.cve.detection.holdout_not_run import not_run_section
from evals.cve.detection.holdout_report import HoldoutReport
from evals.cve.detection.holdout_target_line import TargetLine
from evals.cve.holdout_report_lines import (
    conclusion_text,
    controls_section,
    health_facts,
    incomplete_runs_lines,
    run_cutoff_line,
    span,
)


def render_markdown(report: HoldoutReport) -> str:
    return "\n".join(
        [
            "# Holdout detection rate",
            "",
            f"Recorded at: {report.recorded_at}",
            "",
            f"Holdout detection rate: {report.holdout_detection_rate:.3f}"
            f" (95% Wilson {span(report.cited_interval)})",
            "",
            *_ladder_section(report),
            *_split_section(report),
            *controls_section(report.controls),
            *not_run_section(report.not_run, len(report.targets), report.second_pass),
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
    lines = [run_cutoff_line(report.run_cutoff)]
    lines += [
        f"- {line.side.value}: {line.number:.3f} ({span(line.interval)}), {line.targets} target(s)"
        for line in report.sides
    ]
    if report.contrast is None:
        lines.append("- contrast: not computed (a side has fewer than 5 targets)")
    else:
        lines.append(f"- contrast: {span(report.contrast)}")
        lines.append(f"- conclusion: {conclusion_text(report.conclusion)}")
    return ["## Split by cutoff side", *lines, ""]


def _health_section(targets: Sequence[TargetLine]) -> list[str]:
    """Report-only: one line per target whose server misbehaved or whose replay failed."""
    lines = [f"- {line.flaw_id}: {facts}" for line in targets if (facts := _health_facts(line))]
    return ["## Server health and replay", *lines, ""] if lines else []


def _health_facts(line: TargetLine) -> str:
    facts = health_facts(line)
    if line.unchecked_runs_by_reason:
        facts.append(f"replay unchecked: {_by_cause(line.unchecked_runs_by_reason)}")
    if line.replay_attempt_failures_by_cause:
        facts.append(f"replay attempt failures: {_by_cause(line.replay_attempt_failures_by_cause)}")
    return ", ".join(facts)


def _by_cause(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{cause} x{count}" for cause, count in sorted(counts.items()))


def _incomplete_runs_lines(report: HoldoutReport) -> list[str]:
    touched = [target.flaw_id for target in report.targets if target.incomplete_runs > 0]
    return incomplete_runs_lines(
        report.incomplete_run_count, touched, report.incomplete_runs_by_cause
    )


def _throttled_lines(report: HoldoutReport) -> list[str]:
    if report.throttled_requests == 0:
        return []
    return [
        f"Throttled by the model provider: {report.throttled_requests} requests"
        f" at concurrency {report.concurrency}"
    ]
