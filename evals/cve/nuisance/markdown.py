"""The markdown of a nuisance report, rendered from the proof-free report model alone."""

from collections.abc import Sequence

from evals.cve.holdout_report_lines import (
    conclusion_text,
    controls_section,
    health_facts,
    incomplete_runs_lines,
    run_cutoff_line,
    span,
)
from evals.cve.nuisance.exits import EXIT_REASON_TEXTS, ExitReason
from evals.cve.nuisance.report import NotRunLine, NuisanceReport, ServerLine
from evals.cve.nuisance.results import DROPPED_RUN_REASONS, NotRunCause
from evals.eval_display import throttled_lines


def render_markdown(report: NuisanceReport) -> str:
    return "\n".join(
        [
            "# Nuisance suite",
            "",
            f"Recorded at: {report.recorded_at}",
            f"Commits: run {report.commit}, census {report.census_commit}, "
            f"walk record {report.walk_record_commit}, admission {report.admission_commit}",
            "",
            f"Holdout nuisance rate: at most {report.holdout_nuisance_rate:.3f}"
            f" (95% Wilson {span(report.cited_interval)})",
            "",
            *_split_section(report),
            *controls_section(report.controls),
            *_servers_section(report.servers),
            *_raw_fail_section(report.servers),
            *_exits_section(report),
            *_not_run_section(report.not_run, len(report.servers), report.second_pass),
            *_health_section(report.servers),
            *_incomplete_runs_lines(report),
            *throttled_lines(report.throttled_requests, report.concurrency),
            f"Total cost: ${report.total_cost:.2f}",
        ]
    )


def _split_section(report: NuisanceReport) -> list[str]:
    lines = [run_cutoff_line(report.run_cutoff)]
    lines += [
        f"- {line.side.value}: {line.number:.3f} ({span(line.interval)}), {line.servers} server(s)"
        for line in report.sides
    ]
    if report.contrast is None:
        lines.append("- contrast: not computed (a side has fewer than 5 servers)")
    else:
        lines.append(f"- contrast: {span(report.contrast)}")
        lines.append(f"- conclusion: {conclusion_text(report.conclusion)}")
    return ["## Split by cutoff side", *lines, ""]


def _servers_section(servers: Sequence[ServerLine]) -> list[str]:
    lines = [
        f"- {line.server_package}: flagged share {line.flagged_share:.3f}, "
        f"{', '.join('flagged' if flagged else 'not flagged' for flagged in line.flagged_per_run)}"
        f", incomplete runs {line.incomplete_runs}, "
        f"counted tools {line.counted_tools_count} of {line.tools_count}, cost ${line.cost:.2f}"
        for line in servers
    ]
    return ["## Servers", *lines, ""]


def _raw_fail_section(servers: Sequence[ServerLine]) -> list[str]:
    lines = [
        f"- {line.server_package}: {_counts(line.raw_fail_per_run)} (on the tools left out by "
        f"their declared function: {_counts(line.declared_function_fail_per_run)})"
        for line in servers
    ]
    return ["## Raw FAIL count (report-only, never compared)", *lines, ""]


def _counts(per_run: Sequence[int]) -> str:
    return ", ".join(str(count) for count in per_run)


def _exits_section(report: NuisanceReport) -> list[str]:
    """The servers outside the nuisance holdout layer, one row per reason of the rule in its order,
    a reason with none included, so two runs read side by side, the exits the nuisance walk derives
    and those the admission records alike. The reached servers whose admission is pending close
    the section: no reason of the rule holds for them yet."""
    by_reason: dict[ExitReason, list[str]] = {reason: [] for reason in ExitReason}
    for line in report.exits:
        by_reason[line.reason].append(line.server_package)
    lines = [
        _server_count_line(EXIT_REASON_TEXTS[reason], packages)
        for reason, packages in by_reason.items()
    ]
    if report.pending_admission:
        lines.append(_server_count_line(_ADMISSION_PENDING, report.pending_admission))
    return ["## Exits", *lines, ""]


_ADMISSION_PENDING = "admission pending (not an exit of the rule)"


def _server_count_line(label: str, packages: Sequence[str]) -> str:
    count = f"- {label}: {len(packages)} server(s)"
    return f"{count}: {', '.join(packages)}" if packages else count


_BENIGN_CALL_FAILED = "benign call failed before the runs"


def _not_run_section(
    not_run: Sequence[NotRunLine], audited_servers: int, second_pass: dict[str, str]
) -> list[str]:
    """The servers left out of N for this run only, unlike the exits: one row per cause present,
    then every server with its reason, closed by the servers that ran only after a clean solo
    second pass of the vet, each with its first pass's reason. The two in-run causes are counted
    against the servers launched, the benign-call failures plainly since they were never launched
    for the runs."""
    if not not_run:
        return ["## Not run", "- none", *_second_pass_lines(second_pass), ""]
    by_cause: dict[NotRunCause, list[str]] = {}
    for line in not_run:
        by_cause.setdefault(line.cause, []).append(line.server_package)
    launched = audited_servers + sum(len(by_cause.get(cause, [])) for cause in DROPPED_RUN_REASONS)
    counts = [
        f"- {len(packages)} of the {launched} server(s) launched: {reason}: {', '.join(packages)}"
        for cause, reason in DROPPED_RUN_REASONS.items()
        if (packages := by_cause.get(cause))
    ]
    if benign := by_cause.get(NotRunCause.BENIGN_CALL_FAILED):
        counts.append(f"- {_BENIGN_CALL_FAILED}: {len(benign)} server(s): {', '.join(benign)}")
    servers = [f"- {line.server_package}: {line.reason}" for line in not_run]
    return ["## Not run", *counts, *servers, *_second_pass_lines(second_pass), ""]


def _second_pass_lines(second_pass: dict[str, str]) -> list[str]:
    return [
        f"- {package}: run after a clean solo second pass of the vet (first pass: {reason})"
        for package, reason in second_pass.items()
    ]


def _health_section(servers: Sequence[ServerLine]) -> list[str]:
    """Report-only: one line per server with a non-zero health count."""
    lines = [
        f"- {line.server_package}: {facts}"
        for line in servers
        if (facts := ", ".join(health_facts(line)))
    ]
    return ["## Server health", *lines, ""] if lines else []


def _incomplete_runs_lines(report: NuisanceReport) -> list[str]:
    touched = [line.server_package for line in report.servers if line.incomplete_runs > 0]
    return incomplete_runs_lines(
        report.incomplete_run_count, touched, report.incomplete_runs_by_cause
    )
