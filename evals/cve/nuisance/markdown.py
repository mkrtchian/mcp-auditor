"""The markdown of a nuisance report, rendered from the proof-free report model alone."""

from collections.abc import Sequence

from evals.cve.detection.holdout_report import ConclusionLine, IntervalModel, RunCutoffModel
from evals.cve.nuisance.report import NotRunLine, NuisanceReport, ServerLine
from evals.cve.nuisance.results import DROPPED_RUN_REASONS, NotRunCause


def render_markdown(report: NuisanceReport) -> str:
    return "\n".join(
        [
            "# Nuisance suite",
            "",
            f"Recorded at: {report.recorded_at}",
            f"Commits: run {report.commit}, census {report.census_commit}, "
            f"walk record {report.walk_record_commit}",
            "",
            f"Holdout nuisance rate: at most {report.holdout_nuisance_rate:.3f}"
            f" (95% Wilson {_span(report.cited_interval)})",
            "",
            *_split_section(report),
            *_controls_section(report),
            *_servers_section(report.servers),
            *_raw_fail_section(report.servers),
            *_exits_section(report),
            *_not_run_section(report.not_run, len(report.servers), report.second_pass),
            *_health_section(report.servers),
            *_incomplete_runs_lines(report),
            *_throttled_lines(report),
            f"Total cost: ${report.total_cost:.2f}",
        ]
    )


def _split_section(report: NuisanceReport) -> list[str]:
    lines = [_run_cutoff_line(report.run_cutoff)]
    lines += [
        f"- {line.side.value}: {line.number:.3f} ({_span(line.interval)}), {line.servers} server(s)"
        for line in report.sides
    ]
    if report.contrast is None:
        lines.append("- contrast: not computed (a side has fewer than 5 servers)")
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


def _controls_section(report: NuisanceReport) -> list[str]:
    lines = [f"- {name}: {_span(interval)}" for name, interval in sorted(report.controls.items())]
    return ["## Controls", *lines, ""]


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
    """The standing exits the code derives, one row per reason. The rule's other exits (never
    fixed, no counted tool, spent by a reading, a fork of an excluded server) have no row the
    code derives and live in the log."""
    by_reason: dict[str, list[str]] = {}
    for line in report.exits:
        by_reason.setdefault(line.reason, []).append(line.server_package)
    lines = [
        f"- {reason}: {len(packages)} server(s): {', '.join(packages)}"
        for reason, packages in by_reason.items()
    ]
    return ["## Exits", *(lines or ["- none"]), ""]


_BENIGN_CALL_FAILED = "benign call failed before the runs"


def _not_run_section(
    not_run: Sequence[NotRunLine], audited_servers: int, second_pass: dict[str, str]
) -> list[str]:
    """The servers left out of N for this run only, unlike the exits: one row per cause present,
    then every server with its reason, closed by the servers that ran only after a clean solo
    second pass of the vet, each with its first pass's reason. The two in-run causes are counted
    against the servers launched, the benign-call failures plainly since they were never launched
    for the runs. The rule's other exits (never fixed, no counted tool, spent by a reading, a fork
    of an excluded server) have no row the code derives and live in the log."""
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
        f"- {line.server_package}: {facts}" for line in servers if (facts := _health_facts(line))
    ]
    return ["## Server health", *lines, ""] if lines else []


def _health_facts(line: ServerLine) -> str:
    facts: list[str] = []
    if line.non_protocol_lines:
        facts.append(f"non-protocol lines {line.non_protocol_lines}")
    if line.lost_connection_responses:
        facts.append(f"connection lost on {line.lost_connection_responses} call(s)")
    if line.relaunches:
        facts.append(f"relaunched {line.relaunches} time(s)")
    if line.unsent_calls:
        facts.append(f"{line.unsent_calls} call(s) not sent")
    if line.cut_responses:
        facts.append(f"{line.cut_responses} response(s) shown cut")
    return ", ".join(facts)


_INCOMPLETE_RUNS = "Incomplete runs (a model call missed: refused, unreadable or too long)"


def _incomplete_runs_lines(report: NuisanceReport) -> list[str]:
    touched = [line.server_package for line in report.servers if line.incomplete_runs > 0]
    count = f"{_INCOMPLETE_RUNS}: {report.incomplete_run_count}"
    by_cause = [
        f"- {cause}: {runs} run(s)"
        for cause, runs in sorted(report.incomplete_runs_by_cause.items())
    ]
    return [f"{count} ({', '.join(touched)})" if touched else count, *by_cause]


def _throttled_lines(report: NuisanceReport) -> list[str]:
    if report.throttled_requests == 0:
        return []
    return [
        f"Throttled by the model provider: {report.throttled_requests} requests"
        f" at concurrency {report.concurrency}"
    ]


def _span(interval: IntervalModel) -> str:
    return f"{interval.low:.3f} to {interval.high:.3f}"
