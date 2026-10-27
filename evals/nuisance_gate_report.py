"""The report of a nuisance gate run. Unlike the nuisance figure's report, it carries the flagged
tool names and goes with a per-case export, because the gate's servers may be read
(nuisance-rule.md, Reading)."""

from collections.abc import Sequence

from pydantic import BaseModel

from evals.cell_grid import replay_fraction
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_counter import flagged_tools, raw_fail_count
from evals.nuisance_counting import counted_tools
from evals.nuisance_gate import NuisanceGateResult, ServerComparison
from evals.nuisance_gate_baseline import NuisanceGateConditions
from evals.nuisance_gate_session_model import NuisanceGateSession
from evals.nuisance_results import FigureExit


class GateServerLine(BaseModel):
    server_package: str
    flagged_per_run: list[bool]
    flagged_tools_per_run: list[list[str]]
    raw_fail_per_run: list[int]  # report-only, never compared


class NuisanceGateReport(BaseModel):
    conditions: NuisanceGateConditions
    commit: str
    dirty: bool
    concurrency: int
    throttled_requests: int
    servers: list[GateServerLine]
    not_run: dict[str, str]
    not_admitted: list[str]
    outside_gate: list[FigureExit]
    orphans: list[str]
    gate: NuisanceGateResult
    written: list[str]
    recording_refused: list[str]


def server_lines(
    session: NuisanceGateSession, servers: Sequence[AdmittedServer]
) -> list[GateServerLine]:
    lines: list[GateServerLine] = []
    for server in servers:
        audits = [a for a in session.audits if a.server_package == server.server_package]
        if not audits:
            continue
        counted = counted_tools(server)
        lines.append(
            GateServerLine(
                server_package=server.server_package,
                flagged_per_run=[audit.flagged for audit in audits],
                flagged_tools_per_run=[
                    sorted(flagged_tools(audit.report, counted)) for audit in audits
                ],
                raw_fail_per_run=[raw_fail_count(audit.report) for audit in audits],
            )
        )
    return lines


def render_markdown(report: NuisanceGateReport) -> str:
    return "\n".join(
        [
            "# Nuisance gate",
            "",
            *render_conditions(report),
            *render_throttled(report),
            "",
            f"Verdict: **{report.gate.verdict.value}**",
            *[f"- {reason}" for reason in report.gate.reasons],
            "",
            *_servers_section(report),
            *_listed("## Not run", [f"{p}: {why}" for p, why in report.not_run.items()]),
            *_listed("## Not admitted", report.not_admitted),
            *_listed(
                "## Outside the gate",
                [f"{e.server_package}: {e.reason}" for e in report.outside_gate],
            ),
            *_listed("## Orphaned baseline files", report.orphans),
            *_listed(
                "## Recording",
                [*report.written, *(f"refused: {why}" for why in report.recording_refused)],
            ),
        ]
    )


def render_conditions(report: NuisanceGateReport) -> list[str]:
    dirty = " (dirty tree)" if report.dirty else ""
    conditions = report.conditions
    return [
        f"Commit: {report.commit}{dirty}",
        f"Model: {conditions.provider} {conditions.model}, judge {conditions.judge_model}, "
        f"{conditions.runs} run(s), concurrency {report.concurrency}",
    ]


def render_throttled(report: NuisanceGateReport) -> list[str]:
    if report.throttled_requests == 0:
        return []
    return [
        f"Throttled by the model provider: {report.throttled_requests} requests "
        f"at concurrency {report.concurrency}"
    ]


def _servers_section(report: NuisanceGateReport) -> list[str]:
    lines = {line.server_package: line for line in report.servers}
    rows = [
        _row(comparison, lines.get(comparison.server_package)) for comparison in report.gate.servers
    ]
    return [
        "## Servers",
        "",
        "| Server | Outcome | Baseline | Runs | Replays | Detail |",
        "|---|---|---|---|---|---|",
        *rows,
        "",
        GATE_LEGEND,
        "",
    ]


GATE_LEGEND = (
    "Runs: A an alarm on a counted tool, . none. "
    "Baseline: every run its file holds, both recordings once confirmed. "
    "Replays: the alarm reproduced in k of n replays."
)


def _row(comparison: ServerComparison, line: GateServerLine | None) -> str:
    cells = [
        comparison.server_package,
        comparison.outcome.value,
        server_letters(comparison.baseline_runs) or "-",
        server_letters(comparison.candidate_runs) or "-",
        replay_fraction(comparison.replays),
        server_detail(comparison, line).replace("|", "\\|"),
    ]
    return f"| {' | '.join(cells)} |"


def server_letters(flagged: Sequence[bool]) -> str:
    return "".join("A" if alarm else "." for alarm in flagged)


def server_detail(comparison: ServerComparison, line: GateServerLine | None) -> str:
    runs = [] if line is None else _flagged_tools(line)
    parts = [*([comparison.detail] if comparison.detail else []), *runs]
    return "; ".join(parts) or "-"


def _flagged_tools(line: GateServerLine) -> list[str]:
    return [
        f"run {index + 1}: {', '.join(tools)}"
        for index, tools in enumerate(line.flagged_tools_per_run)
        if tools
    ]


def _listed(header: str, items: Sequence[str]) -> list[str]:
    return [header, *([f"- {item}" for item in items] or ["- none"]), ""]
