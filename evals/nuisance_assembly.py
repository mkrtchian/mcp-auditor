"""The result of one admitted server, assembled from its run audits: pure, no aggregate computed
here, every count a property of the result."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from evals.cve.census.draw_order import DrawEntry
from evals.cve_units import JudgeCategory
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_audit import NuisanceAudit, incomplete_causes, is_incomplete
from evals.nuisance_counter import fail_count_on, flagged_tools, raw_fail_count
from evals.nuisance_counting import (
    counted_flaws,
    counted_tools,
    declared_function_tools,
    flaw_counted_tools,
)
from evals.nuisance_results import NuisanceRunStatus, NuisanceServerResult
from evals.probe.analysis import call_cost
from evals.probe.candidates import Prices


def assemble_server(
    server: AdmittedServer,
    audits: Sequence[NuisanceAudit],
    draw_order: Sequence[DrawEntry],
    prices: tuple[Prices, Prices],
) -> NuisanceServerResult:
    split = split_flaw_of(server, draw_order)
    counting = ServerCounting(
        counted=counted_tools(server),
        split_tools=frozenset() if split is None else _flaw_tools(server, split.identifier),
        declared_function=declared_function_tools(server),
    )
    gen_price, judge_price = prices
    reports = [audit.report for audit in audits]
    return NuisanceServerResult(
        server_package=server.server_package,
        split_flaw=None if split is None else split.identifier,
        split_disclosure_date=None if split is None else split.disclosure_date,
        statuses=tuple(_run_status(audit, counting) for audit in audits),
        counted_tools_count=len(counting.counted),
        tools_count=len(reports[0].tool_reports),
        run_cost=sum(
            call_cost(report.generator_usage, gen_price)
            + call_cost(report.judge_usage, judge_price)
            for report in reports
        ),
    )


def split_flaw_of(server: AdmittedServer, draw_order: Sequence[DrawEntry]) -> DrawEntry | None:
    """The first draw-order entry that is a counted flaw of the server with a counted tool."""
    with_tools = {flaw.flaw for flaw in counted_flaws(server) if flaw_counted_tools(flaw)}
    return next((entry for entry in draw_order if entry.identifier in with_tools), None)


def _flaw_tools(server: AdmittedServer, identifier: str) -> frozenset[str]:
    (flaw,) = [flaw for flaw in counted_flaws(server) if flaw.flaw == identifier]
    return flaw_counted_tools(flaw)


@dataclass(frozen=True)
class ServerCounting:
    """The tool sets a server's runs are read against, derived once per server."""

    counted: Mapping[str, frozenset[JudgeCategory]]
    split_tools: frozenset[str]
    declared_function: Mapping[str, frozenset[JudgeCategory]]


def _run_status(audit: NuisanceAudit, counting: ServerCounting) -> NuisanceRunStatus:
    report = audit.report
    flagged = flagged_tools(report, counting.counted)
    return NuisanceRunStatus(
        flagged=bool(flagged),
        split_flagged=bool(flagged & counting.split_tools),
        incomplete=is_incomplete(report),
        raw_fail_count=raw_fail_count(report),
        declared_function_fail_count=fail_count_on(report, counting.declared_function),
        non_protocol_lines=audit.health.non_protocol_lines,
        lost_connection_responses=audit.health.lost_connection_responses,
        miss_causes=sorted(cause.value for cause in incomplete_causes(report)),
    )
