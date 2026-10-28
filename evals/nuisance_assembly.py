"""The result of one admitted server, assembled from its run audits: pure, no aggregate computed
here, every count a property of the result."""

from collections.abc import Mapping, Sequence

from evals.cve_units import JudgeCategory
from evals.holdout_draw import DrawEntry
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_audit import NuisanceAudit, incomplete_causes, is_incomplete
from evals.nuisance_counter import flagged_tools, raw_fail_count
from evals.nuisance_counting import counted_flaws, counted_tools, flaw_counted_tools
from evals.nuisance_results import NuisanceRunStatus, NuisanceServerResult
from evals.probe import call_cost
from evals.probe_candidates import Prices


def assemble_server(
    server: AdmittedServer,
    audits: Sequence[NuisanceAudit],
    draw_order: Sequence[DrawEntry],
    prices: tuple[Prices, Prices],
) -> NuisanceServerResult:
    counted = counted_tools(server)
    split = split_flaw_of(server, draw_order)
    split_tools = frozenset[str]() if split is None else _flaw_tools(server, split.identifier)
    gen_price, judge_price = prices
    reports = [audit.report for audit in audits]
    return NuisanceServerResult(
        server_package=server.server_package,
        split_flaw=None if split is None else split.identifier,
        split_disclosure_date=None if split is None else split.disclosure_date,
        statuses=tuple(_run_status(audit, counted, split_tools) for audit in audits),
        counted_tools_count=len(counted),
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


def _run_status(
    audit: NuisanceAudit,
    counted: Mapping[str, frozenset[JudgeCategory]],
    split_tools: frozenset[str],
) -> NuisanceRunStatus:
    report = audit.report
    flagged = flagged_tools(report, counted)
    return NuisanceRunStatus(
        flagged=bool(flagged),
        split_flagged=bool(flagged & split_tools),
        incomplete=is_incomplete(report),
        raw_fail_count=raw_fail_count(report),
        non_protocol_lines=audit.health.non_protocol_lines,
        lost_connection_responses=audit.health.lost_connection_responses,
        miss_causes=sorted(cause.value for cause in incomplete_causes(report)),
    )
