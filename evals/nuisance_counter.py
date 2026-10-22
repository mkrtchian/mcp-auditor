"""The nuisance verdict of one audit report: which counted tools it flags, and its raw count.

It reads only these domain fields: `tool_reports`, `tool.name`, `cases`, `chains`,
`eval_result.verdict`, `eval_result.category`.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from evals import nuisance_counting
from evals.baseline import fingerprint_sources
from evals.cve_units import JudgeCategory, Verdict
from mcp_auditor.domain.models import AuditReport, EvalResult

# The grammar is left out: its own fingerprint covers the VALID_CATEGORIES read here. The two
# modules that decide what counts, the verdict predicate and the counted-tool derivation, are in.
_COUNTER_PATHS = (Path(__file__), Path(nuisance_counting.__file__))


@dataclass(frozen=True)
class ToolVerdict:
    tool: str
    category: JudgeCategory | None
    verdict: Verdict | None


def tool_verdicts(report: AuditReport) -> list[ToolVerdict]:
    verdicts: list[ToolVerdict] = []
    for tool_report in report.tool_reports:
        name = tool_report.tool.name
        verdicts += [_verdict(name, case.eval_result) for case in tool_report.cases]
        # A chain is attributed to the tool it was planned against, which every step of it calls.
        verdicts += [_verdict(name, chain.eval_result) for chain in tool_report.chains]
    return verdicts


def flagged_tools(
    report: AuditReport, counted: Mapping[str, frozenset[JudgeCategory]]
) -> frozenset[str]:
    return frozenset(
        verdict.tool
        for verdict in tool_verdicts(report)
        if verdict.verdict is Verdict.FAIL
        and verdict.tool in counted
        and verdict.category in counted[verdict.tool]
    )


def raw_fail_count(report: AuditReport) -> int:
    return sum(verdict.verdict is Verdict.FAIL for verdict in tool_verdicts(report))


def counter_fingerprint() -> str:
    return fingerprint_sources([path.read_text() for path in _COUNTER_PATHS])


def _verdict(tool: str, result: EvalResult | None) -> ToolVerdict:
    if result is None:
        return ToolVerdict(tool, None, None)
    return ToolVerdict(tool, JudgeCategory(result.category.value), Verdict(result.verdict.value))
