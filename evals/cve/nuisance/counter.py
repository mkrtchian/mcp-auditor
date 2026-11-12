"""What the counter reads in one audit report: which counted tools it flags, its raw count and
the part of it on a given set of tools.

It reads only these domain fields: `tool_reports`, `tool.name`, `cases`, `chains`,
`judge_result.verdict`, `judge_result.category`.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from evals.baseline import fingerprint_sources
from evals.cve.nuisance import counting
from evals.cve.units import JudgeCategory, Verdict
from mcp_auditor.domain.models import AuditReport, JudgeResult

# The grammar is left out: its own fingerprint covers the VALID_CATEGORIES read here. The two
# modules that decide what counts, the verdict predicate and the counted-tool derivation, are in.
_COUNTER_PATHS = (Path(__file__), Path(counting.__file__))


@dataclass(frozen=True)
class ToolVerdict:
    tool: str
    category: JudgeCategory | None
    verdict: Verdict | None


def tool_verdicts(report: AuditReport) -> list[ToolVerdict]:
    verdicts: list[ToolVerdict] = []
    for tool_report in report.tool_reports:
        name = tool_report.tool.name
        verdicts += [_verdict(name, case.judge_result) for case in tool_report.cases]
        # A chain is attributed to the tool it was planned against, which every step of it calls.
        verdicts += [_verdict(name, chain.judge_result) for chain in tool_report.chains]
    return verdicts


def _verdict(tool: str, result: JudgeResult | None) -> ToolVerdict:
    if result is None:
        return ToolVerdict(tool, None, None)
    return ToolVerdict(tool, JudgeCategory(result.category.value), Verdict(result.verdict.value))


def flagged_tools(
    report: AuditReport, counted: Mapping[str, frozenset[JudgeCategory]]
) -> frozenset[str]:
    return frozenset(
        verdict.tool for verdict in tool_verdicts(report) if _fails_on(verdict, counted)
    )


def fail_count_on(report: AuditReport, tools: Mapping[str, frozenset[JudgeCategory]]) -> int:
    return sum(_fails_on(verdict, tools) for verdict in tool_verdicts(report))


def _fails_on(verdict: ToolVerdict, tools: Mapping[str, frozenset[JudgeCategory]]) -> bool:
    return (
        verdict.verdict is Verdict.FAIL
        and verdict.tool in tools
        and verdict.category in tools[verdict.tool]
    )


def raw_fail_count(report: AuditReport) -> int:
    return sum(verdict.verdict is Verdict.FAIL for verdict in tool_verdicts(report))


def counter_fingerprint() -> str:
    return fingerprint_sources([path.read_text() for path in _COUNTER_PATHS])
