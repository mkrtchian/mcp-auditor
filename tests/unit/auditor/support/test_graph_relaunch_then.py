from typing import Any

from mcp_auditor.domain import CoverageGap, ToolReport
from mcp_auditor.domain.server_liveness import UnsentCause


def report_has_unsent_calls(
    report: ToolReport, cases: int, chains: int, cause: UnsentCause
) -> None:
    gap = report.coverage_gap
    assert gap is not None
    assert (gap.unsent_cases, gap.unsent_chains, gap.unsent_cause) == (cases, chains, cause)


def tools_left_in_server_down_gaps(
    result: dict[str, Any], tool_names: list[str], test_budget: int, chains: int
) -> None:
    left = result["audit_report"].tool_reports[-len(tool_names) :]
    assert [report.tool.name for report in left] == tool_names
    expected = CoverageGap(
        requested_cases=test_budget,
        received_cases=0,
        missing_categories=[],
        unsent_chains=chains,
        unsent_cause=UnsentCause.SERVER_DOWN,
    )
    assert all(report.coverage_gap == expected and not report.cases for report in left)
