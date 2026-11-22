from typing import Any

from mcp_auditor.domain.models import ToolReport


def tool_report_at(result: dict[str, Any], index: int) -> ToolReport:
    return result["audit_report"].tool_reports[index]


def report_has_judged_chains(report: ToolReport, expected_count: int) -> None:
    assert len(report.chains) == expected_count
    assert all(chain.judge_result is not None for chain in report.chains)


def report_has_a_gap_of(report: ToolReport, requested: int, received: int) -> None:
    assert report.coverage_gap is not None
    assert report.coverage_gap.requested_cases == requested
    assert report.coverage_gap.received_cases == received
