from typing import Any

from mcp_auditor.domain.server_liveness import UnsentCause


def each_tool_audited_once(result: dict[str, Any], tool_names: list[str]) -> None:
    reports = result["audit_report"].tool_reports
    assert [report.tool.name for report in reports] == tool_names


def no_tool_in_a_server_down_gap(result: dict[str, Any]) -> None:
    gaps = [report.coverage_gap for report in result["audit_report"].tool_reports]
    assert all(gap is None or gap.unsent_cause is not UnsentCause.SERVER_DOWN for gap in gaps)


def no_tool_has_a_gap(result: dict[str, Any]) -> None:
    assert all(report.coverage_gap is None for report in result["audit_report"].tool_reports)
