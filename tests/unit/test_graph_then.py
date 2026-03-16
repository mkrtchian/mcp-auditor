from typing import Any

from mcp_auditor.domain import ToolReport


def has_tool_reports(result: dict[str, Any], expected_count: int) -> None:
    assert len(result["audit_report"].tool_reports) == expected_count


def tool_report_at(result: dict[str, Any], index: int) -> ToolReport:
    return result["audit_report"].tool_reports[index]


def report_has_results(report: ToolReport, expected_count: int) -> None:
    assert len(report.results) == expected_count


def report_is_for_tool(report: ToolReport, tool_name: str) -> None:
    assert report.tool.name == tool_name


def token_usage_is_nonzero(result: dict[str, Any]) -> None:
    usage = result["audit_report"].token_usage
    assert usage.input_tokens > 0
    assert usage.output_tokens > 0
