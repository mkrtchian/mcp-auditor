from typing import Any


def each_tool_audited_once(result: dict[str, Any], tool_names: list[str]) -> None:
    reports = result["audit_report"].tool_reports
    assert [report.tool.name for report in reports] == tool_names
