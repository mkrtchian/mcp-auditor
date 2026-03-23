from typing import Any

from mcp_auditor.domain import ToolReport


def has_tool_reports(result: dict[str, Any], expected_count: int) -> None:
    assert len(result["audit_report"].tool_reports) == expected_count


def tool_report_at(result: dict[str, Any], index: int) -> ToolReport:
    return result["audit_report"].tool_reports[index]


def report_has_cases(report: ToolReport, expected_count: int) -> None:
    assert len(report.cases) == expected_count


def report_is_for_tool(report: ToolReport, tool_name: str) -> None:
    assert report.tool.name == tool_name


def attack_context_is_non_empty(result: dict[str, Any]) -> None:
    ctx = result["attack_context"]
    has_content = (
        ctx.db_engine is not None
        or ctx.framework is not None
        or ctx.language is not None
        or ctx.exposed_internals
        or ctx.effective_payloads
        or ctx.observations
    )
    assert has_content, f"Expected non-empty attack context, got {ctx}"
