from typing import Any

from mcp_auditor.domain import AttackChain, ToolReport


def has_tool_reports(result: dict[str, Any], expected_count: int) -> None:
    assert len(result["audit_report"].tool_reports) == expected_count


def tool_report_at(result: dict[str, Any], index: int) -> ToolReport:
    return result["audit_report"].tool_reports[index]


def report_has_cases(report: ToolReport, expected_count: int) -> None:
    assert len(report.cases) == expected_count


def report_is_for_tool(report: ToolReport, tool_name: str) -> None:
    assert report.tool.name == tool_name


def report_has_no_chains(report: ToolReport) -> None:
    assert report.chains == []


def report_has_chains(report: ToolReport, expected_count: int) -> None:
    assert len(report.chains) == expected_count


def chain_has_eval_result(chain: AttackChain) -> None:
    assert chain.eval_result is not None


def token_usage_is_positive(result: dict[str, Any]) -> None:
    usage = result["audit_report"].token_usage
    assert usage.input_tokens > 0
    assert usage.output_tokens > 0


def attack_context_is_non_empty(result: dict[str, Any]) -> None:
    context = result["attack_context"]
    has_content = (
        context.db_engine is not None
        or context.framework is not None
        or context.language is not None
        or context.exposed_internals
        or context.effective_payloads
        or context.observations
    )
    assert has_content, f"Expected non-empty attack context, got {context}"
