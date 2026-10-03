from typing import Any

from mcp_auditor.domain import AttackChain, ToolReport
from mcp_auditor.domain.models import AuditStep, RefusedStep
from mcp_auditor.graph.prompts import REDACTION_NOTICE
from tests.fakes import FakeLLM


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


def provider_usage_is_positive(result: dict[str, Any]) -> None:
    usage = result["audit_report"].provider_usage
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


def report_has_a_gap_of(report: ToolReport, requested: int, received: int) -> None:
    assert report.coverage_gap is not None
    assert report.coverage_gap.requested_cases == requested
    assert report.coverage_gap.received_cases == received


def report_has_no_gap(report: ToolReport) -> None:
    assert report.coverage_gap is None


def audit_report_has_refused_steps(
    result: dict[str, Any], expected: list[tuple[str, AuditStep]]
) -> None:
    _are_refused_steps(result["audit_report"].refused_steps, expected)


def state_has_refused_steps(result: dict[str, Any], expected: list[tuple[str, AuditStep]]) -> None:
    _are_refused_steps(result["refused_steps"], expected)


def _are_refused_steps(steps: list[RefusedStep], expected: list[tuple[str, AuditStep]]) -> None:
    assert [(step.tool_name, step.step) for step in steps] == expected


def every_prompt_has_the_redaction_notice(fake_llm: FakeLLM, expected_prompts: int) -> None:
    assert len(fake_llm.prompts) == expected_prompts
    assert all(REDACTION_NOTICE in prompt for prompt in fake_llm.prompts)


def no_prompt_holds(fake_llm: FakeLLM, text: str) -> None:
    assert fake_llm.prompts
    assert not any(text in prompt for prompt in fake_llm.prompts)
