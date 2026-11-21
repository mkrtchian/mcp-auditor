from typing import Any

from mcp_auditor.domain import ProviderUsage, ToolReport
from mcp_auditor.graph.prompts import REDACTION_NOTICE
from tests.fakes import FakeLLM, FakeMCPClient


def has_tool_reports(result: dict[str, Any], expected_count: int) -> None:
    assert len(result["audit_report"].tool_reports) == expected_count


def report_is_for_tool(report: ToolReport, tool_name: str) -> None:
    assert report.tool.name == tool_name


def one_case_blocked_unjudged_and_not_called(report: ToolReport, client: FakeMCPClient) -> None:
    [blocked] = [case for case in report.cases if case.blocked_reason is not None]
    assert blocked.judge_result is None
    assert len([case for case in report.cases if case.judge_result is not None]) == 1
    assert len(client.calls) == 1


def report_splits_usage(
    result: dict[str, Any],
    judge_calls: int,
    judge_usage: ProviderUsage,
    generator_calls: int,
    generator_usage: ProviderUsage,
) -> None:
    report = result["audit_report"]
    assert report.judge_usage == _times(judge_usage, judge_calls)
    assert report.generator_usage == _times(generator_usage, generator_calls)
    assert report.provider_usage == report.judge_usage.add(report.generator_usage)


def report_bills_to_chains(result: dict[str, Any], chain_calls: list[ProviderUsage]) -> None:
    report = result["audit_report"]
    chain_usage = _sum(chain_calls)
    assert report.chain_usage == chain_usage
    assert report.single_step_usage == report.provider_usage.sub(chain_usage)
    assert report.single_step_usage.input_tokens > 0


def _times(usage: ProviderUsage, count: int) -> ProviderUsage:
    return _sum([usage] * count)


def _sum(usages: list[ProviderUsage]) -> ProviderUsage:
    total = ProviderUsage()
    for usage in usages:
        total = total.add(usage)
    return total


def every_prompt_has_the_redaction_notice(fake_llm: FakeLLM, expected_prompts: int) -> None:
    assert len(fake_llm.prompts) == expected_prompts
    assert all(REDACTION_NOTICE in prompt for prompt in fake_llm.prompts)


def no_prompt_holds(fake_llm: FakeLLM, text: str) -> None:
    assert fake_llm.prompts
    assert not any(text in prompt for prompt in fake_llm.prompts)
