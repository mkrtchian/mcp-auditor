from typing import Any

from mcp_auditor.domain import AttackChain, AuditCategory, EvalVerdict


def chain_judge_result_is(
    chain: AttackChain,
    tool_name: str,
    category: AuditCategory,
    payload: dict[str, Any],
    verdict: EvalVerdict,
) -> None:
    assert chain.judge_result is not None
    assert chain.judge_result.tool_name == tool_name
    assert chain.judge_result.category == category
    assert chain.judge_result.arguments == payload
    assert chain.judge_result.verdict == verdict
