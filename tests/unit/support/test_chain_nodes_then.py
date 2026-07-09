from typing import Any

from mcp_auditor.domain import AttackChain, AuditCategory, ChainGoal, EvalVerdict


def pending_chains_count(result: dict[str, Any], expected: int) -> None:
    assert len(result["pending_chains"]) == expected


def current_chain_goal_is(result: dict[str, Any], goal: ChainGoal) -> None:
    assert result["current_chain_goal"] == goal


def completed_chains_count(result: dict[str, Any], expected: int) -> None:
    assert len(result["completed_chains"]) == expected


def chain_has_steps(chain: AttackChain, expected: int) -> None:
    assert len(chain.steps) == expected


def chain_eval_result_is(
    chain: AttackChain,
    tool_name: str,
    category: AuditCategory,
    payload: dict[str, Any],
    verdict: EvalVerdict,
) -> None:
    assert chain.eval_result is not None
    assert chain.eval_result.tool_name == tool_name
    assert chain.eval_result.category == category
    assert chain.eval_result.payload == payload
    assert chain.eval_result.verdict == verdict
