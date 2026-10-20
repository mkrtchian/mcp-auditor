from typing import Any

from mcp_auditor.domain import AttackChain, AuditCategory, EvalVerdict
from mcp_auditor.domain.models import AuditStep, MissCause
from tests.unit.support.test_chain_nodes_given import DEFAULT_TOOL_NAME


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


def unreadable_step_recorded(result: dict[str, Any], step: AuditStep) -> None:
    _one_missed_step(result, step, MissCause.UNREADABLE_ANSWER)


def refused_step_recorded(result: dict[str, Any], step: AuditStep) -> None:
    _one_missed_step(result, step, MissCause.PROVIDER_REFUSAL)


def _one_missed_step(result: dict[str, Any], step: AuditStep, cause: MissCause) -> None:
    [missed] = result["missed_steps"]
    assert (missed.tool_name, missed.step, missed.cause) == (DEFAULT_TOOL_NAME, step, cause)
