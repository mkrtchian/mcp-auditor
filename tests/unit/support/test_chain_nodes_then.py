from typing import Any

from mcp_auditor.domain import AttackChain, AuditCategory, EvalVerdict
from mcp_auditor.domain.models import MissCause, ModelCallKind
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


def unreadable_call_recorded(result: dict[str, Any], kind: ModelCallKind) -> None:
    _one_missed_call(result, kind, MissCause.UNREADABLE_ANSWER)


def refused_call_recorded(result: dict[str, Any], kind: ModelCallKind) -> None:
    _one_missed_call(result, kind, MissCause.PROVIDER_REFUSAL)


def _one_missed_call(result: dict[str, Any], kind: ModelCallKind, cause: MissCause) -> None:
    [missed] = result["missed_model_calls"]
    assert (missed.tool_name, missed.kind, missed.cause) == (DEFAULT_TOOL_NAME, kind, cause)
