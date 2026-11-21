from typing import Any

from mcp_auditor.domain.models import MissCause, ModelCallKind
from tests.unit.auditor.support.chain_states import DEFAULT_TOOL_NAME


def unreadable_call_recorded(result: dict[str, Any], kind: ModelCallKind) -> None:
    _one_missed_call(result, kind, MissCause.UNREADABLE_ANSWER)


def refused_call_recorded(result: dict[str, Any], kind: ModelCallKind) -> None:
    _one_missed_call(result, kind, MissCause.PROVIDER_REFUSAL)


def _one_missed_call(result: dict[str, Any], kind: ModelCallKind, cause: MissCause) -> None:
    [missed] = result["missed_model_calls"]
    assert (missed.tool_name, missed.kind, missed.cause) == (DEFAULT_TOOL_NAME, kind, cause)
