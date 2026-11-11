from typing import Any

from mcp_auditor.domain import Judgment, TestCase, ToolDefinition
from mcp_auditor.domain.models import MissCause, MissedModelCall, ModelCallKind


def current_case_has_error(result: dict[str, Any], expected_error: str) -> None:
    assert result["current_case"].error == expected_error
    assert result["current_case"].response is None


def discovered_tools_are(tools: list[ToolDefinition], expected_names: list[str]) -> None:
    assert [t.name for t in tools] == expected_names


def judged_case_identity_from(result: dict[str, Any], tool_name: str, case: TestCase) -> None:
    eval_result = result["processed_cases"][0].eval_result
    assert eval_result is not None
    assert eval_result.tool_name == tool_name
    assert eval_result.category == case.payload.category
    assert eval_result.payload == case.payload.arguments


def judged_case_uses_judgment(result: dict[str, Any], judgment: Judgment) -> None:
    eval_result = result["processed_cases"][0].eval_result
    assert eval_result is not None
    assert eval_result.verdict == judgment.verdict
    assert eval_result.justification == judgment.justification
    assert eval_result.severity == judgment.severity


def refused_call_recorded(result: dict[str, Any], tool_name: str, kind: ModelCallKind) -> None:
    assert result["missed_model_calls"] == [
        MissedModelCall(
            tool_name=tool_name,
            kind=kind,
            cause=MissCause.PROVIDER_REFUSAL,
            detail="flagged by policy",
        )
    ]
