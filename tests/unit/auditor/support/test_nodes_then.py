from typing import Any

from mcp_auditor.domain import Judgment, TestCase, ToolDefinition
from mcp_auditor.domain.models import MissCause, MissedModelCall, ModelCallKind


def current_case_has_error(result: dict[str, Any], expected_error: str) -> None:
    assert result["current_case"].error == expected_error
    assert result["current_case"].response is None


def discovered_tools_are(tools: list[ToolDefinition], expected_names: list[str]) -> None:
    assert [t.name for t in tools] == expected_names


def judged_case_identity_from(result: dict[str, Any], tool_name: str, case: TestCase) -> None:
    judge_result = result["processed_cases"][0].judge_result
    assert judge_result is not None
    assert judge_result.tool_name == tool_name
    assert judge_result.category == case.payload.category
    assert judge_result.arguments == case.payload.arguments


def judged_case_uses_judgment(result: dict[str, Any], judgment: Judgment) -> None:
    judge_result = result["processed_cases"][0].judge_result
    assert judge_result is not None
    assert judge_result.verdict == judgment.verdict
    assert judge_result.justification == judgment.justification
    assert judge_result.severity == judgment.severity


def refused_call_recorded(result: dict[str, Any], tool_name: str, kind: ModelCallKind) -> None:
    assert result["missed_model_calls"] == [
        MissedModelCall(
            tool_name=tool_name,
            kind=kind,
            cause=MissCause.PROVIDER_REFUSAL,
            detail="flagged by policy",
        )
    ]
