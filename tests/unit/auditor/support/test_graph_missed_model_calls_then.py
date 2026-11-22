from typing import Any

from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind


def audit_report_has_missed_calls(
    result: dict[str, Any], expected: list[tuple[str, ModelCallKind]]
) -> None:
    _are_missed_calls(result["audit_report"].missed_model_calls, expected)


def audit_report_misses_one_call(
    result: dict[str, Any], tool_name: str, kind: ModelCallKind, cause: MissedCallCause
) -> None:
    report = result["audit_report"]
    assert [
        (missed.tool_name, missed.kind, missed.cause) for missed in report.missed_model_calls
    ] == [(tool_name, kind, cause)]
    assert not report.is_complete


def state_has_missed_calls(
    result: dict[str, Any], expected: list[tuple[str, ModelCallKind]]
) -> None:
    _are_missed_calls(result["missed_model_calls"], expected)


def _are_missed_calls(
    missed_calls: list[MissedModelCall], expected: list[tuple[str, ModelCallKind]]
) -> None:
    assert [(missed.tool_name, missed.kind) for missed in missed_calls] == expected
