from typing import Any

from mcp_auditor.domain import TestCaseBatch
from mcp_auditor.domain.models import AuditStep, MissCause, MissedStep


def pending_payloads_are(result: dict[str, Any], batch: TestCaseBatch) -> None:
    assert [case.payload for case in result["pending_cases"]] == batch.cases


def provider_usage_count(result: dict[str, Any], expected: int) -> None:
    assert len(result["provider_usage"]) == expected


def one_generation_refusal_recorded(result: dict[str, Any]) -> None:
    assert result["missed_steps"] == [
        MissedStep(
            tool_name="test_tool",
            step=AuditStep.TEST_GENERATION,
            cause=MissCause.PROVIDER_REFUSAL,
            detail="flagged by policy",
        )
    ]
