from typing import Any

from mcp_auditor.domain import TestCaseBatch


def pending_payloads_are(result: dict[str, Any], batch: TestCaseBatch) -> None:
    assert [case.payload for case in result["pending_cases"]] == batch.cases


def token_usage_count(result: dict[str, Any], expected: int) -> None:
    assert len(result["token_usage"]) == expected
