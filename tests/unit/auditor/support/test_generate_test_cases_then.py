from typing import Any

from mcp_auditor.domain.models import TestCaseBatch


def pending_payloads_are(result: dict[str, Any], batch: TestCaseBatch) -> None:
    assert [case.payload for case in result["pending_cases"]] == batch.cases
