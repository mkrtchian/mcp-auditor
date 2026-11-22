from mcp_auditor.domain import (
    AuditCategory,
    EvalVerdict,
    JudgeResult,
    Judgment,
    Severity,
    TestCase,
)
from tests.unit.auditor.support.chain_states import a_payload


def a_judgment(
    verdict: EvalVerdict = EvalVerdict.FAIL,
    severity: Severity = Severity.HIGH,
) -> Judgment:
    return Judgment(
        verdict=verdict,
        justification="path traversal succeeded",
        severity=severity,
    )


def a_single_step_case(response: str = "ok", error: str | None = None) -> TestCase:
    return TestCase(
        payload=a_payload(),
        response=response,
        error=error,
        judge_result=a_fail_judge_result(),
    )


def a_fail_judge_result() -> JudgeResult:
    return JudgeResult(
        tool_name="t",
        category=AuditCategory.INJECTION,
        arguments={"path": "/etc/passwd"},
        verdict=EvalVerdict.FAIL,
        justification="path traversal succeeded",
        severity=Severity.HIGH,
    )


def a_blocked_single_step_case(
    reason: str = "destructive filesystem command: rm -rf",
) -> TestCase:
    return TestCase(payload=a_payload(arguments={"path": "1; rm -rf /"}), blocked_reason=reason)
