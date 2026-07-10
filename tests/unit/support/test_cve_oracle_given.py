from dataclasses import dataclass
from typing import Any

from evals.cve_oracle import CVEResult, CVEStatus, RunDetection
from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    ChainGoal,
    ChainStep,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)

SENTINEL = "s3nt1nel_ab12cd34ef56"
INFO_LEAKAGE = AuditCategory.INFO_LEAKAGE
FAIL = EvalVerdict.FAIL
PASS = EvalVerdict.PASS


@dataclass
class FakeTarget:
    cve_id: str = "CVE-2025-0001"
    severity: str = "9.1 CRITICAL"
    sentinel: str = SENTINEL
    awaited_capability: str | None = None
    note: str = "test note"


@dataclass
class FakeOutOfScopeCVE:
    cve_id: str
    severity: str
    reason: str


def a_target(awaited_capability: str | None = None, sentinel: str = SENTINEL) -> FakeTarget:
    return FakeTarget(awaited_capability=awaited_capability, sentinel=sentinel)


def a_case_with_response(
    response: str | dict[str, Any] | None = None,
    error: str | None = None,
    verdict: EvalVerdict = FAIL,
    category: AuditCategory = INFO_LEAKAGE,
) -> TestCase:
    return TestCase(
        payload=_a_payload(category),
        response=response,
        error=error,
        eval_result=_a_result(verdict, category),
    )


def a_chain_with_step(
    response: str | None = None,
    error: str | None = None,
    verdict: EvalVerdict = FAIL,
    category: AuditCategory = INFO_LEAKAGE,
) -> AttackChain:
    payload = _a_payload(category)
    return AttackChain(
        goal=ChainGoal(description="test chain", category=category, first_step=payload),
        steps=[ChainStep(payload=payload, response=response, error=error)],
        eval_result=_a_result(verdict, category),
    )


def a_report(
    cases: list[TestCase] | None = None, chains: list[AttackChain] | None = None
) -> AuditReport:
    tool_report = ToolReport(
        tool=ToolDefinition(name="read_file", description="test", input_schema={"type": "object"}),
        cases=cases or [],
        chains=chains or [],
    )
    return AuditReport(target="test", tool_reports=[tool_report], token_usage=TokenUsage())


def a_detection(surfaced: bool, in_fail: bool) -> RunDetection:
    return RunDetection(
        sentinel_surfaced=surfaced,
        sentinel_in_fail=in_fail,
        evidence=SENTINEL if surfaced else None,
        category=INFO_LEAKAGE if surfaced else None,
    )


def a_cve_result(
    cve_id: str,
    status: CVEStatus,
    severity: str = "9.1 CRITICAL",
    awaited_capability: str | None = None,
    hits: int = 0,
    runs: int = 3,
) -> CVEResult:
    return CVEResult(
        cve_id=cve_id,
        severity=severity,
        note="test note",
        status=status,
        awaited_capability=awaited_capability,
        runs=runs,
        hits=hits,
        surfaced=hits,
        budget=8,
    )


def _a_payload(category: AuditCategory) -> AuditPayload:
    return AuditPayload(category=category, description="test", arguments={})


def _a_result(verdict: EvalVerdict, category: AuditCategory) -> EvalResult:
    return EvalResult(
        tool_name="read_file",
        category=category,
        payload={},
        verdict=verdict,
        justification="test",
        severity=Severity.HIGH,
    )
