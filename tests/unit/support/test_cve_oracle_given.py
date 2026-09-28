import re
from dataclasses import dataclass, field

from evals.cve_baseline import CVERunConditions
from evals.cve_grammar import CVEStatus, MechanismClass, MissClass, RunGrade
from evals.cve_oracle import CVEBenchmarkReport, CVEResult
from mcp_auditor.domain.models import AuditCategory

SENTINEL = "s3nt1nel_ab12cd34ef56"
FINGERPRINT = "0123456789abcdef" * 4


@dataclass(frozen=True)
class FakeTarget:
    cve_id: str = "CVE-2025-0001"
    severity: str = "9.1 CRITICAL"
    sentinel: str = SENTINEL
    mechanism: MechanismClass = MechanismClass.READ_OUTSIDE_SCOPE
    aim: re.Pattern[str] = field(default=re.compile(r"^/outside/"))
    awaited_capability: str | None = "declared-scope awareness"
    note: str = "test note"


@dataclass
class FakeOutOfScopeCVE:
    cve_id: str
    severity: str
    reason: str


def a_detected_grade() -> RunGrade:
    return RunGrade(
        status=CVEStatus.DETECTED,
        surfaced=True,
        aimed=True,
        evidence=f"leaked {SENTINEL}",
        category=AuditCategory.INJECTION,
    )


def a_missed_grade(miss_class: MissClass, fail_without_proof: bool = False) -> RunGrade:
    return RunGrade(
        status=CVEStatus.MISSED,
        miss_class=miss_class,
        aimed=miss_class != MissClass.NOT_AIMED,
        fail_without_proof=fail_without_proof,
    )


def a_cve_result(
    cve_id: str,
    status: CVEStatus,
    detected_runs: int = 0,
    aimed_runs: int = 0,
    fail_without_proof_runs: int = 0,
    miss_class: MissClass | None = None,
) -> CVEResult:
    return CVEResult(
        cve_id=cve_id,
        severity="9.1 CRITICAL",
        note="test note",
        mechanism=MechanismClass.COMMAND_EXECUTION,
        status=status,
        miss_class=miss_class,
        awaited_capability="cross-tool chains",
        runs=3,
        detected_runs=detected_runs,
        surfaced_runs=detected_runs,
        aimed_runs=aimed_runs,
        fail_without_proof_runs=fail_without_proof_runs,
        budget=10,
    )


def a_benchmark_report(results: list[CVEResult]) -> CVEBenchmarkReport:
    return CVEBenchmarkReport(
        conditions=CVERunConditions(
            runs=3,
            budget=10,
            tools_filtered=True,
            provider="openai",
            model="gpt-6-luna",
            judge_model="gpt-6-judge",
            reasoning="none",
            judge_reasoning=None,
            grammar_fingerprint=FINGERPRINT,
        ),
        results=results,
    )
