import re
from dataclasses import dataclass, field

from evals.cve.detection.baseline import DetectionRunConditions
from evals.cve.detection.costs import TargetCost
from evals.cve.detection.gate import DetectionGateResult, TargetComparison, TargetOutcome
from evals.cve.detection.oracle import DetectionReport, TargetResult
from evals.cve_grammar import CVEStatus, MechanismClass, MissClass, RunGrade
from evals.cve_units import JudgeCategory
from evals.gate_outcome import GateOutcome
from evals.metrics import UsageBreakdown
from mcp_auditor.domain.models import ProviderUsage

NONCE = "s3nt1nel_ab12cd34ef56"
FINGERPRINT = "0123456789abcdef" * 4
CONCURRENCY = 4
COMMIT = "c0ffee"


@dataclass(frozen=True)
class FakeTarget:
    flaw_id: str = "CVE-2025-0001"
    severity: str = "9.1 CRITICAL"
    nonce: str = NONCE
    mechanisms: frozenset[MechanismClass] = frozenset({MechanismClass.READ_OUTSIDE_SCOPE})
    aim: re.Pattern[str] = field(default=re.compile(r"^/outside/"))
    awaited_capability: str | None = "declared-scope awareness"
    note: str = "test note"


@dataclass
class FakeOutOfScopeFlaw:
    flaw_id: str
    severity: str
    reason: str


def a_detected_grade() -> RunGrade:
    return RunGrade(
        status=CVEStatus.DETECTED,
        surfaced_places=frozenset({"planted"}),
        aimed=True,
        evidence=f"leaked {NONCE}",
        category=JudgeCategory("injection"),
    )


def a_missed_grade(miss_class: MissClass, fail_without_proof: bool = False) -> RunGrade:
    return RunGrade(
        status=CVEStatus.MISSED,
        miss_class=miss_class,
        aimed=miss_class != MissClass.NOT_AIMED,
        fail_without_proof=fail_without_proof,
    )


def a_cve_result(
    flaw_id: str,
    status: CVEStatus,
    detected_runs: int = 0,
    aimed_runs: int = 0,
    fail_without_proof_runs: int = 0,
    miss_class: MissClass | None = None,
    struck_places: list[list[str]] | None = None,
    unchecked_places: list[list[str]] | None = None,
    mechanisms: tuple[MechanismClass, ...] = (MechanismClass.COMMAND_EXECUTION,),
) -> TargetResult:
    return TargetResult(
        flaw_id=flaw_id,
        severity="9.1 CRITICAL",
        note="test note",
        mechanisms=list(mechanisms),
        status=status,
        miss_class=miss_class,
        awaited_capability="cross-tool chains",
        runs=3,
        detected_runs=detected_runs,
        surfaced_runs=detected_runs,
        aimed_runs=aimed_runs,
        fail_without_proof_runs=fail_without_proof_runs,
        budget=10,
        struck_places=struck_places or [],
        unchecked_places=unchecked_places or [],
    )


def a_benchmark_report(results: list[TargetResult]) -> DetectionReport:
    return DetectionReport(
        conditions=DetectionRunConditions(
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
        concurrency=CONCURRENCY,
        commit=COMMIT,
        dirty=False,
        results=results,
    )


def a_red_gate() -> DetectionGateResult:
    return DetectionGateResult(
        outcome=GateOutcome.RED,
        reasons=["CVE-2025-53355: regression, the miss reproduced in 4 of 4 retests"],
        targets=[
            TargetComparison(
                flaw_id="CVE-2025-53355",
                outcome=TargetOutcome.REGRESSION,
                candidate_runs=[
                    CVEStatus.DETECTED,
                    CVEStatus.MISSED,
                    CVEStatus.REACHED_BUT_JUDGED_PASS,
                ],
                retests=[True] * 4,
            ),
            TargetComparison(
                flaw_id="CVE-2025-53109",
                outcome=TargetOutcome.HELD,
                candidate_runs=[CVEStatus.DETECTED] * 3,
            ),
        ],
    )


def a_report_gated_on(*targets: TargetComparison) -> DetectionReport:
    gate = DetectionGateResult(outcome=GateOutcome.GREEN, reasons=[], targets=list(targets))
    return a_benchmark_report([]).model_copy(update={"gate": gate})


def a_target_cost(flaw_id: str) -> TargetCost:
    return TargetCost(
        flaw_id=flaw_id,
        usage=UsageBreakdown(total=ProviderUsage(input_tokens=2000, output_tokens=300)),
        single_step=0.25,
        chains=0.5,
        judge=0.125,
        total=0.75,
        largest_input_tokens=900,
    )
