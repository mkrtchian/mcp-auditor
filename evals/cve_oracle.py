from collections.abc import Sequence
from datetime import date
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel

from evals.cve_baseline import CVERunConditions
from evals.cve_costs import TargetCost
from evals.cve_gate import CVEGateResult
from evals.cve_grammar import CVEStatus, MechanismClass, MissClass, RunGrade, resolve
from evals.cve_measurement import MeasurementSettings
from evals.cve_units import JudgeCategory
from mcp_auditor.domain.models import ProviderUsage


class UngradedStatus(StrEnum):
    NOT_RUN = "not_run"
    OUT_OF_SCOPE = "out_of_scope"


type TargetStatus = CVEStatus | UngradedStatus


class TargetInfo(Protocol):
    """Descriptive slice of a CVE target the pure oracle reads. It never grades, so it reads
    no nonce or aim."""

    @property
    def cve_id(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def mechanism(self) -> MechanismClass | None: ...
    @property
    def awaited_capability(self) -> str | None: ...
    @property
    def note(self) -> str: ...


class OutOfScopeInfo(Protocol):
    """A CVE tracked but never run (only catchable with instrumentation)."""

    @property
    def cve_id(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def reason(self) -> str: ...


class CVEResult(BaseModel):
    cve_id: str
    severity: str
    note: str
    mechanism: MechanismClass | None = None
    status: TargetStatus
    miss_class: MissClass | None = None
    awaited_capability: str | None = None
    runs: int = 0
    detected_runs: int = 0
    surfaced_runs: int = 0
    aimed_runs: int = 0
    fail_without_proof_runs: int = 0
    budget: int = 0
    evidence: str | None = None
    category: JudgeCategory | None = None
    not_run_conditions: list[str] = []  # the pre-run check's dead conditions, when NOT_RUN
    surfaced_places: list[list[str]] = []  # per run: the places whose nonce surfaced
    struck_places: list[list[str]] = []  # per run: the credits the replay refused
    unchecked_places: list[list[str]] = []  # per run: the credits the replay could not check


class CVEBenchmarkReport(BaseModel):
    conditions: CVERunConditions
    concurrency: int  # an execution setting, never compared nor recorded in a baseline
    throttled_requests: int = 0  # an execution observation, never compared nor recorded
    provider_usage: ProviderUsage = ProviderUsage()  # every attempt billed, replays included
    commit: str
    dirty: bool
    results: list[CVEResult]
    gate: CVEGateResult | None = None
    recording_refused: list[str] = []
    measurement: MeasurementSettings | None = None  # forced settings, never compared
    costs: list[TargetCost] = []  # ungated runs priced from evals/holdout_conditions.json only
    prices_as_of: date | None = None


def result_for(target: TargetInfo, grades: Sequence[RunGrade], budget: int) -> CVEResult:
    resolution = resolve(grades)
    return CVEResult(
        cve_id=target.cve_id,
        severity=target.severity,
        note=target.note,
        mechanism=target.mechanism,
        status=resolution.status,
        miss_class=resolution.miss_class,
        awaited_capability=target.awaited_capability,
        runs=len(grades),
        detected_runs=resolution.detected_runs,
        surfaced_runs=resolution.surfaced_runs,
        aimed_runs=resolution.aimed_runs,
        fail_without_proof_runs=resolution.fail_without_proof_runs,
        budget=budget,
        evidence=resolution.evidence,
        category=resolution.category,
        surfaced_places=resolution.surfaced_places,
        struck_places=resolution.struck_places,
        unchecked_places=resolution.unchecked_places,
    )


def not_run(target: TargetInfo, conditions: list[str] | None = None) -> CVEResult:
    return CVEResult(
        cve_id=target.cve_id,
        severity=target.severity,
        note=target.note,
        mechanism=target.mechanism,
        status=UngradedStatus.NOT_RUN,
        awaited_capability=target.awaited_capability,
        not_run_conditions=conditions or [],
    )


def out_of_scope_results(cves: Sequence[OutOfScopeInfo]) -> list[CVEResult]:
    return [
        CVEResult(
            cve_id=cve.cve_id,
            severity=cve.severity,
            note=cve.reason,
            status=UngradedStatus.OUT_OF_SCOPE,
        )
        for cve in cves
    ]
