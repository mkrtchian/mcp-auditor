from collections.abc import Sequence
from datetime import date
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel

from evals.cve.detection.baseline import DetectionRunConditions
from evals.cve.detection.costs import TargetCost
from evals.cve.detection.gate import DetectionGateResult
from evals.cve.detection.measurement import MeasurementSettings
from evals.cve.grammar import FlawClass, MissKind, RunGrade, TargetStatus, resolve
from evals.cve.units import JudgeCategory
from mcp_auditor.domain.models import ProviderUsage


class UngradedStatus(StrEnum):
    NOT_RUN = "not_run"
    OUT_OF_SCOPE = "out_of_scope"


type ResultStatus = TargetStatus | UngradedStatus


class TargetInfo(Protocol):
    """Descriptive slice of a target the pure oracle reads. It never grades, so it reads
    no nonce or aim."""

    @property
    def flaw_id(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def classes(self) -> frozenset[FlawClass]: ...
    @property
    def awaited_capability(self) -> str | None: ...
    @property
    def note(self) -> str: ...


class OutOfScopeInfo(Protocol):
    """A flaw tracked but never run (only catchable with instrumentation)."""

    @property
    def flaw_id(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def reason(self) -> str: ...


class TargetResult(BaseModel):
    flaw_id: str
    severity: str
    note: str
    classes: list[FlawClass] = []  # sorted, empty for no class and out of scope
    status: ResultStatus
    miss_kind: MissKind | None = None
    awaited_capability: str | None = None
    runs: int = 0
    detected_runs: int = 0
    surfaced_runs: int = 0
    aimed_runs: int = 0
    fail_without_proof_runs: int = 0
    budget: int = 0
    evidence: str | None = None
    category: JudgeCategory | None = None
    not_run_reasons: list[str] = []  # the out-of-calibration reasons, when NOT_RUN
    surfaced_places: list[list[str]] = []  # per run: the places whose nonce surfaced
    struck_places: list[list[str]] = []  # per run: the credits the replay struck
    unchecked_places: list[list[str]] = []  # per run: the credits the replay could not check


class DetectionReport(BaseModel):
    conditions: DetectionRunConditions
    concurrency: int  # an execution setting, never compared nor recorded in a baseline
    throttled_requests: int = 0  # an execution observation, never compared nor recorded
    provider_usage: ProviderUsage = (
        ProviderUsage()
    )  # every attempt billed, retests and replays included
    commit: str
    dirty: bool
    results: list[TargetResult]
    gate: DetectionGateResult | None = None
    recording_refused: list[str] = []
    measurement: MeasurementSettings | None = None  # forced settings, never compared
    costs: list[TargetCost] = []  # no-baseline runs priced from evals/holdout_conditions.json only
    prices_as_of: date | None = None


def result_for(target: TargetInfo, grades: Sequence[RunGrade], budget: int) -> TargetResult:
    resolution = resolve(grades)
    return TargetResult(
        flaw_id=target.flaw_id,
        severity=target.severity,
        note=target.note,
        classes=sorted(target.classes),
        status=resolution.status,
        miss_kind=resolution.miss_kind,
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


def not_run(target: TargetInfo, reasons: list[str] | None = None) -> TargetResult:
    return TargetResult(
        flaw_id=target.flaw_id,
        severity=target.severity,
        note=target.note,
        classes=sorted(target.classes),
        status=UngradedStatus.NOT_RUN,
        awaited_capability=target.awaited_capability,
        not_run_reasons=reasons or [],
    )


def out_of_scope_results(flaws: Sequence[OutOfScopeInfo]) -> list[TargetResult]:
    return [
        TargetResult(
            flaw_id=flaw.flaw_id,
            severity=flaw.severity,
            note=flaw.reason,
            status=UngradedStatus.OUT_OF_SCOPE,
        )
        for flaw in flaws
    ]
