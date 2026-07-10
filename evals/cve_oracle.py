from collections.abc import Iterator, Sequence
from enum import StrEnum
from typing import Any, NamedTuple, Protocol

from pydantic import BaseModel

from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditReport,
    EvalVerdict,
    TestCase,
)


class CVEStatus(StrEnum):
    DETECTED = "detected"
    REACHED_BUT_JUDGED_PASS = "reached_but_judged_pass"
    MISSED = "missed"
    MISSED_AWAITING_CAPABILITY = "missed_awaiting_capability"
    OUT_OF_SCOPE = "out_of_scope"
    NOT_RUN = "not_run"


class TargetInfo(Protocol):
    """Descriptive slice of a CVE target the pure oracle reads."""

    @property
    def cve_id(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def sentinel(self) -> str: ...
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


class RunDetection(BaseModel):
    sentinel_surfaced: bool
    sentinel_in_fail: bool
    evidence: str | None = None
    category: AuditCategory | None = None


class CVEResult(BaseModel):
    cve_id: str
    severity: str
    note: str
    status: CVEStatus
    awaited_capability: str | None = None
    runs: int = 0
    hits: int = 0
    surfaced: int = 0
    budget: int = 0
    evidence: str | None = None
    category: AuditCategory | None = None


def detect_in_report(target: TargetInfo, report: AuditReport) -> RunDetection:
    matches = [out for out in _observed_outputs(report) if target.sentinel in out.text]
    if not matches:
        return RunDetection(sentinel_surfaced=False, sentinel_in_fail=False)
    fail_matches = [out for out in matches if out.verdict == EvalVerdict.FAIL]
    representative = fail_matches[0] if fail_matches else matches[0]
    return RunDetection(
        sentinel_surfaced=True,
        sentinel_in_fail=bool(fail_matches),
        evidence=representative.text,
        category=representative.category,
    )


def resolve_status(target: TargetInfo, detections: list[RunDetection], budget: int) -> CVEResult:
    hits = sum(1 for d in detections if d.sentinel_in_fail)
    surfaced = sum(1 for d in detections if d.sentinel_surfaced)
    evidence, category = _representative_evidence(detections)
    return CVEResult(
        cve_id=target.cve_id,
        severity=target.severity,
        note=target.note,
        status=_status_for(hits, surfaced, target.awaited_capability),
        awaited_capability=target.awaited_capability,
        runs=len(detections),
        hits=hits,
        surfaced=surfaced,
        budget=budget,
        evidence=evidence,
        category=category,
    )


def not_run(target: TargetInfo) -> CVEResult:
    return CVEResult(
        cve_id=target.cve_id,
        severity=target.severity,
        note=target.note,
        status=CVEStatus.NOT_RUN,
        awaited_capability=target.awaited_capability,
    )


def out_of_scope_results(cves: Sequence[OutOfScopeInfo]) -> list[CVEResult]:
    return [
        CVEResult(
            cve_id=cve.cve_id,
            severity=cve.severity,
            note=cve.reason,
            status=CVEStatus.OUT_OF_SCOPE,
        )
        for cve in cves
    ]


def render_markdown(results: list[CVEResult]) -> str:
    header = "| CVE | CVSS | Status | Hit-rate | Budget | Awaited capability | Note |"
    separator = "|---|---|---|---|---|---|---|"
    rows = [_render_row(result) for result in results]
    detected = sum(1 for result in results if result.status == CVEStatus.DETECTED)
    summary = f"Detected {detected}/{len(results)} CVEs."
    return "\n".join([header, separator, *rows, "", summary])


class _ObservedOutput(NamedTuple):
    text: str
    verdict: EvalVerdict
    category: AuditCategory


def _observed_outputs(report: AuditReport) -> Iterator[_ObservedOutput]:
    for tool_report in report.tool_reports:
        for case in tool_report.cases:
            if case.eval_result is None:
                continue
            for text in _case_texts(case):
                yield _ObservedOutput(text, case.eval_result.verdict, case.eval_result.category)
        for chain in tool_report.chains:
            if chain.eval_result is None:
                continue
            for text in _chain_texts(chain):
                yield _ObservedOutput(text, chain.eval_result.verdict, chain.eval_result.category)


def _case_texts(case: TestCase) -> list[str]:
    return [text for text in (_coerce(case.response), case.error) if text is not None]


def _chain_texts(chain: AttackChain) -> list[str]:
    return [
        text for step in chain.steps for text in (step.response, step.error) if text is not None
    ]


def _coerce(response: str | dict[str, Any] | None) -> str | None:
    if response is None or isinstance(response, str):
        return response
    return str(response)


def _status_for(hits: int, surfaced: int, awaited_capability: str | None) -> CVEStatus:
    if hits:
        return CVEStatus.DETECTED
    if surfaced:
        return CVEStatus.REACHED_BUT_JUDGED_PASS
    if awaited_capability is None:
        return CVEStatus.MISSED
    return CVEStatus.MISSED_AWAITING_CAPABILITY


def _representative_evidence(
    detections: list[RunDetection],
) -> tuple[str | None, AuditCategory | None]:
    for detection in detections:
        if detection.sentinel_in_fail:
            return detection.evidence, detection.category
    for detection in detections:
        if detection.sentinel_surfaced:
            return detection.evidence, detection.category
    return None, None


def _render_row(result: CVEResult) -> str:
    hit_rate = f"{result.hits}/{result.runs}"
    awaited = result.awaited_capability or "-"
    return (
        f"| {result.cve_id} | {result.severity} | {result.status.value} "
        f"| {hit_rate} | {result.budget} | {awaited} | {result.note} |"
    )
