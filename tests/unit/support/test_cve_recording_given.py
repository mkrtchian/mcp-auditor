from evals.cve_baseline import CVERunConditions
from evals.cve_grammar import CVEStatus
from evals.cve_recording import TargetRecording
from tests.unit.support.test_cve_gate_given import (
    CVE_ID,
    DETECTED,
    FIXTURE,
    MISSED,
    RECORDED_COMMIT,
    a_comparison,
    a_gated_baseline,
    an_exploratory_baseline,
    conditions,
)

__all__ = [
    "CVE_ID",
    "DETECTED",
    "MISSED",
    "RECORDED_COMMIT",
    "a_comparison",
    "a_gated_baseline",
    "an_exploratory_baseline",
    "conditions",
]

RECORDING_TIME = "2026-09-28T11:00:00+00:00"


def a_recording(
    runs: list[CVEStatus] | None = None,
    commit: str = RECORDED_COMMIT,
    recording_conditions: CVERunConditions | None = None,
    fixture: str = FIXTURE,
    completed: bool = True,
) -> TargetRecording:
    return TargetRecording(
        cve_id=CVE_ID,
        conditions=recording_conditions or conditions(),
        fixture_fingerprint=fixture,
        commit=commit,
        recorded_at=RECORDING_TIME,
        runs=runs if runs is not None else [MISSED, DETECTED, DETECTED],
        completed=completed,
        image_ids={"kubernetes": "sha256:4567"},
    )
