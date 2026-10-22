from evals.nuisance_gate_baseline import NuisanceGateConditions
from evals.nuisance_gate_recording import ServerRecording
from tests.unit.support.test_nuisance_gate_given import (
    FIXTURE,
    RECORDED_COMMIT,
    SERVER_PACKAGE,
    a_comparison,
    a_confirmed_baseline,
    a_gated_baseline,
    an_exploratory_baseline,
    conditions,
)

__all__ = [
    "FIXTURE",
    "RECORDED_COMMIT",
    "SERVER_PACKAGE",
    "a_comparison",
    "a_confirmed_baseline",
    "a_gated_baseline",
    "an_exploratory_baseline",
    "conditions",
]

RECORDING_TIME = "2026-10-22T11:00:00+00:00"


def a_recording(
    runs: list[bool] | None = None,
    *,
    completed: bool = True,
    commit: str = RECORDED_COMMIT,
    fixture: str = FIXTURE,
    recording_conditions: NuisanceGateConditions | None = None,
) -> ServerRecording:
    return ServerRecording(
        server_package=SERVER_PACKAGE,
        conditions=recording_conditions or conditions(),
        fixture_fingerprint=fixture,
        commit=commit,
        recorded_at=RECORDING_TIME,
        runs=runs if runs is not None else [False] * 3,
        completed=completed,
        image_ids={"filesystem-patched": "sha256:4567"},
    )
