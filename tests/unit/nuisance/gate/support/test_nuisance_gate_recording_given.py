import tests.unit.nuisance.gate.support.nuisance_gate_baselines as nuisance_gate_baselines
from evals.cve.nuisance.gate.gate_baseline import NuisanceGateConditions
from evals.cve.nuisance.gate.gate_recording import ServerRecording

RECORDING_TIME = "2026-10-22T11:00:00+00:00"


def a_recording(
    runs: list[bool] | None = None,
    *,
    completed: bool = True,
    commit: str = nuisance_gate_baselines.RECORDED_COMMIT,
    fixture: str = nuisance_gate_baselines.FIXTURE,
    recording_conditions: NuisanceGateConditions | None = None,
) -> ServerRecording:
    return ServerRecording(
        server_package=nuisance_gate_baselines.SERVER_PACKAGE,
        conditions=recording_conditions or nuisance_gate_baselines.conditions(),
        fixture_fingerprint=fixture,
        commit=commit,
        recorded_at=RECORDING_TIME,
        runs=runs if runs is not None else [False] * 3,
        completed=completed,
        image_ids={"filesystem-patched": "sha256:4567"},
    )
