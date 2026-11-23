import tests.unit.nuisance.gate.support.nuisance_gate_baselines as nuisance_gate_baselines
from evals.cve.nuisance.gate.gate import ServerCandidate


def a_candidate(
    runs: list[bool],
    *,
    completed: bool = True,
    fixture: str = nuisance_gate_baselines.FIXTURE,
) -> ServerCandidate:
    return ServerCandidate(
        server_package=nuisance_gate_baselines.SERVER_PACKAGE,
        fixture_fingerprint=fixture,
        runs=runs,
        completed=completed,
    )
