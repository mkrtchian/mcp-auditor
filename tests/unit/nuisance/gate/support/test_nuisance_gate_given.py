from evals.cve.nuisance.gate.gate import ServerCandidate, ServerComparison, ServerOutcome
from tests.unit.nuisance.gate.support.test_nuisance_gate_baseline_given import FIXTURE as FIXTURE
from tests.unit.nuisance.gate.support.test_nuisance_gate_baseline_given import (
    RECORDED_COMMIT as RECORDED_COMMIT,
)
from tests.unit.nuisance.gate.support.test_nuisance_gate_baseline_given import (
    SERVER_PACKAGE as SERVER_PACKAGE,
)
from tests.unit.nuisance.gate.support.test_nuisance_gate_baseline_given import (
    a_confirmed_baseline as a_confirmed_baseline,
)
from tests.unit.nuisance.gate.support.test_nuisance_gate_baseline_given import (
    a_gated_baseline as a_gated_baseline,
)
from tests.unit.nuisance.gate.support.test_nuisance_gate_baseline_given import (
    an_unconfirmed_baseline as an_unconfirmed_baseline,
)
from tests.unit.nuisance.gate.support.test_nuisance_gate_baseline_given import (
    conditions as conditions,
)


def a_candidate(
    runs: list[bool],
    *,
    completed: bool = True,
    fixture: str = FIXTURE,
    package: str = SERVER_PACKAGE,
) -> ServerCandidate:
    return ServerCandidate(
        server_package=package, fixture_fingerprint=fixture, runs=runs, completed=completed
    )


def a_comparison(outcome: ServerOutcome, package: str = SERVER_PACKAGE) -> ServerComparison:
    return ServerComparison(server_package=package, outcome=outcome, candidate_runs=[False] * 3)
