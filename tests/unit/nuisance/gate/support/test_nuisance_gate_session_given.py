from pathlib import Path

from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.gate.gate_baseline import (
    NuisanceGateConditions,
    baseline_file_name,
    write_baseline,
)
from tests.unit.nuisance.gate.support.nuisance_gate_sessions import a_baseline_file
from tests.unit.nuisance.gate.support.test_nuisance_gate_baseline_given import (
    a_confirmed_baseline,
    a_gated_baseline,
    conditions,
)


def a_flagged_file(directory: Path, server: AdmittedServer) -> None:
    flagged_once = a_confirmed_baseline([True, *[False] * 5], server.server_package)
    a_baseline_file(directory, server, flagged_once)


def other_conditions() -> NuisanceGateConditions:
    return conditions().model_copy(update={"model": "another-model"})


def an_orphaned_file(directory: Path) -> str:
    package = "npm:no-longer-current"
    write_baseline(directory, a_gated_baseline(package))
    return baseline_file_name(package)
