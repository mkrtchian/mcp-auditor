import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve.nuisance.admission.admission import AdmittedServer


def a_server_outside_the_census(package: str) -> AdmittedServer:
    return holdout_runs.a_server(package)
