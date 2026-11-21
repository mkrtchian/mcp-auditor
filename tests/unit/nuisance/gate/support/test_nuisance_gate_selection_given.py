import tests.unit.nuisance.support.test_nuisance_run_given as run_given
from evals.cve.nuisance.admission.admission import AdmittedServer


def a_server_outside_the_census(package: str) -> AdmittedServer:
    return run_given.a_server(package)
