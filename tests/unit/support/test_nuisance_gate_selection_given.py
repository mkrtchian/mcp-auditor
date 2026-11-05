import tests.unit.support.test_nuisance_run_given as run_given
from evals.nuisance_admission import AdmittedServer, NuisanceAdmission
from tests.unit.support.test_nuisance_admission_given import an_admission


def admitting(*servers: AdmittedServer) -> NuisanceAdmission:
    return an_admission().model_copy(update={"servers": list(servers)})


def a_server_outside_the_census(package: str) -> AdmittedServer:
    return run_given.a_server(package)
