from evals.cve.nuisance.admission.walk import nuisance_population
from evals.cve.nuisance.admission.walk_record import WalkInputs


def the_population_is(walk_inputs: WalkInputs, *packages: str) -> None:
    population = nuisance_population(walk_inputs)
    assert [server.server_package for server in population] == list(packages)
