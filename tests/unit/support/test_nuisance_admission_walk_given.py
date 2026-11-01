import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals.holdout_draw import draw_digest
from evals.nuisance_admission import NuisanceAdmission
from evals.nuisance_walk_record import NuisanceCensus


def admitting_another_package_outside_the_walk() -> NuisanceAdmission:
    """OTHER_PACKAGE admitted through SECOND_FLAW, a census flaw of it that is not a draw-order
    candidate, so the walk never reaches it."""
    return admission_given.admitting_the_server_of(
        admission_given.SECOND_FLAW, admission_given.OTHER_PACKAGE, "context-forge-nuisance"
    )


def with_the_second_flaw_reaching(admission: NuisanceAdmission) -> NuisanceAdmission:
    [server] = admission.servers
    reaching = server.model_copy(update={"reaching_flaw": admission_given.SECOND_FLAW})
    return admission.model_copy(update={"servers": [reaching]})


_QUEUE_CENSUS_FLAWS = ["CVE-2025-1001", "CVE-2025-1002", "CVE-2025-1003"]


def a_nuisance_census_with_two_queue_servers(addition_size: int) -> NuisanceCensus:
    """Each flaw its own server, `npm:<flaw>`: the holdout walk reaches the first by draw order,
    the queue the other two, the servers of `the_queue_packages`."""
    census = walk_given.a_census_walking_the_first(1, of=_QUEUE_CENSUS_FLAWS)
    return NuisanceCensus(census=census, record=walk_given.an_empty_record(addition_size))


def the_queue_packages() -> list[str]:
    return [f"npm:{flaw}" for flaw in sorted(_QUEUE_CENSUS_FLAWS, key=draw_digest)[1:]]


def admitting_the_queue_servers() -> NuisanceAdmission:
    """Listed against their draw order, so the size check has to sort them."""
    servers = [
        admission_given.admitting_the_server_of(
            package.removeprefix("npm:"), package, f"{package.removeprefix('npm:')}-nuisance"
        ).servers[0]
        for package in reversed(the_queue_packages())
    ]
    return admission_given.an_admission().model_copy(update={"servers": servers})


def without_stdio(admission: NuisanceAdmission, server_package: str) -> NuisanceAdmission:
    servers = [
        server.model_copy(update={"runs_over_stdio": False})
        if server.server_package == server_package
        else server
        for server in admission.servers
    ]
    return admission.model_copy(update={"servers": servers})
