import tests.unit.support.nuisance_admissions as admissions
import tests.unit.support.nuisance_walks as walks
from evals.cve.census.draw_order import draw_digest
from evals.cve.nuisance.admission.admission import NuisanceAdmission
from evals.cve.nuisance.admission.walk_record import WalkInputs
from tests.unit.support.admission_mutations import admitting


def admitting_another_package_outside_the_walk() -> NuisanceAdmission:
    """OTHER_PACKAGE admitted through SECOND_FLAW, a census flaw of it that is not a draw-order
    candidate, so the walk never reaches it."""
    return admissions.admitting_the_server_of(
        admissions.SECOND_FLAW, admissions.OTHER_PACKAGE, "context-forge-nuisance"
    )


def with_the_second_flaw_reaching(admission: NuisanceAdmission) -> NuisanceAdmission:
    [server] = admission.servers
    reaching = server.model_copy(update={"reaching_flaw": admissions.SECOND_FLAW})
    return admission.model_copy(update={"servers": [reaching]})


_QUEUE_CENSUS_FLAWS = ["CVE-2025-1001", "CVE-2025-1002", "CVE-2025-1003"]


def walk_inputs_with_two_queue_servers(addition_size: int) -> WalkInputs:
    """Each flaw its own server, `npm:<flaw>`: the detection walk reaches the first by draw order,
    the queue the other two, the servers of `the_queue_packages`."""
    census = walks.a_census_walking_the_first(1, of=_QUEUE_CENSUS_FLAWS)
    return WalkInputs(census=census, record=walks.an_empty_record(addition_size))


def admitting_the_queue_servers() -> NuisanceAdmission:
    """Listed against their draw order, so the size check has to sort them."""
    servers = [
        admissions.admitting_the_server_of(
            package.removeprefix("npm:"), package, f"{package.removeprefix('npm:')}-nuisance"
        ).servers[0]
        for package in reversed(the_queue_packages())
    ]
    return admitting(*servers)


def the_queue_packages() -> list[str]:
    return [f"npm:{flaw}" for flaw in sorted(_QUEUE_CENSUS_FLAWS, key=draw_digest)[1:]]
