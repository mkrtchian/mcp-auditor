import tests.unit.support.test_nuisance_admission_given as given
from evals.neo4j_backend import NEO4J_BRIDGE, NEO4J_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import BACKENDS, backend_problems


def _a_server() -> AdmittedServer:
    return given.an_admission().servers[0]


def test_the_neo4j_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="neo4j", image=NEO4J_IMAGE, network=NEO4J_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []
