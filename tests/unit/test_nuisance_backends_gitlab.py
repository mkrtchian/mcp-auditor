import tests.unit.support.test_nuisance_admission_given as given
from evals.gitlab_backend import GITLAB_BRIDGE, GITLAB_RESPONDER_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import BACKENDS, backend_problems


def _a_server() -> AdmittedServer:
    return given.an_admission().servers[0]


def test_the_gitlab_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(
        provisioner="gitlab", image=GITLAB_RESPONDER_IMAGE, network=GITLAB_BRIDGE
    )

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []
