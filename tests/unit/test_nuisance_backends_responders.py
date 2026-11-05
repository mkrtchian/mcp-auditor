import tests.unit.support.test_nuisance_admission_given as given
from evals.apify_backend import (
    APIFY_BRIDGE,
    APIFY_RESPONDER_IMAGE,
)
from evals.atlassian_backend import (
    ATLASSIAN_BRIDGE,
    ATLASSIAN_RESPONDER_IMAGE,
)
from evals.googleapis_backend import GOOGLEAPIS_BRIDGE, GOOGLEAPIS_RESPONDER_IMAGE
from evals.jenkins_backend import JENKINS_BRIDGE, JENKINS_RESPONDER_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import BACKENDS, backend_problems


def _a_server() -> AdmittedServer:
    return given.an_admission().servers[0]


def test_the_atlassian_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(
        provisioner="atlassian", image=ATLASSIAN_RESPONDER_IMAGE, network=ATLASSIAN_BRIDGE
    )

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_the_apify_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="apify", image=APIFY_RESPONDER_IMAGE, network=APIFY_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_the_jenkins_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(
        provisioner="jenkins", image=JENKINS_RESPONDER_IMAGE, network=JENKINS_BRIDGE
    )

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_the_googleapis_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(
        provisioner="googleapis", image=GOOGLEAPIS_RESPONDER_IMAGE, network=GOOGLEAPIS_BRIDGE
    )

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []
