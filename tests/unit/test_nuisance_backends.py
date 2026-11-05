import ipaddress

import pytest

import tests.unit.support.test_nuisance_admission_given as given
from evals.ckan_backend import CKAN_BRIDGE, CKAN_RESPONDER_IMAGE
from evals.contextforge_backend import (
    CONTEXTFORGE_BRIDGE,
    CONTEXTFORGE_RESPONDER_IMAGE,
    CONTEXTFORGE_RESPONDER_IP,
)
from evals.docker_paths import DOCKER_DIRECTORY
from evals.doris_backend import DORIS_BRIDGE, DORIS_IMAGE
from evals.mysql_backend import MYSQL_BRIDGE, MYSQL_IMAGE
from evals.n8n_backend import N8N_BRIDGE, N8N_RESPONDER_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import BACKENDS, backend_problems


def _a_server() -> AdmittedServer:
    return given.an_admission().servers[0]


def test_the_doris_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="doris", image=DORIS_IMAGE, network=DORIS_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_the_ckan_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="ckan", image=CKAN_RESPONDER_IMAGE, network=CKAN_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_the_contextforge_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(
        provisioner="contextforge",
        image=CONTEXTFORGE_RESPONDER_IMAGE,
        network=CONTEXTFORGE_BRIDGE,
    )

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_the_contextforge_responder_ip_is_global():
    # The patched gateway refuses a REST tool whose host is private by `ipaddress`, and the
    # documentation ranges count as private there.
    assert ipaddress.ip_address(CONTEXTFORGE_RESPONDER_IP).is_global


@pytest.mark.parametrize("dockerfile", ["Dockerfile.contextforge", "Dockerfile.contextforge-vuln"])
def test_the_gateway_benign_tool_aims_at_the_contextforge_responder(dockerfile: str):
    baked = (DOCKER_DIRECTORY / dockerfile).read_text()

    assert f'"GW_BENIGN_URL", "http://{CONTEXTFORGE_RESPONDER_IP}/"' in baked


def test_the_mysql_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="mysql", image=MYSQL_IMAGE, network=MYSQL_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []


def test_the_n8n_fixture_is_accepted_by_the_registry():
    backend = BackendFixture(provisioner="n8n", image=N8N_RESPONDER_IMAGE, network=N8N_BRIDGE)

    assert backend_problems(given.with_a_backend(_a_server(), backend), BACKENDS) == []
