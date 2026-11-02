import pytest

import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_run_given as run_given
from evals import cve_targets
from evals.ckan_backend import CKAN_RESPONDER_IMAGE
from evals.neo4j_backend import NEO4J_IMAGE
from evals.nuisance_admission import AdmittedServer, BackendFixture
from evals.nuisance_backends import (
    BACKENDS,
    RegisteredBackend,
    built_backend_services,
    built_backend_tags,
)


def _is_built(entry: RegisteredBackend) -> bool:
    return entry.image.startswith("mcp-auditor-cve-") and entry.image.endswith(":local")


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_a_backend_built_locally_names_the_compose_service_of_its_image(key: str):
    entry = BACKENDS[key]
    tags = [cve_targets.image_tag(service) for service in entry.built_services]

    if _is_built(entry):
        assert entry.image in tags
    else:
        assert tags == []


def test_the_pulled_backends_name_no_service():
    assert BACKENDS["doris"].built_services == ()
    assert BACKENDS["mysql"].built_services == ()


def _a_server_on(key: str, package: str = admission.SERVER_PACKAGE) -> AdmittedServer:
    entry = BACKENDS[key]
    backend = BackendFixture(provisioner=key, image=entry.image, network=entry.network)
    return admission.with_a_backend(run_given.a_server(package), backend)


def test_two_servers_on_one_backend_give_one_service():
    servers = [_a_server_on("ckan", "npm:one"), _a_server_on("ckan", "npm:two")]

    assert built_backend_services(servers) == ["ckan-responder"]


def test_a_pulled_backend_gives_no_service():
    assert built_backend_services([_a_server_on("doris")]) == []


def test_a_server_with_no_backend_gives_no_service():
    assert built_backend_services([run_given.a_server()]) == []


def test_the_built_backend_tags_are_the_image_tags_of_their_services():
    servers = [_a_server_on("ckan", "npm:one"), _a_server_on("neo4j", "npm:two")]

    assert built_backend_tags(servers) == [CKAN_RESPONDER_IMAGE, NEO4J_IMAGE]
