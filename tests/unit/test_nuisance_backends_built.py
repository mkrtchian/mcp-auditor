import pytest

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_run_given as run_given
from evals import cve_targets
from evals.atlassian_backend import ATLASSIAN_RESPONDER_IMAGE
from evals.nuisance_backends import (
    BACKENDS,
    RegisteredBackend,
    built_backend_services,
    built_backend_tags,
)
from evals.responder_backend import Responder
from tests.unit.support.test_backend_lifecycle_given import every_responder


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
        assert "@sha256:" in entry.image


@pytest.mark.parametrize("responder", every_responder(), ids=lambda r: r.container)
def test_every_responder_image_is_rebuilt_with_its_backend(responder: Responder):
    backend_on = {entry.network: entry for entry in BACKENDS.values()}

    built = backend_on[responder.bridge].built_services
    assert responder.image in [cve_targets.image_tag(service) for service in built]


def test_two_servers_on_one_backend_give_one_service():
    servers = [
        edits.on_the_ckan_backend(run_given.a_server("npm:one")),
        edits.on_the_ckan_backend(run_given.a_server("npm:two")),
    ]

    assert built_backend_services(servers) == list(BACKENDS["ckan"].built_services)


def test_a_pulled_backend_gives_no_service():
    assert (
        built_backend_services([edits.with_the_registered_backend(run_given.a_server(), "doris")])
        == []
    )


def test_a_server_with_no_backend_gives_no_service():
    assert built_backend_services([run_given.a_server()]) == []


def test_the_built_backend_tags_are_the_image_tags_of_their_services():
    servers = [
        edits.on_the_ckan_backend(run_given.a_server("npm:one")),
        edits.with_the_registered_backend(run_given.a_server("npm:two"), "atlassian"),
    ]

    assert built_backend_tags(servers) == [*_ckan_stack_tags(), ATLASSIAN_RESPONDER_IMAGE]


def _ckan_stack_tags() -> list[str]:
    return [cve_targets.image_tag(service) for service in BACKENDS["ckan"].built_services]
