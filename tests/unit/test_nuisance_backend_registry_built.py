import pytest

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_run_given as run_given
from evals.cve.backends.atlassian import ATLASSIAN_RESPONDER_IMAGE
from evals.cve.backends.responder import Responder
from evals.cve.detection import targets as detection_targets
from evals.cve.nuisance.backend_registry import (
    BACKENDS,
    built_backend_services,
    built_backend_tags,
)
from evals.cve.nuisance.fixtures import FIX_CHECK_FIXTURES
from tests.unit.support.test_backend_lifecycle_given import every_responder


def _is_built(image: str) -> bool:
    return image.startswith("mcp-auditor-cve-") and image.endswith(":local")


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_a_backend_built_locally_names_the_compose_service_of_its_image(key: str):
    entry = BACKENDS[key]
    tags = [detection_targets.image_tag(service) for service in entry.built_services]

    for image in entry.images:
        assert image in tags if _is_built(image) else "@sha256:" in image
    if not any(_is_built(image) for image in entry.images):
        assert tags == []


_BACKEND_ON = {entry.network: entry for entry in BACKENDS.values()}


@pytest.mark.parametrize(
    "responder",
    [responder for responder in every_responder() if responder.bridge in _BACKEND_ON],
    ids=lambda r: r.container,
)
def test_every_run_responder_image_is_rebuilt_with_its_backend(responder: Responder):
    built = _BACKEND_ON[responder.bridge].built_services

    assert responder.image in [detection_targets.image_tag(service) for service in built]


@pytest.mark.parametrize(
    "responder",
    [responder for responder in every_responder() if responder.bridge not in _BACKEND_ON],
    ids=lambda r: r.container,
)
def test_every_fix_check_responder_image_is_rebuilt_by_a_fix_check_naming_it(
    responder: Responder,
):
    named = (
        service for fixture in FIX_CHECK_FIXTURES for service in fixture.backend_services or ()
    )

    assert responder.image in [detection_targets.image_tag(service) for service in named]


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
    return [detection_targets.image_tag(service) for service in BACKENDS["ckan"].built_services]
