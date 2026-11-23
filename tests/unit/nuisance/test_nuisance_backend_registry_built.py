import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_holdout_runs as holdout_runs
from evals.cve import images as cve_images
from evals.cve.backends.atlassian import ATLASSIAN_RESPONDER_IMAGE
from evals.cve.nuisance.backend_registry import (
    BACKENDS,
    built_backend_services,
    built_backend_tags,
)


def test_two_servers_on_one_backend_give_one_service():
    servers = [
        mutations.on_the_ckan_backend(holdout_runs.a_server("npm:one")),
        mutations.on_the_ckan_backend(holdout_runs.a_server("npm:two")),
    ]

    assert built_backend_services(servers) == list(BACKENDS["ckan"].built_services)


def test_a_pulled_backend_gives_no_service():
    assert (
        built_backend_services(
            [mutations.with_the_registered_backend(holdout_runs.a_server(), "doris")]
        )
        == []
    )


def test_a_server_with_no_backend_gives_no_service():
    assert built_backend_services([holdout_runs.a_server()]) == []


def test_the_built_backend_tags_are_the_image_tags_of_their_services():
    servers = [
        mutations.on_the_ckan_backend(holdout_runs.a_server("npm:one")),
        mutations.with_the_registered_backend(holdout_runs.a_server("npm:two"), "atlassian"),
    ]

    assert built_backend_tags(servers) == [*_ckan_stack_tags(), ATLASSIAN_RESPONDER_IMAGE]


def _ckan_stack_tags() -> list[str]:
    return [cve_images.image_tag(service) for service in BACKENDS["ckan"].built_services]
