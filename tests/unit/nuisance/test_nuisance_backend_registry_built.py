import tests.unit.nuisance.support.test_nuisance_holdout_run_given as run_given
import tests.unit.support.admission_mutations as mutations
from evals.cve.backends.atlassian import ATLASSIAN_RESPONDER_IMAGE
from evals.cve.detection import targets as detection_targets
from evals.cve.nuisance.backend_registry import (
    BACKENDS,
    built_backend_services,
    built_backend_tags,
)


def test_two_servers_on_one_backend_give_one_service():
    servers = [
        mutations.on_the_ckan_backend(run_given.a_server("npm:one")),
        mutations.on_the_ckan_backend(run_given.a_server("npm:two")),
    ]

    assert built_backend_services(servers) == list(BACKENDS["ckan"].built_services)


def test_a_pulled_backend_gives_no_service():
    assert (
        built_backend_services(
            [mutations.with_the_registered_backend(run_given.a_server(), "doris")]
        )
        == []
    )


def test_a_server_with_no_backend_gives_no_service():
    assert built_backend_services([run_given.a_server()]) == []


def test_the_built_backend_tags_are_the_image_tags_of_their_services():
    servers = [
        mutations.on_the_ckan_backend(run_given.a_server("npm:one")),
        mutations.with_the_registered_backend(run_given.a_server("npm:two"), "atlassian"),
    ]

    assert built_backend_tags(servers) == [*_ckan_stack_tags(), ATLASSIAN_RESPONDER_IMAGE]


def _ckan_stack_tags() -> list[str]:
    return [detection_targets.image_tag(service) for service in BACKENDS["ckan"].built_services]
