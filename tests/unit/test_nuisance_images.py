import pytest

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as given
from evals.cve.detection import targets as detection_targets
from evals.cve.kit import launch as kit_launch
from evals.cve.nuisance import images as nuisance_images
from evals.nuisance_admission import NuisanceAdmission


def test_the_three_image_namespaces_are_pairwise_distinct():
    tags = {
        detection_targets.image_tag("filesystem"),
        kit_launch.image_tag("filesystem"),
        nuisance_images.image_tag("filesystem"),
    }
    assert len(tags) == 3


@pytest.mark.parametrize("service", ["filesystem-patched", "sentinel"])
def test_an_acceptance_service_is_a_namespace_problem(service: str):
    [problem] = nuisance_images.namespace_problems(_with_service(service))
    assert service in problem


def test_a_clean_admission_has_no_namespace_problem():
    assert nuisance_images.namespace_problems(given.an_admission()) == []


def _with_service(service: str) -> NuisanceAdmission:
    return edits.with_the_server(
        given.an_admission(), lambda server: server.model_copy(update={"service": service})
    )
