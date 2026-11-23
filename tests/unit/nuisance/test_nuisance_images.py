import pytest

import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_admissions as admissions
from evals.cve import images as cve_images
from evals.cve.kit import launch as kit_launch
from evals.cve.nuisance import images as nuisance_images
from evals.cve.nuisance.admission.admission import NuisanceAdmission


def test_the_three_image_namespaces_are_pairwise_distinct():
    tags = {
        cve_images.image_tag("filesystem"),
        kit_launch.image_tag("filesystem"),
        nuisance_images.image_tag("filesystem"),
    }
    assert len(tags) == 3


@pytest.mark.parametrize("service", ["filesystem-patched", "sentinel"])
def test_an_acceptance_service_is_a_namespace_problem(service: str):
    [problem] = nuisance_images.namespace_problems(_with_service(service))
    assert service in problem


def test_a_clean_admission_has_no_namespace_problem():
    assert nuisance_images.namespace_problems(admissions.an_admission()) == []


def _with_service(service: str) -> NuisanceAdmission:
    return mutations.with_the_server(
        admissions.an_admission(), lambda server: server.model_copy(update={"service": service})
    )
