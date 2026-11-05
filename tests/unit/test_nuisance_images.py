import pytest

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as given
from evals import cve_targets, nuisance_images
from evals.holdout_kit import kit_launch
from evals.nuisance_admission import NuisanceAdmission


def test_the_three_image_namespaces_are_pairwise_distinct():
    tags = {
        cve_targets.image_tag("filesystem"),
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


def test_admission_problems_carries_the_namespace_problem():
    admission = _with_service("sentinel")

    problems = given.problems_of(admission)

    assert any("sentinel" in problem for problem in problems)


def _with_service(service: str) -> NuisanceAdmission:
    return edits.with_the_server(
        given.an_admission(), lambda server: server.model_copy(update={"service": service})
    )
