import re

import pytest

import tests.unit.nuisance.admission.support.test_nuisance_admission_given as admission_given
from evals.cve.backends.gitlab import GITLAB_HOST
from evals.cve.backends.googleapis import GOOGLEAPIS_RESPONDER_IP
from evals.cve.backends.jenkins import JENKINS_URL
from evals.cve.docker_paths import DOCKER_DIRECTORY
from evals.cve.nuisance.admission.admission import BackendFixture
from evals.cve.nuisance.backend_registry import BACKENDS, backend_problems

# These servers take their backend's address from their image, so the address baked into the run
# Dockerfile and its vulnerable one has to be the one the backend stands at.
_BAKED_ADDRESSES = {
    "jenkins": f"JENKINS_URL={JENKINS_URL}",
    "gitlab": f"GITLAB_API_URL=http://{GITLAB_HOST}/",
    "googleapis": f"UPSTREAM_URL=http://{GOOGLEAPIS_RESPONDER_IP}",
}


@pytest.mark.parametrize(
    ("dockerfile", "baked"),
    [
        (f"Dockerfile.{service}{suffix}", baked)
        for service, baked in _BAKED_ADDRESSES.items()
        for suffix in ("", "-vuln")
    ],
)
def test_the_run_image_bakes_the_address_its_backend_stands_at(dockerfile: str, baked: str):
    assert baked in (DOCKER_DIRECTORY / dockerfile).read_text()


@pytest.mark.parametrize("dockerfile", ["Dockerfile.jenkins", "Dockerfile.jenkins-vuln"])
def test_the_jenkins_run_image_bakes_the_api_token_the_controller_image_seeds(dockerfile: str):
    controller = (DOCKER_DIRECTORY / "Dockerfile.jenkins-responder").read_text()
    seeded = re.search(r"^ARG JENKINS_API_TOKEN=(\S+)$", controller, re.MULTILINE)

    assert seeded is not None
    assert f"JENKINS_TOKEN={seeded[1]}" in (DOCKER_DIRECTORY / dockerfile).read_text()


@pytest.mark.parametrize("key", [key for key, entry in BACKENDS.items() if entry.built_services])
def test_a_built_backend_resets_no_container_by_name(key: str):
    assert BACKENDS[key].reset_containers == ()


def test_a_recorded_backend_whose_image_list_differs_from_the_registered_one_is_refused():
    recorded = BackendFixture(
        provisioner="fake", images=["fake/backend:1.0", "fake/extra:1.0"], network="fake-net"
    )
    server = admission_given.with_a_backend(admission_given.an_admitted_server(), recorded)

    problems = backend_problems(server, admission_given.a_backend_registry())

    assert len(problems) == 1
    assert "is not the registered" in problems[0]
