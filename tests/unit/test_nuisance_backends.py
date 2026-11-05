import ipaddress

import pytest

import tests.unit.support.test_backend_lifecycle_given as given
from evals.ckan_backend import CKAN_ALIASES, CKAN_RESPONDER_IP, ckan_server_args
from evals.contextforge_backend import CONTEXTFORGE_RESPONDER_IP
from evals.docker_paths import DOCKER_DIRECTORY
from evals.gitlab_backend import GITLAB_RESPONDER_IP
from evals.googleapis_backend import GOOGLEAPIS_RESPONDER_IP
from evals.jenkins_backend import JENKINS_RESPONDER_IP
from evals.neo4j_backend import NEO4J_HOST
from tests.unit.support.docker_argv import carries, values_after

# These servers take their backend's address from their image, so the address baked into the run
# Dockerfile and its vulnerable twin has to be the one the backend stands its responder at.
_BAKED_ADDRESSES = {
    "contextforge": f'"GW_BENIGN_URL", "http://{CONTEXTFORGE_RESPONDER_IP}/"',
    "jenkins": f"JENKINS_URL=http://{JENKINS_RESPONDER_IP}",
    "gitlab": f"GITLAB_API_URL=http://{GITLAB_RESPONDER_IP}/",
    "googleapis": f"UPSTREAM_URL=http://{GOOGLEAPIS_RESPONDER_IP}",
    "neo4j": f"NEO4J_URI=bolt://{NEO4J_HOST}:",
}


def test_the_contextforge_responder_ip_is_global():
    # The patched gateway refuses a REST tool whose host is private by `ipaddress`, and the
    # documentation ranges count as private there.
    assert ipaddress.ip_address(CONTEXTFORGE_RESPONDER_IP).is_global


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


def test_the_ckan_portal_hosts_resolve_to_the_self_signed_responder_the_server_trusts():
    args = ckan_server_args("server-name", "image", given.a_host(), ["serve"])

    assert sorted(values_after(args, "--add-host")) == sorted(
        f"{alias}:{CKAN_RESPONDER_IP}" for alias in CKAN_ALIASES
    )
    assert carries(args, ["-e", "NODE_TLS_REJECT_UNAUTHORIZED=0"])
