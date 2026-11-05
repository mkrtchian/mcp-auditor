# The proof that a closed fixture network reaches neither the host nor the Internet: a listener
# on the host's every address, the sentinel image as the client. The control on a plain network
# keeps the closed case from passing on a listener that was unreachable anyway. The planted case
# checks the path every networked target takes, a container joined to a planting's holder.
#
# Skipped without Docker, failed under `CVE_PLANTING_REQUIRED=1`, as `test_cve_planting.py`. A
# missing or foreign sentinel image is rebuilt through compose before the first case.
import os

import pytest

import tests.integration.support.test_closed_networks_given as given
import tests.integration.support.test_closed_networks_then as then
from evals.closed_network import ensure_closed_network
from evals.cve_images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve_planting_base import SENTINEL_SERVICE


@pytest.fixture(autouse=True, scope="module")
def _docker_prerequisites() -> None:
    missing = given.missing_prerequisite()
    if missing is not None:
        if os.environ.get("CVE_PLANTING_REQUIRED") == "1":
            pytest.fail(missing)
        pytest.skip(missing)
    try:
        ensure_images([SENTINEL_SERVICE], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


def test_a_closed_network_reaches_neither_the_host_nor_the_internet():
    with (
        given.a_host_listener() as port,
        given.a_closed_network() as network,
        given.a_container_on(network) as container,
    ):
        then.unreachable(container, port)
        then.no_default_route(container)
        then.pinned_name_resolves_and_unpinned_fails_fast(container)


def test_a_planted_launch_with_a_network_reaches_neither_the_host_nor_the_internet():
    with (
        given.a_host_listener() as port,
        given.a_planted_launch_with_a_network() as args,
        given.a_container_with(args) as container,
    ):
        assert given.reaches(container, given.IP_LITERAL, 80)
        then.unreachable(container, port)
        then.no_default_route(container)


def test_a_plain_network_reaches_the_host_listener_through_its_gateway():
    with (
        given.a_host_listener() as port,
        given.an_open_network() as network,
        given.a_container_on(network) as container,
    ):
        assert given.reaches(container, given.gateway(container), port)


def test_an_open_labelled_network_with_a_running_container_is_recreated_closed():
    with given.an_open_network() as network, given.a_started_container_on(network) as container:
        ensure_closed_network(network)

        then.closed_without(network, container)
