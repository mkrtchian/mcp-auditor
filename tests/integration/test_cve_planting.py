# The acceptance test of the real CVE planting path: a real sentinel served by a real
# busybox container, read by a container started with the target's planted arguments. It is
# the only instrument of the production `DockerPlanting` and the readiness probe (the fake
# stands in everywhere else), so it must go red on a planting regression.
#
# Skipped without Docker, as `test_confined_launch.py` is. `CVE_PLANTING_REQUIRED=1`, set by
# the CI integration job and the CVE calibration job, turns that skip into a failure: a green
# step there must mean the planting path ran. A missing or foreign sentinel image is rebuilt
# through compose before the first case.
import os
import time

import pytest

import tests.integration.support.test_cve_planting_given as given
import tests.integration.support.test_cve_planting_then as then
from evals.cve_images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve_planting import DockerPlanting, PlantingFailed, planted
from evals.cve_planting_base import SENTINEL_IMAGE, SENTINEL_SERVICE


@pytest.fixture(autouse=True, scope="module")
def _planting_prerequisites() -> None:
    missing = given.missing_prerequisite()
    if missing is not None:
        if os.environ.get("CVE_PLANTING_REQUIRED") == "1":
            pytest.fail(missing)
        pytest.skip(missing)
    try:
        ensure_images([SENTINEL_SERVICE], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


def test_a_planted_ip_literal_endpoint_serves_its_nonce():
    spec = given.spec_of(given.IP_LITERAL, "/fict/secret")

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = given.read_as_target(args, given.IP_LITERAL, "/fict/secret")

    assert body == spec.nonces["endpoint-1"]


def test_two_coexisting_launches_each_serve_their_own_nonce():
    spec_a = given.spec_of(given.IP_LITERAL, "/fict/a")
    spec_b = given.spec_of(given.IP_LITERAL, "/fict/b")

    with (
        planted(spec_a, SENTINEL_IMAGE, DockerPlanting()) as args_a,
        planted(spec_b, SENTINEL_IMAGE, DockerPlanting()) as args_b,
    ):
        body_a = given.read_as_target(args_a, given.IP_LITERAL, "/fict/a")
        body_b = given.read_as_target(args_b, given.IP_LITERAL, "/fict/b")

    assert body_a == spec_a.nonces["endpoint-1"]
    assert body_b == spec_b.nonces["endpoint-1"]
    assert body_a != body_b


@pytest.mark.parametrize(
    "path",
    [
        "/fict/dir/",
        "/fict/meta?api-version=1",
        "/fict/a#frag",
        "/fict/sp ace/x",
        "/fict/a%20b",
        "/",
        "/fict/café",
    ],
)
def test_a_path_a_client_rewrites_on_the_wire_serves_the_nonce(path: str):
    spec = given.spec_of(given.IP_LITERAL, path)

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = given.read_as_target(args, given.IP_LITERAL, path)

    assert body == spec.nonces["endpoint-1"]


@pytest.mark.parametrize(
    ("host", "has_network"),
    [("meta.fict", False), ("meta.fict", True), ("localhost", False)],
    ids=["reserved_block_add_host", "bridge_alias", "localhost"],
)
def test_a_name_host_serves_its_nonce_read_by_name(host: str, has_network: bool):
    spec = given.spec_of(host, "/fict/secret", has_network=has_network)

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = given.read_as_target(args, host, "/fict/secret")

    assert body == spec.nonces["endpoint-1"]


@pytest.mark.parametrize("has_network", [False, True], ids=["no_network", "network"])
def test_a_file_place_beside_a_name_host_still_serves_its_nonce(has_network: bool):
    spec = given.spec_of("meta.fict", "/fict/secret", has_network=has_network, file_at="/etc/fict")

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = given.read_as_target(args, "meta.fict", "/fict/secret")

    assert body == spec.nonces["endpoint-1"]


def test_a_file_place_over_etc_hosts_beside_a_name_host_fails_the_probe(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr("evals.cve_planting_docker._SENTINEL_PROBE_BUDGET", 3.0)
    spec = given.spec_of("meta.fict", "/fict/secret", file_at="/etc/hosts")

    with pytest.raises(PlantingFailed), planted(spec, SENTINEL_IMAGE, DockerPlanting()):
        pass


def test_a_file_place_over_resolv_conf_beside_a_bridge_alias_fails_the_probe(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr("evals.cve_planting_docker._SENTINEL_PROBE_BUDGET", 3.0)
    spec = given.spec_of("meta.fict", "/fict/secret", has_network=True, file_at="/etc/resolv.conf")

    with pytest.raises(PlantingFailed), planted(spec, SENTINEL_IMAGE, DockerPlanting()):
        pass


def test_a_one_sentinel_launch_tears_down_well_under_the_sigterm_grace():
    spec = given.spec_of(given.IP_LITERAL, "/fict/secret")

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        assert given.read_as_target(args, given.IP_LITERAL, "/fict/secret")
        start = time.monotonic()
    teardown = time.monotonic() - start

    assert teardown < 8.0  # `docker rm -f`, never the 10 s `docker stop` SIGTERM grace


def test_no_labelled_container_or_network_outlives_two_launches():
    docker = given.RecordingPlanting()

    for suffix in ("/fict/one", "/fict/two"):
        spec = given.spec_of(given.IP_LITERAL, suffix, has_network=True)
        with planted(spec, SENTINEL_IMAGE, docker) as args:
            assert given.read_as_target(args, given.IP_LITERAL, suffix) == spec.nonces["endpoint-1"]

    then.nothing_it_made_outlives(docker)
