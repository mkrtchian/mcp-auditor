# The acceptance test of the real CVE planting path: a real sentinel served by a real
# busybox container, read from inside the holder namespace a target would join. It is the
# only instrument of the production `DockerPlanting` and the readiness probe (the fake
# stands in everywhere else), so it must go red on a planting regression.
#
# Skipped without Docker, as `test_confined_launch.py` is, and skipped when the sentinel
# image is absent: the CI integration job has Docker but builds no image, so a missing image
# must skip rather than trigger a registry pull. A stale image (built before the entrypoint
# wrote `$FLAG` at `SERVE_FILE`, the file the harness computes with `served_file`) serves
# nothing at the planted path, so every case fails: rebuild with
# `docker compose -f evals/docker/compose.yml build`.
import subprocess
import time

import pytest

from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting import (
    RANDOM_NONCES,
    DockerPlanting,
    PlantedArgs,
    PlantingHost,
    SymbolicUser,
    planted,
    planting_spec,
)
from evals.cve_planting_base import LABEL, SENTINEL_IMAGE
from evals.cve_planting_spec import request_target
from mcp_auditor.adapters.docker import DockerRuntime

_HAS_DOCKER = DockerRuntime().available()


def _sentinel_image_present() -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", SENTINEL_IMAGE], capture_output=True, text=True
    )
    return result.returncode == 0


requires_docker = pytest.mark.skipif(not _HAS_DOCKER, reason="CVE planting needs Docker")
requires_sentinel_image = pytest.mark.skipif(
    _HAS_DOCKER and not _sentinel_image_present(),
    reason=f"{SENTINEL_IMAGE} absent: docker compose -f evals/docker/compose.yml build",
)

_IP_LITERAL = "198.51.100.5"  # RFC 5737 documentation range: routes nowhere


def _endpoint_place(host: str, path: str) -> Place:
    return Place(
        id="endpoint-1",
        family="fictional-family",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.HTTP_ENDPOINT,
        coordinates=Coordinates(PlantKind.HTTP_ENDPOINT, host=host, path=path),
    )


def _spec_of(host: str, path: str, *, has_network: bool = False):
    place = _endpoint_place(host, path)
    planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/fictional", has_network)
    return planting_spec([place], planting_host, RANDOM_NONCES)


def _read_in_namespace(args: PlantedArgs, host: str, path: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            *args.network,
            "--entrypoint",
            "wget",
            SENTINEL_IMAGE,
            "-qO-",
            f"http://{host}:80{request_target(path)}",
        ],
        capture_output=True,
        text=True,
    )
    return result.stdout


def _labelled_containers() -> set[str]:
    result = subprocess.run(
        ["docker", "ps", "-aq", "--filter", f"label={LABEL}"], capture_output=True, text=True
    )
    return set(result.stdout.split())


def _labelled_networks() -> set[str]:
    result = subprocess.run(
        ["docker", "network", "ls", "-q", "--filter", f"label={LABEL}"],
        capture_output=True,
        text=True,
    )
    return set(result.stdout.split())


@requires_docker
@requires_sentinel_image
def test_a_planted_ip_literal_endpoint_serves_its_nonce():
    spec = _spec_of(_IP_LITERAL, "/fict/secret")

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = _read_in_namespace(args, _IP_LITERAL, "/fict/secret")

    assert body == spec.nonces["endpoint-1"]


@requires_docker
@requires_sentinel_image
def test_two_concurrent_launches_each_serve_their_own_nonce():
    spec_a = _spec_of(_IP_LITERAL, "/fict/a")
    spec_b = _spec_of(_IP_LITERAL, "/fict/b")

    with (
        planted(spec_a, SENTINEL_IMAGE, DockerPlanting()) as args_a,
        planted(spec_b, SENTINEL_IMAGE, DockerPlanting()) as args_b,
    ):
        body_a = _read_in_namespace(args_a, _IP_LITERAL, "/fict/a")
        body_b = _read_in_namespace(args_b, _IP_LITERAL, "/fict/b")

    assert body_a == spec_a.nonces["endpoint-1"]
    assert body_b == spec_b.nonces["endpoint-1"]
    assert body_a != body_b


@requires_docker
@requires_sentinel_image
@pytest.mark.parametrize(
    "path",
    ["/fict/dir/", "/fict/meta?api-version=1", "/fict/a#frag", "/fict/sp ace/x", "/fict/a%20b"],
)
def test_a_path_a_client_rewrites_on_the_wire_serves_the_nonce(path: str):
    spec = _spec_of(_IP_LITERAL, path)

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = _read_in_namespace(args, _IP_LITERAL, path)

    assert body == spec.nonces["endpoint-1"]


@requires_docker
@requires_sentinel_image
@pytest.mark.parametrize(
    ("host", "has_network"),
    [("meta.fict", False), ("meta.fict", True), ("localhost", False)],
    ids=["reserved_block_add_host", "bridge_alias", "localhost"],
)
def test_a_name_host_serves_its_nonce_read_by_name(host: str, has_network: bool):
    spec = _spec_of(host, "/fict/secret", has_network=has_network)

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        body = _read_in_namespace(args, host, "/fict/secret")

    assert body == spec.nonces["endpoint-1"]


@requires_docker
@requires_sentinel_image
def test_a_one_sentinel_launch_tears_down_well_under_the_sigterm_grace():
    spec = _spec_of(_IP_LITERAL, "/fict/secret")

    with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
        assert _read_in_namespace(args, _IP_LITERAL, "/fict/secret")
        start = time.monotonic()
    teardown = time.monotonic() - start

    assert teardown < 8.0  # `docker rm -f`, never the 10 s `docker stop` SIGTERM grace


@requires_docker
@requires_sentinel_image
def test_no_labelled_container_or_network_outlives_two_launches():
    before_containers = _labelled_containers()
    before_networks = _labelled_networks()

    for suffix in ("/fict/one", "/fict/two"):
        spec = _spec_of(_IP_LITERAL, suffix, has_network=True)
        with planted(spec, SENTINEL_IMAGE, DockerPlanting()) as args:
            assert _read_in_namespace(args, _IP_LITERAL, suffix) == spec.nonces["endpoint-1"]

    assert _labelled_containers() <= before_containers
    assert _labelled_networks() <= before_networks
