# A nuisance server with no backend whose admission declares a public name: its single-container
# launch joins the holder serving that name under its real name, with no network of its own.
#
# Skipped without Docker or openssl. `CVE_PLANTING_REQUIRED=1` turns that skip into a failure,
# as in `test_cve_planting.py`.
import subprocess
from pathlib import Path

import pytest

import tests.integration.support.stand_in_capture as stand_in_capture
from evals.cve.nuisance.confinement import single_container_launch_args
from evals.cve.planting_base import (
    SENTINEL_IMAGE,
    PlantingHost,
    PublicNames,
    SymbolicUser,
)
from tests.integration.support.docker_prerequisites import stand_in_prerequisites
from tests.integration.support.recording_planting import (
    RecordingPlanting,
    no_container_it_started_outlives,
)
from tests.unit.support.docker_argv import value_after
from tests.unit.support.fictional_stand_ins import HOST as STAND_IN_HOST


@pytest.fixture(autouse=True, scope="module")
def _stand_in_prerequisites() -> None:
    stand_in_prerequisites()


def test_a_backend_less_server_reaches_its_public_name_through_the_stand_in(tmp_path: Path):
    names = PublicNames(stand_ins=(STAND_IN_HOST,))
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False, public_names=names)
    docker = RecordingPlanting()
    fetch = ["-qO-", f"http://{STAND_IN_HOST}/"]

    with single_container_launch_args(
        SENTINEL_IMAGE,
        host,
        fetch,
        docker=docker,
        stand_ins_directory=stand_in_capture.a_stand_ins_directory(tmp_path),
    ) as args:
        # The busybox image's own entrypoint serves a file; wget stands for the server.
        image = args.index(SENTINEL_IMAGE)
        command = [*args[:image], "--entrypoint", "wget", *args[image:]]
        result = subprocess.run(
            ["docker", *command], capture_output=True, text=True, timeout=60, check=False
        )

    assert (result.returncode, result.stdout) == (0, stand_in_capture.PLAIN_BODY), result.stderr
    assert value_after(args, "--network").startswith("container:")
    assert docker.networks == []
    no_container_it_started_outlives(docker)
