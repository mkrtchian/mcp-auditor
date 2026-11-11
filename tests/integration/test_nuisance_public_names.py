# A nuisance server with no backend whose admission declares a public name: its single-container
# launch joins the holder serving that name under its real name, with no network of its own.
#
# Skipped without Docker or openssl. `CVE_PLANTING_REQUIRED=1` turns that skip into a failure,
# as in `test_cve_planting.py`.
import os
import subprocess
from pathlib import Path

import pytest

import tests.integration.support.test_cve_planting_given as planting
import tests.integration.support.test_cve_planting_stand_ins_given as given
from evals.cve.images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve_planting_base import (
    SENTINEL_IMAGE,
    SENTINEL_SERVICE,
    STAND_IN_SERVICE,
    PlantingHost,
    PublicNames,
    SymbolicUser,
)
from evals.nuisance_confinement import single_container_launch_args
from tests.integration.support.test_cve_planting_then import no_container_it_started_outlives


@pytest.fixture(autouse=True, scope="module")
def _stand_in_prerequisites() -> None:
    missing = planting.missing_prerequisite() or given.missing_openssl()
    if missing is not None:
        if os.environ.get("CVE_PLANTING_REQUIRED") == "1":
            pytest.fail(missing)
        pytest.skip(missing)
    try:
        ensure_images([SENTINEL_SERVICE, STAND_IN_SERVICE], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


def test_a_backend_less_server_reaches_its_public_name_through_the_stand_in(tmp_path: Path):
    names = PublicNames(stand_ins=(given.STAND_IN_HOST,))
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False, public_names=names)
    docker = planting.RecordingPlanting()
    fetch = ["-qO-", f"http://{given.STAND_IN_HOST}/"]

    with single_container_launch_args(
        SENTINEL_IMAGE,
        host,
        fetch,
        docker=docker,
        stand_ins_directory=given.a_stand_ins_directory(tmp_path),
    ) as args:
        # The busybox image's own entrypoint serves a file; wget stands for the server.
        image = args.index(SENTINEL_IMAGE)
        command = [*args[:image], "--entrypoint", "wget", *args[image:]]
        result = subprocess.run(
            ["docker", *command], capture_output=True, text=True, timeout=60, check=False
        )

    assert (result.returncode, result.stdout) == (0, given.PLAIN_BODY), result.stderr
    assert "none" not in args[args.index("--network") + 1]
    assert docker.networks == []
    no_container_it_started_outlives(docker)
