"""A real Docker launch of the kit's Doris backend builder.

The guard the unit isolation test cannot be: the builder ensures the heavy FE+BE cluster and
yields a launch that connects, and the holdout fixture's benign call answers without error. Behind
NUISANCE_DORIS=1 because it pulls apache/doris:all-in-one-4.1.3 and mysql:8.0.46, waits on the
cluster's health (up to 240 s + 180 s) and leaves the persistent cluster and its two networks
running, as the holdout does by design. Under the flag, Docker absent skips, or fails when
CVE_PLANTING_REQUIRED=1 (the test_cve_planting.py convention).
"""

import os
import subprocess

import pytest

from evals import cve_targets
from evals.cve_images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve_planting import RANDOM_NONCES, PlantingHost, SymbolicUser, planting_spec
from evals.doris_backend import DORIS_DB
from evals.holdout_kit.kit_backends import doris_backend_env
from evals.holdout_kit.kit_client import KitMCPClient, docker_client_env

_SERVICE = "holdout-2025-66335-doris-patched"


def _missing_prerequisite() -> str | None:
    if _docker("version") != 0:
        return "the nuisance Doris backend test needs Docker"
    return None


def _docker(*args: str) -> int:
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True).returncode
    except OSError:
        return 127


@pytest.fixture(autouse=True, scope="module")
def _prerequisites() -> None:
    if os.environ.get("NUISANCE_DORIS") != "1":
        pytest.skip(
            "the nuisance Doris backend test pulls apache/doris:all-in-one-4.1.3 and "
            "mysql:8.0.46, waits on the cluster and leaves it running; set NUISANCE_DORIS=1 to run"
        )
    missing = _missing_prerequisite()
    if missing is not None:
        if os.environ.get("CVE_PLANTING_REQUIRED") == "1":
            pytest.fail(missing)
        pytest.skip(missing)
    try:
        ensure_images([_SERVICE], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


async def test_the_doris_backend_builder_launches_and_answers_a_benign_call():
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
    spec = planting_spec((), host, RANDOM_NONCES)
    with doris_backend_env(cve_targets.image_tag(_SERVICE), spec) as launch:
        async with KitMCPClient.connect(
            launch.command, launch.args, env=docker_client_env(os.environ)
        ) as client:
            tools = await client.list_tools()
            response = await client.call_tool(
                "get_table_comment", {"table_name": "t1", "db_name": DORIS_DB}
            )

    assert "get_table_comment" in {tool.name for tool in tools}
    assert response.is_error is False
