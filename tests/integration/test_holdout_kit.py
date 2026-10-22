"""A real Docker launch of the filesystem acceptance image through kit_launch + kit_client.

The guard the unit isolation test cannot be: a landmine Docker flag lost in the copy fails
list_tools or the benign call here, where the static scan sees nothing. Skipped without Docker,
the test_cve_planting.py convention (CVE_PLANTING_REQUIRED=1 turns the skip into a failure). A
missing or foreign image is rebuilt through compose.
"""

import os
import subprocess

import pytest

from evals.cve_images import ComposeImageStore, ImageBuildFailed, ensure_images
from evals.cve_planting import RANDOM_NONCES, PlantingHost, SymbolicUser, planting_spec
from evals.cve_targets import image_tag
from evals.holdout_kit.kit_client import KitMCPClient, docker_client_env
from evals.holdout_kit.kit_launch import filesystem_env

_SERVICE = "filesystem"
_IMAGE = image_tag(_SERVICE)


def _missing_prerequisite() -> str | None:
    if _docker("version") != 0:
        return "the holdout kit integration test needs Docker"
    return None


def _docker(*args: str) -> int:
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True).returncode
    except OSError:
        return 127


@pytest.fixture(autouse=True, scope="module")
def _prerequisites() -> None:
    missing = _missing_prerequisite()
    if missing is not None:
        if os.environ.get("CVE_PLANTING_REQUIRED") == "1":
            pytest.fail(missing)
        pytest.skip(missing)
    try:
        ensure_images([_SERVICE], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


async def test_list_tools_and_a_benign_call_over_a_real_launch():
    host = PlantingHost(SymbolicUser.HOST, "/", has_network=False)
    spec = planting_spec((), host, RANDOM_NONCES)
    with filesystem_env(_IMAGE, spec) as launch:
        async with KitMCPClient.connect(
            launch.command, launch.args, env=docker_client_env(os.environ)
        ) as client:
            tools = await client.list_tools()
            response = await client.call_tool("list_directory", {"path": "/srv/app"})

    assert "list_directory" in {tool.name for tool in tools}
    assert ".git" in response.content
    assert response.is_error is False
