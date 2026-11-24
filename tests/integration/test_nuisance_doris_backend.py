"""A real Docker launch of the kit's Doris backend builder.

The guard the unit isolation test cannot be: the builder ensures the heavy FE+BE cluster and
yields a launch that connects, and the benign call of the holdout target's detection fixture answers
without error. Behind NUISANCE_DORIS=1 because it pulls apache/doris:all-in-one-4.1.3 and
mysql:8.0.46, both pinned by digest, waits on the cluster's health (up to 240 s + 180 s) and leaves
the persistent cluster and its two networks running, as a holdout run does by design. Under the
flag, Docker absent skips, or fails when CVE_PLANTING_REQUIRED=1 (the test_cve_planting.py
convention).
"""

import os

import pytest

from evals.cve.backends.doris import DORIS_DB
from evals.cve.images import ComposeImageStore, ImageBuildFailed, ensure_images, image_tag
from evals.cve.kit.backends import doris_backend_env
from evals.cve.kit.client import KitMCPClient, docker_client_env
from evals.cve.planting import RANDOM_NONCES, PlantingHost, SymbolicUser, planting_spec
from tests.integration.support.docker_prerequisites import missing_prerequisite, skip_or_require

_SERVICE = "holdout-2025-66335-doris-patched"


@pytest.fixture(autouse=True, scope="module")
def _prerequisites() -> None:
    if os.environ.get("NUISANCE_DORIS") != "1":
        pytest.skip(
            "the nuisance Doris backend test pulls apache/doris:all-in-one-4.1.3 and "
            "mysql:8.0.46, both pinned by digest, waits on the cluster and leaves it running; "
            "set NUISANCE_DORIS=1 to run"
        )
    missing = missing_prerequisite()
    if missing is not None:
        skip_or_require(missing)
    try:
        ensure_images([_SERVICE], ComposeImageStore())
    except ImageBuildFailed as error:
        pytest.fail(str(error))


async def test_the_doris_backend_builder_launches_and_answers_a_benign_call():
    host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)
    spec = planting_spec((), host, RANDOM_NONCES)
    with doris_backend_env(image_tag(_SERVICE), spec) as launch:
        async with KitMCPClient.connect(
            launch.command, launch.args, env=docker_client_env(os.environ)
        ) as client:
            tools = await client.list_tools()
            response = await client.call_tool(
                "get_table_comment", {"table_name": "mytable", "db_name": DORIS_DB}
            )

    assert "get_table_comment" in {tool.name for tool in tools}
    assert response.is_error is False
    assert "my first table" in response.content
