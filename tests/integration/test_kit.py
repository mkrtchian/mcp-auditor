"""A real Docker launch of the filesystem acceptance image through the kit launch and client.

The guard the unit isolation test cannot be: a landmine Docker flag lost in the copy fails
list_tools or the benign call here, where the static scan sees nothing. Skipped or failed as
`docker_prerequisites` says. A missing or foreign image is rebuilt through compose.
"""

import pytest

from evals.cve.images import image_tag
from evals.cve.kit.client import KitMCPClient
from evals.cve.kit.driver import TargetVersion, launch_user_condition, options_before_image
from evals.cve.kit.launch import filesystem_env
from tests.integration.support.docker_prerequisites import image_prerequisites
from tests.unit.support.backend_launch_specs import an_empty_spec

_SERVICE = "filesystem"
_IMAGE = image_tag(_SERVICE)


@pytest.fixture(autouse=True, scope="module")
def _prerequisites() -> None:
    image_prerequisites([_SERVICE])


async def test_list_tools_and_a_benign_call_over_a_real_launch():
    spec = an_empty_spec()
    with filesystem_env(_IMAGE, spec) as launch:
        options = options_before_image(launch.args, _IMAGE)
        async with KitMCPClient.connect(launch) as client:
            tools = await client.list_tools()
            response = await client.call_tool("list_directory", {"path": "/srv/app"})

    assert "list_directory" in {tool.name for tool in tools}
    assert ".git" in response.content
    assert response.is_error is False
    assert launch_user_condition(TargetVersion.VULNERABLE, options, spec) is None
