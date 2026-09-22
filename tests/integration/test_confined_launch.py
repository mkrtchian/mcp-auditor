# The acceptance test of the confined path: a real Docker container, the real
# default launcher table, a public npm server.
#
# The pragmas below cover the imports made inside the test body, which do not
# resolve until the confined path is wired. They go away with the xfail marker.
# pyright: basic
# pyright: reportMissingImports=false, reportAttributeAccessIssue=false
import os
import pathlib
import subprocess
from uuid import uuid4

import pytest

from mcp_auditor.adapters.mcp_client import StdioMCPClient

# Pinned, as the README pins the demo's: this test is the only instrument of the
# confined path, so it must go red on a confinement regression and never on an
# upstream rename.
FILESYSTEM_SERVER = "@modelcontextprotocol/server-filesystem@2026.8.31"


def docker_answers() -> bool:
    try:
        return subprocess.run(["docker", "version"], capture_output=True).returncode == 0
    except OSError:
        return False


@pytest.mark.skipif(not docker_answers(), reason="confined execution needs Docker")
@pytest.mark.xfail(strict=True, raises=ImportError, reason="confined path not wired yet")
async def test_confined_launch_serves_the_filesystem_server(tmp_path: pathlib.Path) -> None:
    from mcp_auditor.target_execution import (
        Host,
        LaunchContext,
        LaunchOptions,
        TargetExecution,
        decide_launch,
    )

    from mcp_auditor.adapters.docker import DockerRuntime, docker_client_env

    runtime = DockerRuntime()
    container_name = f"mcp-auditor-{uuid4().hex[:12]}"
    context = LaunchContext(
        options=LaunchOptions(unconfined=False, image=None, mounts=()),
        runtime=runtime,
        host=Host(
            uid=os.getuid(),
            gid=os.getgid(),
            home=pathlib.Path.home(),
            docker_env=docker_client_env(os.environ),
        ),
        container_name=container_name,
    )
    launch = decide_launch("npx", [FILESYSTEM_SERVER, str(tmp_path)], context).launch

    execution = TargetExecution(launch, runtime)
    async with execution, StdioMCPClient.connect(launch) as client:
        tools = await client.list_tools()

    assert "list_directory" in {tool.name for tool in tools}
    assert execution.record is not None
    assert execution.record.oom_killed is False
    assert str(tmp_path.resolve()) in (execution.record.writable_paths or [])
    assert containers_named(container_name) == ""


def containers_named(name: str) -> str:
    listing = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={name}"],
        capture_output=True,
        text=True,
    )
    return "\n".join(listing.stdout.splitlines()[1:]).strip()
