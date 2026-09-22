# The acceptance test of the confined path: a real Docker container, the real
# default launcher table, a public npm server.
import os
import pathlib
import subprocess
from uuid import uuid4

import pytest

from mcp_auditor.adapters.docker import DockerRuntime, docker_client_env
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.target_execution import (
    Host,
    LaunchContext,
    LaunchOptions,
    TargetExecution,
    decide_launch,
)

# Pinned, as the README pins the demo's: this test is the only instrument of the
# confined path, so it must go red on a confinement regression and never on an
# upstream rename.
FILESYSTEM_SERVER = "@modelcontextprotocol/server-filesystem@2026.8.31"


@pytest.mark.skipif(not DockerRuntime().available(), reason="confined execution needs Docker")
async def test_confined_launch_serves_the_filesystem_server(tmp_path: pathlib.Path) -> None:
    runtime = DockerRuntime()
    container_name = f"mcp-auditor-{uuid4().hex[:12]}"
    # A comma and a colon, both legal on this host and both fatal to a mount argument
    # that does not quote its fields: the daemon is the only judge of that spelling.
    workspace = tmp_path / "data,v2" / "09:30"
    workspace.mkdir(parents=True)
    reference = tmp_path / "ref,1" / "12:00"
    reference.mkdir(parents=True)
    context = LaunchContext(
        options=LaunchOptions(unconfined=False, image=None, mounts=(f"{reference}:ro",)),
        runtime=runtime,
        host=Host(
            uid=os.getuid(),
            gid=os.getgid(),
            home=pathlib.Path.home(),
            docker_env=docker_client_env(os.environ),
        ),
        container_name=container_name,
    )
    target = [FILESYSTEM_SERVER, str(workspace), str(reference)]
    launch = decide_launch("npx", target, context).launch

    execution = TargetExecution(launch, runtime)
    async with execution, StdioMCPClient.connect(launch) as client:
        tools = await client.list_tools()
        written = await client.call_tool(
            "write_file", {"path": f"{workspace}/note.txt", "content": "hello"}
        )
        refused = await client.call_tool(
            "write_file", {"path": f"{reference}/note.txt", "content": "hello"}
        )

    assert "list_directory" in {tool.name for tool in tools}
    # The declared mount wins over the argv default, so the daemon, not the plan, is what
    # makes the second path unwritable.
    assert not written.is_error
    assert refused.is_error or "read-only" in refused.content.lower()
    assert execution.record is not None
    assert execution.record.oom_killed is False
    assert str(workspace.resolve()) in (execution.record.writable_paths or [])
    assert str(reference.resolve()) in (execution.record.read_only_paths or [])
    assert containers_named(container_name) == ""


def containers_named(name: str) -> str:
    listing = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={name}"],
        capture_output=True,
        text=True,
    )
    return "\n".join(listing.stdout.splitlines()[1:]).strip()
