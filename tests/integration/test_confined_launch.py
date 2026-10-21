# The acceptance test of the confined path: a real Docker container, the real
# default launcher table, a public npm server.
import pathlib

import pytest

import tests.integration.support.test_confined_launch_given as given
import tests.integration.support.test_confined_launch_then as then
from mcp_auditor.adapters.docker import DockerRuntime
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.domain.relayed_environment import RelayRequest
from mcp_auditor.target_execution import LaunchOptions, TargetExecution, decide_launch

# Pinned, as the README pins the demo's: this test is the only instrument of the
# confined path, so it must go red on a confinement regression and never on an
# upstream rename.
FILESYSTEM_SERVER = "@modelcontextprotocol/server-filesystem@2026.8.31"
ENV_ECHO_SERVER = pathlib.Path(__file__).parent / "support" / "env_echo_server.py"


@pytest.mark.skipif(not DockerRuntime().available(), reason="confined execution needs Docker")
async def test_confined_launch_serves_the_filesystem_server(tmp_path: pathlib.Path) -> None:
    workspace = given.a_mount_hostile_directory(tmp_path, "data,v2", "09:30")
    reference = given.a_mount_hostile_directory(tmp_path, "ref,1", "12:00")
    context = given.a_confined_context(
        LaunchOptions(unconfined=False, image=None, mounts=(f"{reference}:ro",))
    )
    target = [FILESYSTEM_SERVER, str(workspace), str(reference)]
    launch = decide_launch("npx", target, context).launch

    execution = TargetExecution(launch, context.runtime)
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
    then.the_read_only_mount_refused_the_write(refused, reference)
    then.the_record_lists_the_mounts(execution.record, writable=workspace, read_only=reference)
    then.no_container_is_left(context.container_name)


@pytest.mark.skipif(not DockerRuntime().available(), reason="confined execution needs Docker")
async def test_a_relayed_variable_reaches_the_confined_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MCP_AUDITOR_RELAYED", "relayed-into-the-container")
    context = given.a_confined_context(
        LaunchOptions(
            unconfined=False,
            image=None,
            mounts=(),
            relay=RelayRequest(redacted=("MCP_AUDITOR_RELAYED",)),
        )
    )
    target = ["--with", "mcp==1.26.0", "python", str(ENV_ECHO_SERVER)]
    launch = decide_launch("uvx", target, context).launch

    async with TargetExecution(launch, context.runtime), StdioMCPClient.connect(launch) as client:
        echoed = await client.call_tool("echo", {"name": "MCP_AUDITOR_RELAYED"})

    assert echoed.content == "relayed-into-the-container"
