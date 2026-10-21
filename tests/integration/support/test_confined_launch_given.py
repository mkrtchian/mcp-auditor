import os
import pathlib
from uuid import uuid4

from mcp_auditor.adapters.docker import DockerRuntime, docker_client_env
from mcp_auditor.target_execution import Host, LaunchContext, LaunchOptions


def a_confined_context(options: LaunchOptions) -> LaunchContext:
    return LaunchContext(
        options=options,
        runtime=DockerRuntime(),
        host=Host(
            uid=os.getuid(),
            gid=os.getgid(),
            home=pathlib.Path.home(),
            docker_env=docker_client_env(os.environ),
            environ=dict(os.environ),
        ),
        container_name=f"mcp-auditor-{uuid4().hex[:12]}",
    )


def a_mount_hostile_directory(root: pathlib.Path, name: str, leaf: str) -> pathlib.Path:
    """A comma and a colon, both legal on this host and both fatal to a mount argument
    that does not quote its fields: the daemon is the only judge of that spelling."""
    directory = root / name / leaf
    directory.mkdir(parents=True)
    return directory
