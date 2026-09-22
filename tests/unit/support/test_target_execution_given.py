from collections.abc import Sequence
from pathlib import Path

from mcp_auditor.target_execution import Host, LaunchContext, LaunchOptions
from tests.fakes import FakeContainerRuntime

DOCKER_ENV = {"DOCKER_HOST": "unix:///run/user/1000/docker.sock"}
HOME = Path("/home/alice")
CONTAINER_NAME = "mcp-auditor-0123456789ab"
FILESYSTEM_SERVER = "@modelcontextprotocol/server-filesystem"


def a_context(
    runtime: FakeContainerRuntime,
    *,
    unconfined: bool = False,
    image: str | None = None,
    mounts: Sequence[str] = (),
) -> LaunchContext:
    return LaunchContext(
        options=LaunchOptions(unconfined=unconfined, image=image, mounts=tuple(mounts)),
        runtime=runtime,
        host=Host(uid=1000, gid=1000, home=HOME, docker_env=DOCKER_ENV),
        container_name=CONTAINER_NAME,
    )
