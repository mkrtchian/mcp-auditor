from collections.abc import Mapping, Sequence
from pathlib import Path

from mcp_auditor.domain.relayed_environment import RelayRequest
from mcp_auditor.target_execution import Host, LaunchContext, LaunchOptions
from tests.fakes import FakeContainerRuntime

DOCKER_ENV = {"DOCKER_HOST": "unix:///run/user/1000/docker.sock"}
HOME = Path("/home/alice")
CONTAINER_NAME = "mcp-auditor-0123456789ab"
FILESYSTEM_SERVER = "@modelcontextprotocol/server-filesystem"
NO_RELAY = RelayRequest()


def a_context(
    runtime: FakeContainerRuntime,
    *,
    unconfined: bool = False,
    image: str | None = None,
    mounts: Sequence[str] = (),
    relay: RelayRequest = NO_RELAY,
    environ: Mapping[str, str] | None = None,
) -> LaunchContext:
    return LaunchContext(
        options=LaunchOptions(
            unconfined=unconfined, image=image, mounts=tuple(mounts), relay=relay
        ),
        runtime=runtime,
        host=Host(uid=1000, gid=1000, home=HOME, docker_env=DOCKER_ENV, environ=environ or {}),
        container_name=CONTAINER_NAME,
    )


TOKEN_VALUE = "a-token-long-enough"


def a_context_relaying(
    runtime: FakeContainerRuntime, name: str, *, unconfined: bool = False
) -> LaunchContext:
    return a_context(
        runtime,
        unconfined=unconfined,
        relay=RelayRequest(redacted=(name,)),
        environ={name: TOKEN_VALUE},
    )
