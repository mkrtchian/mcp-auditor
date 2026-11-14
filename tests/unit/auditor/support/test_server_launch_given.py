from pathlib import Path

from mcp_auditor.adapters.server_launch import ContainerIdentity, ContainerProfile
from mcp_auditor.domain.confinement import MountPlan, MountSpec
from mcp_auditor.domain.relayed_environment import RelayedEnvironment, RelayedVariable

IMAGE = "node:24-bookworm-slim"
DIGEST = "sha256:abc123def456"
CONTAINER_NAME = "mcp-auditor-0123456789ab"
QUICK_START_COMMAND = "npx"
QUICK_START_ARGS = ["@modelcontextprotocol/server-filesystem", "/tmp/sandbox"]


def the_quick_start_profile() -> ContainerProfile:
    return _a_profile(
        MountPlan(mounts=(_writable(Path("/tmp/sandbox")),), rewrites={}, unmounted_existing=())
    )


def a_profile_with_a_read_only_mount_and_a_rewrite() -> ContainerProfile:
    return _a_profile(
        MountPlan(
            mounts=(
                _writable(Path("/home/alice/proj/data")),
                MountSpec(host=Path("/data"), writable=False),
            ),
            rewrites={"./data": "/home/alice/proj/data"},
            unmounted_existing=(),
        )
    )


def a_profile_mounting(host: Path) -> ContainerProfile:
    return _a_profile(MountPlan(mounts=(_writable(host),), rewrites={}, unmounted_existing=()))


def _a_profile(mount_plan: MountPlan) -> ContainerProfile:
    return ContainerProfile(
        identity=ContainerIdentity(image=IMAGE, image_digest=DIGEST, name=CONTAINER_NAME),
        mount_plan=mount_plan,
        uid=1000,
        gid=1000,
    )


def _writable(host: Path) -> MountSpec:
    return MountSpec(host=host, writable=True)


def a_token_and_a_region() -> RelayedEnvironment:
    return RelayedEnvironment(
        (
            RelayedVariable("GITHUB_TOKEN", "ghp_secret_value", redacted=True),
            RelayedVariable("AWS_REGION", "eu-west-1", redacted=False),
        )
    )
