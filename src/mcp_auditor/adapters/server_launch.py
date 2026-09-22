# The launch of the server under audit: the user's command, the regime it runs under,
# and the container profile a confined regime derives its argv from. Pure: no
# subprocess, no environment read, no filesystem probe, no clock, no randomness.
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from mcp_auditor.domain.confinement import MountPlan, is_declared_container
from mcp_auditor.domain.models import ExecutionRecord, ExecutionRegime


@dataclass(frozen=True)
class ServerLaunch:
    command: str
    args: tuple[str, ...]
    regime: ExecutionRegime
    profile: "ContainerProfile | None" = None
    client_env: Mapping[str, str] | None = None
    """Variables for the host-side `docker` client, not for the container."""

    def __post_init__(self) -> None:
        confined = self.regime == ExecutionRegime.CONFINED
        if confined and self.profile is None:
            raise ValueError("a confined launch needs a container profile")
        if not confined and self.profile is not None:
            raise ValueError(f"a {self.regime} launch carries no container profile")
        if self.regime == ExecutionRegime.DECLARED_CONTAINER and not is_declared_container(
            self.command, self.args
        ):
            raise ValueError(f"not a declared container: {self.command} {' '.join(self.args)}")

    @classmethod
    def confined(
        cls,
        command: str,
        args: Sequence[str],
        profile: "ContainerProfile",
        client_env: Mapping[str, str],
    ) -> "ServerLaunch":
        return cls(command, tuple(args), ExecutionRegime.CONFINED, profile, client_env)

    @classmethod
    def declared_container(
        cls, command: str, args: Sequence[str], client_env: Mapping[str, str]
    ) -> "ServerLaunch":
        return cls(command, tuple(args), ExecutionRegime.DECLARED_CONTAINER, client_env=client_env)

    @classmethod
    def unconfined(cls, command: str, args: Sequence[str]) -> "ServerLaunch":
        return cls(command, tuple(args), ExecutionRegime.UNCONFINED)

    @property
    def target(self) -> str:
        """The command as the user wrote it, which is how a report names what was audited."""
        return " ".join([self.command, *self.args])

    @property
    def spawn_command(self) -> str:
        return "docker" if self.profile is not None else self.command

    @property
    def spawn_args(self) -> list[str]:
        if self.profile is None:
            return list(self.args)
        return container_argv(self.profile, self.command, self.args)

    def record(self, oom_killed: bool | None) -> ExecutionRecord:
        if self.profile is None:
            return ExecutionRecord(regime=self.regime)
        mounts = self.profile.mount_plan.mounts
        return ExecutionRecord(
            regime=self.regime,
            image=self.profile.identity.image,
            image_digest=self.profile.identity.image_digest,
            writable_paths=[str(mount.host) for mount in mounts if mount.writable],
            read_only_paths=[str(mount.host) for mount in mounts if not mount.writable],
            oom_killed=oom_killed,
        )


@dataclass(frozen=True)
class ContainerIdentity:
    image: str
    image_digest: str | None
    name: str


@dataclass(frozen=True)
class ContainerProfile:
    identity: ContainerIdentity
    mount_plan: MountPlan
    uid: int
    gid: int
    home: str = "/home/audit"
    pids_limit: int = 256
    memory: str = "2g"


def container_argv(profile: ContainerProfile, command: str, args: Sequence[str]) -> list[str]:
    plan = profile.mount_plan
    return [
        "run",
        "-i",
        "--init",
        "--name",
        profile.identity.name,
        "--label",
        "mcp-auditor",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(profile.pids_limit),
        "--memory",
        profile.memory,
        # Equal to --memory, so the bound bites: left out, Docker grants as much swap
        # again and a runaway server thrashes it before the kill fires.
        "--memory-swap",
        profile.memory,
        "--user",
        f"{profile.uid}:{profile.gid}",
        # The uid/gid are the measured requirement: a root-owned tmpfs home makes npm
        # fail with EACCES on its cache.
        "--tmpfs",
        f"{profile.home}:exec,uid={profile.uid},gid={profile.gid}",
        "-e",
        f"HOME={profile.home}",
        *_mount_flags(plan),
        profile.identity.image,
        command,
        *(plan.rewrites.get(element, element) for element in args),
    ]


# --mount rather than -v, and each field quoted whole: -v refuses a host path holding a
# colon, and --mount parses its fields as CSV, where an unquoted comma would split one.
# The quotes go around `src=...`, not around the path, which is where Docker's CSV parser
# accepts them. What no quoting can carry is refused before this runs, by
# `_require_a_spellable_path` in the mount policy: change this spelling and that list is
# wrong, with nothing but the acceptance test to say so.
def _mount_flags(plan: MountPlan) -> list[str]:
    flags: list[str] = []
    for mount in plan.mounts:
        fields = f'type=bind,"src={mount.host}","dst={mount.host}"'
        flags += ["--mount", fields if mount.writable else f"{fields},readonly"]
    return flags
