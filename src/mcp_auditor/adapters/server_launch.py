# The launch of the server under audit: the user's command, the regime it runs under,
# and the container profile a confined regime derives its argv from. Pure: no
# subprocess, no environment read, no filesystem probe, no clock, no randomness.
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from mcp_auditor.domain.confinement import MountPlan, is_declared_container
from mcp_auditor.domain.models import ExecutionRecord, ExecutionRegime
from mcp_auditor.domain.relayed_environment import RelayedEnvironment

NOTHING_RELAYED = RelayedEnvironment()


@dataclass(frozen=True)
class ServerLaunch:
    command: str
    args: tuple[str, ...]
    regime: ExecutionRegime
    profile: "ContainerProfile | None" = None
    client_env: Mapping[str, str] | None = None
    """Variables for the host-side `docker` client, not for the container."""
    relayed: RelayedEnvironment = NOTHING_RELAYED

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
        *,
        relayed: RelayedEnvironment = NOTHING_RELAYED,
    ) -> "ServerLaunch":
        return cls(command, tuple(args), ExecutionRegime.CONFINED, profile, client_env, relayed)

    @classmethod
    def declared_container(
        cls,
        command: str,
        args: Sequence[str],
        client_env: Mapping[str, str],
        *,
        relayed: RelayedEnvironment = NOTHING_RELAYED,
    ) -> "ServerLaunch":
        return cls(
            command,
            tuple(args),
            ExecutionRegime.DECLARED_CONTAINER,
            client_env=client_env,
            relayed=relayed,
        )

    @classmethod
    def unconfined(
        cls,
        command: str,
        args: Sequence[str],
        *,
        relayed: RelayedEnvironment = NOTHING_RELAYED,
    ) -> "ServerLaunch":
        return cls(command, tuple(args), ExecutionRegime.UNCONFINED, relayed=relayed)

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
        return container_argv(self, self.profile)

    @property
    def spawn_environment(self) -> dict[str, str] | None:
        """The variables set over the auditor's default environment, `None` for none."""
        if self.client_env is not None:
            return dict(self.client_env) | self.relayed.values
        return self.relayed.values or None

    def record(self, oom_killed: bool | None) -> ExecutionRecord:
        record = ExecutionRecord(
            regime=self.regime,
            relayed_variables=[v.name for v in self.relayed.variables if v.redacted] or None,
            plain_variables={v.name: v.value for v in self.relayed.variables if not v.redacted}
            or None,
        )
        if self.profile is None:
            return record
        mounts = self.profile.mount_plan.mounts
        return record.model_copy(
            update={
                "image": self.profile.identity.image,
                "image_digest": self.profile.identity.image_digest,
                "writable_paths": [str(mount.host) for mount in mounts if mount.writable],
                "read_only_paths": [str(mount.host) for mount in mounts if not mount.writable],
                "oom_killed": oom_killed,
            }
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


def container_argv(launch: ServerLaunch, profile: ContainerProfile) -> list[str]:
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
        # A bare name: docker reads the value from its own environment, which
        # `spawn_environment` fills, so the value never appears in the argv.
        *(flag for name in launch.relayed.names for flag in ("-e", name)),
        *_mount_flags(plan),
        profile.identity.image,
        launch.command,
        *(plan.rewrites.get(element, element) for element in launch.args),
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
