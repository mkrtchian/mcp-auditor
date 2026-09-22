# The composition root of the target's execution: which regime a command runs under,
# which image confines it, and the lifetime of the container it runs in. Outside the
# hexagon, like `cli.py`, and it decides without printing anything.
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Protocol

from mcp_auditor.adapters.docker import DockerError
from mcp_auditor.adapters.host_paths import existing_paths
from mcp_auditor.adapters.server_launch import ContainerIdentity, ContainerProfile, ServerLaunch
from mcp_auditor.domain.confinement import (
    MissingMountError,
    MountPlan,
    MountPolicy,
    RefusedMountError,
    UnspellableMountError,
    is_declared_container,
    parse_mount_option,
    refused_roots,
)
from mcp_auditor.domain.models import ExecutionRecord

# The mapping comes from Docker's MCP Gateway, which sends the same launchers to the
# same image families. The tag is the one its publisher still rebuilds: a base image
# nobody rebuilds receives no security update, which is the wrong base under a feature
# whose point is confinement.
IMAGE_BY_LAUNCHER: Mapping[str, str] = {
    "npx": "node:24-bookworm-slim",
    "uvx": "ghcr.io/astral-sh/uv:python3.14-trixie-slim",
}

_LOCAL_SCHEMES = ("unix://", "npipe://")


class ContainerRuntime(Protocol):
    def available(self) -> bool: ...

    def endpoint(self) -> str: ...

    def ensure_image(self, image: str) -> str | None: ...

    def pids_limit_enforced(self) -> bool: ...

    def oom_killed(self, container_name: str) -> bool | None: ...

    def remove(self, container_name: str) -> None: ...


@dataclass(frozen=True)
class LaunchOptions:
    unconfined: bool
    image: str | None
    mounts: tuple[str, ...]


@dataclass(frozen=True)
class Host:
    uid: int
    gid: int
    home: Path
    docker_env: Mapping[str, str]


@dataclass(frozen=True)
class LaunchContext:
    options: LaunchOptions
    runtime: ContainerRuntime
    host: Host
    container_name: str


@dataclass(frozen=True)
class LaunchDecision:
    launch: ServerLaunch
    warnings: tuple[str, ...]


class LaunchRefused(Exception):
    """Why the target cannot be launched, and the ways forward."""


def decide_launch(command: str, args: Sequence[str], context: LaunchContext) -> LaunchDecision:
    if context.options.unconfined:
        return LaunchDecision(
            ServerLaunch.unconfined(command, args), _unconfined_warnings(context.options)
        )
    if is_declared_container(command, args):
        return LaunchDecision(
            ServerLaunch.declared_container(command, args, context.host.docker_env), ()
        )
    return _confine(command, args, context)


def _unconfined_warnings(options: LaunchOptions) -> tuple[str, ...]:
    if options.image is None and not options.mounts:
        return ()
    return ("--image and --mount only mean something in a container: ignored under --unconfined",)


def _confine(command: str, args: Sequence[str], context: LaunchContext) -> LaunchDecision:
    image = _image_for(command, context.options)
    _require_a_local_runtime(command, context.runtime)
    plan = _mount_plan(args, context)
    profile = ContainerProfile(
        identity=ContainerIdentity(image, _pull(image, context.runtime), context.container_name),
        mount_plan=plan,
        uid=context.host.uid,
        gid=context.host.gid,
    )
    launch = ServerLaunch.confined(command, args, profile, context.host.docker_env)
    return LaunchDecision(launch, _confined_warnings(plan, context.runtime))


def _image_for(command: str, options: LaunchOptions) -> str:
    image = options.image or IMAGE_BY_LAUNCHER.get(command)
    if image is None:
        raise LaunchRefused(
            f"no confinement profile for '{command}': pass --image IMAGE to run it in a "
            "container of your choice, or --unconfined to run it on this host with your "
            "privileges"
        )
    return image


def _require_a_local_runtime(command: str, runtime: ContainerRuntime) -> None:
    if not runtime.available():
        raise LaunchRefused(
            f"confined execution needs Docker: install it and start the daemon, or run with "
            f"--unconfined to launch '{command}' on this host with your privileges"
        )
    endpoint = runtime.endpoint()
    # A bind mount resolves on the daemon's filesystem, so a remote daemon would audit
    # other files, or none: a wrong report that looks right.
    if not endpoint.startswith(_LOCAL_SCHEMES):
        raise LaunchRefused(
            f"the Docker endpoint '{endpoint}' is not on this host, so the paths this command "
            "names would be mounted from that machine: run with --unconfined, or write the "
            "docker run yourself"
        )


def _mount_plan(args: Sequence[str], context: LaunchContext) -> MountPlan:
    declared = tuple(parse_mount_option(raw) for raw in context.options.mounts)
    policy = MountPolicy(declared, refused_roots(context.host.home))
    try:
        return policy.plan(args, existing_paths(policy.spellings_to_resolve(args)))
    except RefusedMountError as refusal:
        raise LaunchRefused(
            f"refusing to mount {refusal.root} into the container: "
            f"pass --mount {refusal.root}:rw to do it on purpose"
        ) from refusal
    except MissingMountError as missing:
        raise LaunchRefused(f"--mount {missing.spelling}: no such path on this host") from missing
    except UnspellableMountError as unspellable:
        raise LaunchRefused(
            f"cannot mount {str(unspellable.host)!r}: a container mount cannot spell "
            f"{unspellable.reason}, rename the path or run with --unconfined"
        ) from unspellable


def _pull(image: str, runtime: ContainerRuntime) -> str | None:
    try:
        return runtime.ensure_image(image)
    except DockerError as failure:
        raise LaunchRefused(str(failure)) from failure


def _confined_warnings(plan: MountPlan, runtime: ContainerRuntime) -> tuple[str, ...]:
    warnings = [
        f"'{word}' exists here but is not mounted: write ./{word} to mount it"
        for word in plan.unmounted_existing
    ]
    if not runtime.pids_limit_enforced():
        warnings.append("this Docker host cannot enforce --pids-limit, the server runs without it")
    return tuple(warnings)


class TargetExecution:
    """The container's lifetime around the connection to the server under audit.

    Whatever ends the block, the kill state is read and the container removed. Under the
    two regimes without a container of the auditor's, nothing is touched.
    """

    def __init__(self, launch: ServerLaunch, runtime: ContainerRuntime):
        self.launch = launch
        self._runtime = runtime
        self.record: ExecutionRecord | None = None

    async def __aenter__(self) -> "TargetExecution":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        profile = self.launch.profile
        if profile is None:
            self.record = self.launch.record(None)
            return
        try:
            self.record = self.launch.record(self._runtime.oom_killed(profile.identity.name))
        finally:
            self._runtime.remove(profile.identity.name)
