"""A trimmed copy of evals/cve_environments.py's launch logic, free of mcp_auditor.

Parity note: the acceptance twin is evals/cve_environments.py. This module copies the four
acceptance per-target environment builders and their helpers, plus `arcadedb_env`, the twin of
`holdout_environments.arcadedb_mcp_env`, dropping only the `connect` coroutine that wraps the
auditor's StdioMCPClient; the kit connects through kit_client.py instead. It adds
`image_tag` and `build_images`. `image_tag` uses the `mcp-auditor-kit-` prefix, not the acceptance
`mcp-auditor-cve-` one, so a kit build never overwrites an acceptance image. The clean
planting and layout layers are reused by in-repo import (cve_planting, cve_layout, cve_places),
never copied, because moving them would move every acceptance fixture fingerprint
(evals/cve_baseline.ENVIRONMENT_PATHS) and redden the gate.

Landmine flags (CLAUDE.md), each named against the failure it guards:
- The `--user` mapping and the layout's owner. The tree is owned by the unprivileged account,
  65534:65534, handed over by `cve_layout.owned_layout` once built and removed by a container
  after the launch, so a server under that account owns the checkout git runs in and writes to
  the layout only where the target's host declares a read-write layout (`layout_mount`, read
  through `cve_layout.layout_mount_args`). The `--user` is emitted by
  cve_planting.unprivileged_user_args (or the planted account's) through PlantedArgs.run_args(),
  exactly as the acceptance launch emits it, so it is reused here rather than rewritten; the
  `/work` tmpfs comes the same way. `kit_driver.check_target` reports a launch running as any
  other account, so a builder that sets its own `--user` is caught.
- `--tmpfs /home/audit:exec,uid=,gid=` and `--memory-swap` are the auditor's OWN confined-run
  container flags (mcp_auditor.adapters.server_launch.container_argv), not this declared-container
  launch. The CVE/kit launch sets HOME=/tmp and no memory bound (cve_planting.confinement_args), so
  these two are deliberately absent here, matching the acceptance twin cve_environments.
"""

import os
import subprocess
from collections.abc import Generator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from evals.cve_layout import (
    ANCHOR_PATHS,
    build_empty_layout,
    build_layout,
    layout_mount_args,
    owned_layout,
)
from evals.cve_places import LayoutAnchor
from evals.cve_planting import (
    PlantedArgs,
    PlantingDocker,
    PlantingSpec,
    confinement_args,
    planted,
)
from evals.cve_planting_docker import DOCKER_PLANTING


def image_tag(name: str) -> str:
    return f"mcp-auditor-kit-{name}:local"


def build_images(docker_dir: Path, services: Sequence[str]) -> None:
    """Build each `docker/Dockerfile.<service>` as image_tag(service). The service name transplants
    unchanged into evals/docker/ and compose.yml, where compose rebuilds the image under the
    acceptance prefix, so the service name must not reuse an acceptance service name."""
    for service in services:
        dockerfile = docker_dir / f"Dockerfile.{service}"
        subprocess.run(
            ["docker", "build", "-t", image_tag(service), "-f", str(dockerfile), str(docker_dir)],
            check=True,
        )


class LaunchShape(StrEnum):
    NORMAL = "normal"
    EMPTY_LAYOUT = "empty_layout"
    FALLBACK = "fallback"


_WORKSPACE = ANCHOR_PATHS[LayoutAnchor.WORKSPACE]  # the mount target, /srv
_PROJECT = ANCHOR_PATHS[LayoutAnchor.PROJECT]  # the in-scope checkout, /srv/app
_CHECKOUT = Path(_PROJECT).relative_to(_WORKSPACE)  # the checkout's path under the temp root

FALLBACK_SCOPE = _PROJECT  # the documented default scope a broken scope-carrying server falls to


@dataclass(frozen=True)
class Launch:
    command: str
    args: list[str]
    chain_budget: int = 0
    max_chain_steps: int = 3
    scope: str | None = None


@dataclass(frozen=True)
class PlantedLaunch:
    launch: Launch
    nonces: Mapping[str, str]


@contextmanager
def filesystem_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    with (
        owned_layout(docker, lambda root: _materialise_with_leak_links(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        yield _filesystem_launch(layout_mount_args(root, spec.host.layout_mount), image, args)


@contextmanager
def git_init_traversal_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    with (
        owned_layout(docker, lambda root: _materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        layout = layout_mount_args(root, spec.host.layout_mount)
        yield _git_launch(layout, image, args, chain_budget=3, max_chain_steps=5)


@contextmanager
def command_injection_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    with (
        owned_layout(docker, lambda root: _materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        yield _layout_launch(layout_mount_args(root, spec.host.layout_mount), image, args)


@contextmanager
def ssrf_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    with (
        owned_layout(docker, lambda root: _materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        yield _layout_launch(layout_mount_args(root, spec.host.layout_mount), image, args)


@contextmanager
def arcadedb_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    # The trimmed twin of holdout_environments.arcadedb_mcp_env. The ArcadeDB MCP stdio server
    # takes no scope argument (it is driven over stdio, not pointed at a directory), so its launch
    # is the /srv mount and the planting args with no path appended after the image, identical to
    # the launch the command-injection and SSRF builders use.
    with (
        owned_layout(docker, lambda root: _materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        yield _layout_launch(layout_mount_args(root, spec.host.layout_mount), image, args)


def _materialise(root: Path, spec: PlantingSpec, shape: LaunchShape) -> None:
    if shape is LaunchShape.EMPTY_LAYOUT:
        build_empty_layout(root)
    else:
        build_layout(root, spec.layout)


def _materialise_with_leak_links(root: Path, spec: PlantingSpec, shape: LaunchShape) -> None:
    _materialise(root, spec, shape)
    if shape is not LaunchShape.EMPTY_LAYOUT:
        checkout = root / _CHECKOUT
        for index, intent in enumerate(spec.files):
            leak = checkout / f"leak{index}"
            leak.mkdir()
            os.symlink(intent.container_path, leak / "report")


def _layout_launch(layout: list[str], image: str, args: PlantedArgs) -> Launch:
    return Launch(
        command="docker",
        args=["run", "-i", "--rm", *confinement_args(), *args.run_args(), *layout, image],
    )


def _filesystem_launch(layout: list[str], image: str, args: PlantedArgs) -> Launch:
    # The server's allowed directory is the in-scope checkout, passed as the final argument.
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            *layout,
            image,
            _PROJECT,
        ],
        scope=_PROJECT,
    )


def _git_launch(
    layout: list[str],
    image: str,
    args: PlantedArgs,
    chain_budget: int = 0,
    max_chain_steps: int = 3,
) -> Launch:
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            *layout,
            image,
            "--repository",
            _PROJECT,
        ],
        chain_budget=chain_budget,
        max_chain_steps=max_chain_steps,
        scope=_PROJECT,
    )
