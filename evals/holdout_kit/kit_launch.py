"""A trimmed copy of evals/cve_environments.py's launch logic, free of mcp_auditor.

Parity note: the acceptance twin is evals/cve_environments.py. This module copies the four
per-target environment builders and their helpers, dropping only the `connect` coroutine that
wraps the auditor's StdioMCPClient; the kit connects through kit_client.py instead. It adds
`image_tag` and `build_images`. `image_tag` uses the `mcp-auditor-kit-` prefix, not the acceptance
`mcp-auditor-cve-` one, so a kit build never overwrites an acceptance image. The clean
planting and layout layers are reused by in-repo import (cve_planting, cve_layout, cve_places),
never copied, because moving them would move every acceptance fixture fingerprint
(evals/cve_baseline._ENVIRONMENT_PATHS) and redden the gate.

Landmine flags (CLAUDE.md), each named against the failure it guards:
- The `--user` mapping. The filesystem and git launches run as the host uid/gid so bind-mounted
  files the server writes into /srv (git_init's .git) are host-owned and teardown can remove them;
  drop the uid/gid and those files are root-owned and teardown or git fails. It is emitted by
  cve_planting.host_user_args / unprivileged_user_args through PlantedArgs.run_args(), exactly as
  the acceptance launch emits it, so it is reused here rather than rewritten.
- `--tmpfs /home/audit:exec,uid=,gid=` and `--memory-swap` are the auditor's OWN confined-run
  container flags (mcp_auditor.adapters.server_launch.container_argv), not this declared-container
  launch. The CVE/kit launch sets HOME=/tmp and no memory bound (cve_planting.confinement_args), so
  these two are deliberately absent here, matching the acceptance twin cve_environments.
"""

import os
import subprocess
import tempfile
from collections.abc import Generator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from evals.cve_layout import ANCHOR_PATHS, build_empty_layout, build_layout
from evals.cve_places import LayoutAnchor
from evals.cve_planting import (
    DockerPlanting,
    PlantedArgs,
    PlantingSpec,
    confinement_args,
    planted,
)


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
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        _materialise(root, spec, shape)
        if shape is not LaunchShape.EMPTY_LAYOUT:
            checkout = root / _CHECKOUT
            for index, intent in enumerate(spec.files):
                leak = checkout / f"leak{index}"
                leak.mkdir()
                os.symlink(intent.container_path, leak / "report")
        yield _filesystem_launch(root, image, args)


@contextmanager
def git_init_traversal_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        _materialise(root, spec, shape)
        yield _git_launch(root, image, args, chain_budget=3, max_chain_steps=5)


@contextmanager
def command_injection_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        _materialise(root, spec, shape)
        yield _read_only_launch(root, image, args)


@contextmanager
def ssrf_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        _materialise(root, spec, shape)
        yield _read_only_launch(root, image, args)


def _materialise(root: Path, spec: PlantingSpec, shape: LaunchShape) -> None:
    if shape is LaunchShape.EMPTY_LAYOUT:
        build_empty_layout(root)
    else:
        build_layout(root, spec.layout)


@contextmanager
def _temp_root() -> Generator[Path]:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as name:
        yield Path(name)


def _read_only_launch(root: Path, image: str, args: PlantedArgs) -> Launch:
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            "-v",
            f"{root}:{_WORKSPACE}:ro",
            image,
        ],
    )


def _filesystem_launch(root: Path, image: str, args: PlantedArgs) -> Launch:
    # Read-only: the filesystem server only reads. The server's allowed directory is the in-scope
    # checkout, passed as the final argument.
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            "-v",
            f"{root}:{_WORKSPACE}:ro",
            image,
            _PROJECT,
        ],
        scope=_PROJECT,
    )


def _git_launch(
    root: Path, image: str, args: PlantedArgs, chain_budget: int = 0, max_chain_steps: int = 3
) -> Launch:
    # Read-write: git_init writes a .git into /srv, and git operates on a repo it owns.
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            "-v",
            f"{root}:{_WORKSPACE}",
            image,
            "--repository",
            _PROJECT,
        ],
        chain_budget=chain_budget,
        max_chain_steps=max_chain_steps,
        scope=_PROJECT,
    )
