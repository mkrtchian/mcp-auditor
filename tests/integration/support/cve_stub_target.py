"""Stub CVE targets shared by the calibration and replay tests: a fictional read server launched
through a `docker` that runs its command on the host, so neither test needs Docker."""

import pathlib
import re
from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager

from evals.cve_environments import Launch, LaunchShape
from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Place, Places, PlantKind
from evals.cve_planting import PlantingHost, PlantingSpec, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

OUTSIDE_AIM = re.compile(r"^/outside/")

Builder = Callable[[str, PlantingSpec, LaunchShape], AbstractContextManager[Launch]]
Call = Callable[[Places, MCPClientPort], Awaitable[None]]


def a_docker_that_runs_its_command_on_the_host(directory: pathlib.Path) -> pathlib.Path:
    """`docker run <command...>` execs the command itself, so a declared container runs
    without Docker."""
    docker = directory / "docker"
    docker.write_text('#!/bin/sh\nshift\nexec "$@"\n')
    docker.chmod(0o755)
    return directory


def a_stub_target(
    cve_id: str,
    builder: Builder,
    benign: Call,
    *,
    aim: re.Pattern[str] = OUTSIDE_AIM,
    kept_places: tuple[str, ...],
) -> CVETarget:
    return CVETarget(
        cve_id=cve_id,
        severity="CVSS 0.0",
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=aim,
        reaches=frozenset({"arbitrary_read"}),
        kept_places=kept_places,
        images=(),
        server_image="stub",
        patched_image="stub-patched",
        planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False),
        builder=builder,
        exploits=(reading("/outside/flag"),),
        benign=benign,
        awaited_capability=None,
        note="",
        tools_filter=None,
    )


def reading(path: str) -> Call:
    async def read(_places: Places, client: MCPClientPort) -> None:
        await client.call_tool("read", {"path": path})

    return read


def a_file_place(place_id: str, path: str) -> Place:
    return Place(
        id=place_id,
        family="fictional",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.FILE,
        coordinates=Coordinates(PlantKind.FILE, path=path),
    )
