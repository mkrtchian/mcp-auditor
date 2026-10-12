import pathlib
import re
import sys
from collections.abc import Awaitable, Callable, Generator
from contextlib import contextmanager

from evals.cve_environments import Launch
from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Place, Places, PlantKind
from evals.cve_planting import PlantingHost, PlantingSpec, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

STUB_PATH = pathlib.Path(__file__).resolve().parent / "cve_stub_server.py"
KEPT_FLAG_ID = "fict-flag"
OUTSIDE_AIM = re.compile(r"^/outside/")


def a_docker_that_runs_its_command_on_the_host(directory: pathlib.Path) -> pathlib.Path:
    """`docker run <command...>` execs the command itself, so a declared container runs
    without Docker."""
    docker = directory / "docker"
    docker.write_text('#!/bin/sh\nshift\nexec "$@"\n')
    docker.chmod(0o755)
    return directory


def a_places_mapping() -> Places:
    """Resolves the stub targets' single fictional kept place. Its coordinate is only read by
    planting_spec (the stub builder does not enter planted), so it stays a plain file place."""
    return {
        KEPT_FLAG_ID: Place(
            id=KEPT_FLAG_ID,
            family="fictional",
            reachable_by=frozenset({"arbitrary_read"}),
            kind=PlantKind.FILE,
            coordinates=Coordinates(PlantKind.FILE, path="/outside/flag"),
        )
    }


def a_target_whose_server_exits_at_startup(cve_id: str, last_words: str) -> CVETarget:
    def launch_from_spec(_spec: PlantingSpec) -> Launch:
        return Launch(
            "docker", ["run", sys.executable, "-c", f"import sys; sys.exit({last_words!r})"]
        )

    return _a_target(cve_id, launch_from_spec, benign=_reading("/inside/file"))


def a_live_target(cve_id: str) -> CVETarget:
    return _a_target(cve_id, _stub_launch, benign=_reading("/inside/file"))


def a_target_whose_benign_call_leaks(cve_id: str) -> CVETarget:
    return _a_target(cve_id, _stub_launch, benign=_reading("/outside/flag"))


def a_target_whose_aim_matches_nothing(cve_id: str) -> CVETarget:
    return _a_target(
        cve_id, _stub_launch, benign=_reading("/inside/file"), aim=re.compile(r"^/nowhere/")
    )


def _stub_launch(spec: PlantingSpec) -> Launch:
    # The host docker shim cannot carry planting flags, so the drawn nonce rides the stub
    # server's command line instead. cve_stub_server reads it as the kept place's nonce.
    return Launch("docker", ["run", sys.executable, str(STUB_PATH), spec.nonces[KEPT_FLAG_ID]])


def _reading(path: str) -> Callable[[MCPClientPort], Awaitable[None]]:
    async def read(client: MCPClientPort) -> None:
        await client.call_tool("read", {"path": path})

    return read


def _a_target(
    cve_id: str,
    launch_from_spec: Callable[[PlantingSpec], Launch],
    benign: Callable[[MCPClientPort], Awaitable[None]],
    aim: re.Pattern[str] = OUTSIDE_AIM,
) -> CVETarget:
    @contextmanager
    def builder(_image: str, spec: PlantingSpec) -> Generator[Launch]:
        yield launch_from_spec(spec)

    return CVETarget(
        cve_id=cve_id,
        severity="CVSS 0.0",
        mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
        aim=aim,
        reaches=frozenset({"arbitrary_read"}),
        kept_places=(KEPT_FLAG_ID,),
        images=(),
        server_image="stub",
        planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False),
        builder=builder,
        exploits=(_reading("/outside/flag"),),
        benign=benign,
        awaited_capability=None,
        note="",
        tools_filter=None,
    )
