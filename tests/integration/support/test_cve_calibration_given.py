import pathlib
import re
import sys
from collections.abc import Awaitable, Callable, Generator
from contextlib import AbstractContextManager, contextmanager

from evals.cve_environments import Launch, LaunchShape
from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Place, Places, PlantKind
from evals.cve_planting import PlantingHost, PlantingSpec, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

STUB_PATH = pathlib.Path(__file__).resolve().parent / "cve_stub_server.py"
KEPT_FLAG_ID = "fict-flag"
OUTSIDE_ID = "fict-outside"
INSIDE_ID = "fict-inside"
OUTSIDE_AIM = re.compile(r"^/outside/")

Builder = Callable[[str, PlantingSpec, LaunchShape], AbstractContextManager[Launch]]


def a_docker_that_runs_its_command_on_the_host(directory: pathlib.Path) -> pathlib.Path:
    """`docker run <command...>` execs the command itself, so a declared container runs
    without Docker."""
    docker = directory / "docker"
    docker.write_text('#!/bin/sh\nshift\nexec "$@"\n')
    docker.chmod(0o755)
    return directory


def a_places_mapping() -> Places:
    """Resolves the single kept place of the calibration targets. Its coordinate is only read by
    planting_spec (the stub builder does not enter planted), so it stays a plain file place."""
    return {KEPT_FLAG_ID: _a_file_place(KEPT_FLAG_ID, "/outside/flag")}


def a_survey_places_mapping() -> Places:
    """Two candidate file places the survey plants together: one the exploit reaches, one the
    benign call reaches. Both are reachable by arbitrary_read, the survey target's reach."""
    return {
        OUTSIDE_ID: _a_file_place(OUTSIDE_ID, "/outside/flag"),
        INSIDE_ID: _a_file_place(INSIDE_ID, "/inside/file"),
    }


def a_target_whose_server_exits_at_startup(cve_id: str, last_words: str) -> CVETarget:
    @contextmanager
    def builder(_image: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        yield Launch(
            "docker", ["run", sys.executable, "-c", f"import sys; sys.exit({last_words!r})"]
        )

    return _a_target(cve_id, builder, benign=_reading("/inside/file"))


def a_live_target(cve_id: str) -> CVETarget:
    return _a_target(cve_id, _serving_builder(), benign=_reading("/inside/file"))


def a_target_whose_benign_call_leaks(cve_id: str) -> CVETarget:
    return _a_target(cve_id, _serving_builder(), benign=_reading("/outside/flag"))


def a_target_whose_aim_matches_nothing(cve_id: str) -> CVETarget:
    return _a_target(
        cve_id, _serving_builder(), benign=_reading("/inside/file"), aim=re.compile(r"^/nowhere/")
    )


def a_target_with_no_kept_place(cve_id: str) -> CVETarget:
    return _a_target(cve_id, _serving_builder(), benign=_reading("/inside/file"), kept_places=())


def a_target_whose_exploit_misses(cve_id: str) -> CVETarget:
    # The vulnerable server surfaces nothing, so the aimed exploit reaches no nonce.
    return _a_target(cve_id, _serving_builder(vulnerable=False), benign=_reading("/inside/file"))


def a_target_whose_patched_version_still_surfaces(cve_id: str) -> CVETarget:
    return _a_target(cve_id, _serving_builder(patched=True), benign=_reading("/inside/file"))


def a_target_whose_patched_benign_errors(cve_id: str) -> CVETarget:
    builder = _serving_builder(patched_error_paths=("/inside/file",))
    return _a_target(cve_id, builder, benign=_reading("/inside/file"))


def a_survey_target(cve_id: str) -> CVETarget:
    # Serves every planted place on both versions, so the exploit reads the outside place and the
    # benign call the inside place, and the patched launch still surfaces the outside place.
    return _a_target(
        cve_id, _serving_builder(patched=True), benign=_reading("/inside/file"), kept_places=()
    )


def _serving_builder(
    vulnerable: bool = True, patched: bool = False, patched_error_paths: tuple[str, ...] = ()
) -> Builder:
    @contextmanager
    def builder(image: str, spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        is_patched = "patched" in image
        args = _serve_args(spec) if (patched if is_patched else vulnerable) else []
        if is_patched:
            args += [f"error={path}" for path in patched_error_paths]
        yield Launch("docker", ["run", sys.executable, str(STUB_PATH), *args])

    return builder


def _serve_args(spec: PlantingSpec) -> list[str]:
    return [
        f"{place.coordinates.path}={spec.nonces[place.id]}"
        for place in spec.places
        if place.coordinates.path is not None
    ]


def _a_file_place(place_id: str, path: str) -> Place:
    return Place(
        id=place_id,
        family="fictional",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.FILE,
        coordinates=Coordinates(PlantKind.FILE, path=path),
    )


def _reading(path: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def read(_places: Places, client: MCPClientPort) -> None:
        await client.call_tool("read", {"path": path})

    return read


def _a_target(
    cve_id: str,
    builder: Builder,
    benign: Callable[[Places, MCPClientPort], Awaitable[None]],
    aim: re.Pattern[str] = OUTSIDE_AIM,
    kept_places: tuple[str, ...] = (KEPT_FLAG_ID,),
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
        exploits=(_reading("/outside/flag"),),
        benign=benign,
        awaited_capability=None,
        note="",
        tools_filter=None,
    )
