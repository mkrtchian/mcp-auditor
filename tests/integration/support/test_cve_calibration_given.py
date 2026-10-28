import pathlib
import re
import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass

from evals.cve_environments import Launch, LaunchShape
from evals.cve_places import HOLDOUT_PLACES, Places, load_places
from evals.cve_planting import PlantingSpec
from evals.cve_targets import CVE_TARGETS, CVETarget, TargetVersion
from mcp_auditor.adapters.docker import DockerRuntime
from tests.integration.support.cve_stub_target import Builder, a_file_place, a_stub_target, reading

STUB_PATH = pathlib.Path(__file__).resolve().parent / "cve_stub_server.py"
KEPT_FLAG_ID = "fict-flag"
KEPT = (KEPT_FLAG_ID,)
OUTSIDE_ID = "fict-outside"
INSIDE_ID = "fict-inside"
GIT_CVE_ID = "CVE-2025-68143"


def a_places_mapping() -> Places:
    """Resolves the single kept place of the calibration targets. Its coordinate is only read by
    planting_spec (the stub builder does not enter planted), so it stays a plain file place."""
    return {KEPT_FLAG_ID: a_file_place(KEPT_FLAG_ID, "/outside/flag")}


def a_survey_places_mapping() -> Places:
    """Two candidate file places the survey plants together: one the exploit reaches, one the
    benign call reaches. Both are reachable by arbitrary_read, the survey target's reach."""
    return {
        OUTSIDE_ID: a_file_place(OUTSIDE_ID, "/outside/flag"),
        INSIDE_ID: a_file_place(INSIDE_ID, "/inside/file"),
    }


def a_target_whose_server_exits_at_startup(cve_id: str, last_words: str) -> CVETarget:
    @contextmanager
    def builder(_image: str, _spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        yield Launch(
            "docker", ["run", sys.executable, "-c", f"import sys; sys.exit({last_words!r})"]
        )

    return a_stub_target(cve_id, builder, reading("/inside/file"), kept_places=KEPT)


def a_live_target(cve_id: str) -> CVETarget:
    return a_stub_target(cve_id, _serving_builder(), reading("/inside/file"), kept_places=KEPT)


def a_target_whose_layout_breaks_the_patched_version(cve_id: str) -> CVETarget:
    # The patched twin exits at startup with the layout mounted but serves on the empty reference
    # arm, so the layout break shows on the patched version only. The vulnerable version serves on
    # both arms, so a one-version check would miss it.
    @contextmanager
    def builder(image: str, spec: PlantingSpec, shape: LaunchShape) -> Generator[Launch]:
        if "patched" in image and shape is not LaunchShape.EMPTY_LAYOUT:
            yield Launch("docker", ["run", sys.executable, "-c", "import sys; sys.exit(1)"])
        else:
            yield Launch("docker", ["run", sys.executable, str(STUB_PATH), *_serve_args(spec)])

    return a_stub_target(cve_id, builder, reading("/inside/file"), kept_places=KEPT)


def a_target_whose_benign_call_leaks(cve_id: str) -> CVETarget:
    return a_stub_target(cve_id, _serving_builder(), reading("/outside/flag"), kept_places=KEPT)


def a_target_whose_aim_matches_nothing(cve_id: str) -> CVETarget:
    return a_stub_target(
        cve_id,
        _serving_builder(),
        reading("/inside/file"),
        aim=re.compile(r"^/nowhere/"),
        kept_places=KEPT,
    )


def a_target_with_no_kept_place(cve_id: str) -> CVETarget:
    return a_stub_target(cve_id, _serving_builder(), reading("/inside/file"), kept_places=())


def a_target_whose_exploit_misses(cve_id: str) -> CVETarget:
    # The vulnerable server surfaces nothing, so the aimed exploit reaches no nonce.
    return a_stub_target(
        cve_id, _serving_builder(vulnerable=False), reading("/inside/file"), kept_places=KEPT
    )


def a_target_whose_patched_version_still_surfaces(cve_id: str) -> CVETarget:
    return a_stub_target(
        cve_id, _serving_builder(patched=True), reading("/inside/file"), kept_places=KEPT
    )


def a_target_whose_patched_benign_errors(cve_id: str) -> CVETarget:
    builder = _serving_builder(patched_error_paths=("/inside/file",))
    return a_stub_target(cve_id, builder, reading("/inside/file"), kept_places=KEPT)


def a_target_whose_vulnerable_launch_fails(
    cve_id: str, tmp_path: pathlib.Path, times: int
) -> CVETarget:
    """Live once launched. Its vulnerable server exits at startup on its first `times` launches."""
    counter = _LaunchCounter(_launches_directory(tmp_path), vulnerable_failures=times)
    builder = _serving_builder(counter=counter)
    return a_stub_target(cve_id, builder, reading("/inside/file"), kept_places=KEPT)


def a_counted_target_whose_exploit_misses(cve_id: str, tmp_path: pathlib.Path) -> CVETarget:
    counter = _LaunchCounter(_launches_directory(tmp_path))
    builder = _serving_builder(vulnerable=False, counter=counter)
    return a_stub_target(cve_id, builder, reading("/inside/file"), kept_places=KEPT)


def a_counted_target_whose_tools_list_breaks(cve_id: str, tmp_path: pathlib.Path) -> CVETarget:
    counter = _LaunchCounter(_launches_directory(tmp_path))
    builder = _serving_builder(counter=counter, broken_tools_list=True)
    return a_stub_target(cve_id, builder, reading("/inside/file"), kept_places=KEPT)


def launches_of(tmp_path: pathlib.Path, version: TargetVersion) -> int:
    counter = _launches_directory(tmp_path) / version.value
    return len(counter.read_text()) if counter.exists() else 0


def _launches_directory(tmp_path: pathlib.Path) -> pathlib.Path:
    directory = tmp_path / "launches"
    directory.mkdir(exist_ok=True)
    return directory


@dataclass(frozen=True)
class _LaunchCounter:
    directory: pathlib.Path
    vulnerable_failures: int = 0

    def args(self, is_patched: bool) -> list[str]:
        version = TargetVersion.PATCHED if is_patched else TargetVersion.VULNERABLE
        failures = 0 if is_patched else self.vulnerable_failures
        return [f"launches={self.directory / version.value}:{failures}"]


def a_survey_target(cve_id: str) -> CVETarget:
    # Serves every planted place on both versions, so the exploit reads the outside place and the
    # benign call the inside place, and the patched launch still surfaces the outside place.
    return a_stub_target(
        cve_id, _serving_builder(patched=True), reading("/inside/file"), kept_places=()
    )


def _serving_builder(
    vulnerable: bool = True,
    patched: bool = False,
    patched_error_paths: tuple[str, ...] = (),
    counter: _LaunchCounter | None = None,
    broken_tools_list: bool = False,
) -> Builder:
    @contextmanager
    def builder(image: str, spec: PlantingSpec, _shape: LaunchShape) -> Generator[Launch]:
        is_patched = "patched" in image
        args = _serve_args(spec) if (patched if is_patched else vulnerable) else []
        if is_patched:
            args += [f"error={path}" for path in patched_error_paths]
        if counter is not None:
            args += counter.args(is_patched)
        if broken_tools_list:
            args.append("broken-tools-list")
        yield Launch("docker", ["run", sys.executable, str(STUB_PATH), *args])

    return builder


def _serve_args(spec: PlantingSpec) -> list[str]:
    return [
        f"{place.coordinates.path}={spec.nonces[place.id]}"
        for place in spec.places
        if place.coordinates.path is not None
    ]


def the_git_target() -> CVETarget:
    return next(target for target in CVE_TARGETS if target.cve_id == GIT_CVE_ID)


def the_holdout_places() -> Places:
    return load_places(HOLDOUT_PLACES)


def missing_docker() -> str | None:
    if not DockerRuntime().available():
        return "the git reference-arm check needs Docker"
    return None
