import dataclasses
import json
import re
import shutil
from collections.abc import Callable
from pathlib import Path

from evals.baseline import BaselineStatus, RecordingRef
from evals.cve_baseline import CVERunConditions, CVETargetBaseline
from evals.cve_grammar import CVEStatus, MechanismClass
from evals.cve_places import Coordinates, LayoutAnchor, Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_base import LayoutMount, PublicNames
from evals.cve_targets import CVE_TARGETS, CVETarget, LaunchMode
from evals.docker_paths import DOCKER_DIRECTORY
from evals.gate import ReplayRule
from mcp_auditor.domain.ports import MCPClientPort
from tests.unit.support.test_cve_planting_stand_ins_given import HOST as STAND_IN_HOST
from tests.unit.support.test_cve_planting_stand_ins_given import (
    a_stand_ins_directory as a_stand_ins_directory,
)

type TargetChange = Callable[[CVETarget, Places, Path], tuple[CVETarget, Places]]
type StandInChange = Callable[[CVETarget, Path], CVETarget]

KEPT_ENDPOINT_ID = "fict-endpoint"
KEPT_FILE_ID = "fict-file"
KEPT_LAYOUT_ID = "fict-layout"

KUBERNETES_TARGET = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53355")
SYMLINK_TARGET = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53109")
RECORDED_COMMIT = "0123abc"


def a_docker_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "docker"
    directory.mkdir()
    for dockerfile in DOCKER_DIRECTORY.glob("Dockerfile.*"):
        shutil.copy(dockerfile, directory / dockerfile.name)
    return directory


def _an_endpoint_record(
    *, path: str = "/fictional/meta", family: str = "fictional-family"
) -> Place:
    return Place(
        id=KEPT_ENDPOINT_ID,
        family=family,
        reachable_by=frozenset({"internal_fetch"}),
        kind=PlantKind.HTTP_ENDPOINT,
        coordinates=Coordinates(PlantKind.HTTP_ENDPOINT, host="fictional-service", path=path),
    )


def _a_file_record(
    entry_id: str = KEPT_FILE_ID,
    *,
    path: str = "/fictional/secret",
    family: str = "fictional-family",
) -> Place:
    return Place(
        id=entry_id,
        family=family,
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.FILE,
        coordinates=Coordinates(PlantKind.FILE, path=path),
    )


def a_target_keeping_an_endpoint() -> tuple[CVETarget, Places]:
    target = dataclasses.replace(KUBERNETES_TARGET, kept_places=(KEPT_ENDPOINT_ID,))
    return target, {KEPT_ENDPOINT_ID: _an_endpoint_record()}


def a_target_keeping_a_file() -> tuple[CVETarget, Places]:
    target = dataclasses.replace(KUBERNETES_TARGET, kept_places=(KEPT_FILE_ID,))
    return target, {KEPT_FILE_ID: _a_file_record()}


def a_layout_record(
    *, relpath: str = "config", anchor: LayoutAnchor = LayoutAnchor.PROJECT_BARE
) -> Place:
    return Place(
        id=KEPT_LAYOUT_ID,
        family="fictional-family",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.GIT_REMOTE_URL,
        coordinates=Coordinates(PlantKind.GIT_REMOTE_URL, anchor=anchor, relpath=relpath),
    )


def a_target_keeping_a_layout_place() -> tuple[CVETarget, Places]:
    target = dataclasses.replace(KUBERNETES_TARGET, kept_places=(KEPT_LAYOUT_ID,))
    return target, {KEPT_LAYOUT_ID: a_layout_record()}


def _appending_to_its_dockerfile(line: str) -> TargetChange:
    def change(
        target: CVETarget, places: Places, docker_directory: Path
    ) -> tuple[CVETarget, Places]:
        dockerfile = docker_directory / f"Dockerfile.{target.images[0]}"
        dockerfile.write_text(f"{dockerfile.read_text()}\n{line}\n")
        return target, places

    return change


def _appending_to_the_sentinel_dockerfile(line: str) -> TargetChange:
    def change(
        target: CVETarget, places: Places, docker_directory: Path
    ) -> tuple[CVETarget, Places]:
        dockerfile = docker_directory / "Dockerfile.sentinel"
        dockerfile.write_text(f"{dockerfile.read_text()}\n{line}\n")
        return target, places

    return change


def _appending_to_the_patched_dockerfile(line: str) -> TargetChange:
    def change(
        target: CVETarget, places: Places, docker_directory: Path
    ) -> tuple[CVETarget, Places]:
        dockerfile = docker_directory / f"Dockerfile.{target.patched_image}"
        dockerfile.write_text(f"{dockerfile.read_text()}\n{line}\n")
        return target, places

    return change


def _replacing(**fields: object) -> TargetChange:
    def change(
        target: CVETarget, places: Places, _docker_directory: Path
    ) -> tuple[CVETarget, Places]:
        return dataclasses.replace(target, **fields), places

    return change


def _changing_its_host(**fields: object) -> TargetChange:
    def change(
        target: CVETarget, places: Places, _docker_directory: Path
    ) -> tuple[CVETarget, Places]:
        host = dataclasses.replace(target.planting_host, **fields)
        return dataclasses.replace(target, planting_host=host), places

    return change


def _declaring_a_backend_source() -> TargetChange:
    def change(
        target: CVETarget, places: Places, docker_directory: Path
    ) -> tuple[CVETarget, Places]:
        return dataclasses.replace(
            target, backend_sources=(a_backend_source(docker_directory),)
        ), places

    return change


def a_backend_source(directory: Path) -> Path:
    source = directory / "fictional_backend.py"
    source.write_text('SCHEMA = "CREATE TABLE t1 (c1 INT)"\n')
    return source


def a_target_seeding_a_backend(directory: Path) -> tuple[CVETarget, Places]:
    target, places = a_target_keeping_a_file()
    return dataclasses.replace(target, backend_sources=(a_backend_source(directory),)), places


def rewriting_the_backend_source(target: CVETarget) -> None:
    target.backend_sources[0].write_text('SCHEMA = "CREATE TABLE t2 (c1 INT)"\n')


def _keeping_another_record() -> TargetChange:
    def change(target: CVETarget, places: Places, _docker: Path) -> tuple[CVETarget, Places]:
        extra = _a_file_record("fict-extra")
        kept = (*target.kept_places, extra.id)
        return dataclasses.replace(target, kept_places=kept), {**places, extra.id: extra}

    return change


def _moving_the_kept_endpoint_record() -> TargetChange:
    def change(target: CVETarget, places: Places, _docker: Path) -> tuple[CVETarget, Places]:
        return target, {**places, KEPT_ENDPOINT_ID: _an_endpoint_record(path="/fictional/moved")}

    return change


def _adding_a_record_the_target_does_not_keep() -> TargetChange:
    def change(target: CVETarget, places: Places, _docker: Path) -> tuple[CVETarget, Places]:
        other = _a_file_record("fict-unkept")
        return target, {**places, other.id: other}

    return change


def _changing_the_kept_record_family() -> TargetChange:
    def change(target: CVETarget, places: Places, _docker: Path) -> tuple[CVETarget, Places]:
        return target, {**places, KEPT_FILE_ID: _a_file_record(family="another-family")}

    return change


async def _another_exploit(_places: Places, client: MCPClientPort) -> None:
    await client.call_tool("kubectl_generic", {"command": "version && id"})


# Applied to a_target_keeping_an_endpoint (so the sentinel Dockerfile is in the fingerprint).
FINGERPRINTED_CHANGES: dict[str, TargetChange] = {
    "dockerfile instruction": _appending_to_its_dockerfile("RUN true"),
    "patched dockerfile instruction": _appending_to_the_patched_dockerfile("RUN true"),
    "aim": _replacing(aim=re.compile(r"[;&]")),
    "class": _replacing(mechanisms=frozenset({MechanismClass.READ_OUTSIDE_SCOPE})),
    "a class gained": _replacing(
        mechanisms=frozenset({MechanismClass.COMMAND_EXECUTION, MechanismClass.READ_OUTSIDE_SCOPE})
    ),
    "no class": _replacing(mechanisms=frozenset[MechanismClass]()),
    "tools filter": _replacing(tools_filter=frozenset({"kubectl_generic", "kubectl_get"})),
    "server image": _replacing(server_image="another-service"),
    "reaches": _replacing(reaches=frozenset({"arbitrary_read"})),
    "planting host": _replacing(planting_host=PlantingHost(SymbolicUser.HOST, "/elsewhere", True)),
    "a read-write layout": _changing_its_host(layout_mount=LayoutMount.READ_WRITE),
    "a baked /work": _changing_its_host(baked_work=True),
    "a fictional kept id added": _keeping_another_record(),
    "a kept record moved in the mapping": _moving_the_kept_endpoint_record(),
    "the sentinel Dockerfile (a kept endpoint)": _appending_to_the_sentinel_dockerfile("RUN true"),
    "launch mode": _replacing(launch_mode=LaunchMode.FALLBACK),
    "backend images": _replacing(backend_images=("apache/doris:all-in-one-4.1.3",)),
    "backend source declared": _declaring_a_backend_source(),
}

# Applied to a_target_keeping_a_file (so no kept endpoint, the sentinel Dockerfile is out).
UNFINGERPRINTED_CHANGES: dict[str, TargetChange] = {
    "dockerfile comment": _appending_to_its_dockerfile("# a comment"),
    "dockerfile blank line": _appending_to_its_dockerfile("   "),
    "note": _replacing(note="another note"),
    "severity": _replacing(severity="CVSS 9.8 (v3.1, CNA)"),
    "awaited capability": _replacing(awaited_capability="cross-tool chains"),
    "exploits": _replacing(exploits=(_another_exploit,)),
    "a record the target does not keep": _adding_a_record_the_target_does_not_keep(),
    "a kept record's family": _changing_the_kept_record_family(),
    "the sentinel Dockerfile (no kept endpoint)": _appending_to_the_sentinel_dockerfile("RUN true"),
    "no backend source declared": _replacing(backend_sources=()),
}


def a_target_declaring_a_stand_in() -> tuple[CVETarget, Places]:
    target, places = a_target_keeping_a_file()
    host = dataclasses.replace(
        target.planting_host, public_names=PublicNames(stand_ins=(STAND_IN_HOST,))
    )
    return dataclasses.replace(target, planting_host=host), places


def _rewriting_the_capture(**fields: object) -> StandInChange:
    def change(target: CVETarget, stand_ins: Path) -> CVETarget:
        capture_file = stand_ins / f"{STAND_IN_HOST}.json"
        capture = json.loads(capture_file.read_text())
        capture_file.write_text(json.dumps({**capture, **fields}))
        return target

    return change


def _rewriting_the_leaf(target: CVETarget, stand_ins: Path) -> CVETarget:
    (stand_ins / "tls" / f"{STAND_IN_HOST}.pem").write_text("another leaf")
    return target


def _trusting(*names: str) -> StandInChange:
    def change(target: CVETarget, _stand_ins: Path) -> CVETarget:
        public_names = dataclasses.replace(target.planting_host.public_names, trust=names)
        host = dataclasses.replace(target.planting_host, public_names=public_names)
        return dataclasses.replace(target, planting_host=host)

    return change


# Applied to a_target_declaring_a_stand_in, on the directory a_stand_ins_directory wrote.
STAND_IN_CHANGES: dict[str, StandInChange] = {
    "capture": _rewriting_the_capture(captured_at="2026-11-03T10:00:00Z"),
    "leaf": _rewriting_the_leaf,
    "address": _rewriting_the_capture(address="93.184.215.15"),
    "trust setting": _trusting("SSL_CERT_FILE"),
}


def conditions(runs: int = 3) -> CVERunConditions:
    return CVERunConditions(
        runs=runs,
        budget=10,
        tools_filtered=True,
        provider="openai",
        model="gpt-6-luna",
        judge_model="gpt-6-luna",
        reasoning="none",
        judge_reasoning="none",
        grammar_fingerprint="grammar",
    )


def a_baseline(
    runs: list[CVEStatus],
    status: BaselineStatus = BaselineStatus.EXPLORATORY,
    cve_id: str = "CVE-2025-53355",
) -> CVETargetBaseline:
    return CVETargetBaseline(
        cve_id=cve_id,
        status=status,
        conditions=conditions(),
        fixture_fingerprint="fixture",
        replay_rule=ReplayRule(),
        commit=RECORDED_COMMIT,
        recorded_at="2026-09-28T10:00:00+00:00",
        runs=runs,
        image_ids={"kubernetes": "sha256:0123"},
    )


def a_confirmation(runs: list[CVEStatus]) -> CVETargetBaseline:
    first = RecordingRef(commit=RECORDED_COMMIT, recorded_at="2026-09-28T09:00:00+00:00")
    return a_baseline(runs, status=BaselineStatus.CONFIRMED).model_copy(update={"confirms": first})
