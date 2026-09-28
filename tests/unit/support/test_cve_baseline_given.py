import dataclasses
import re
import shutil
from collections.abc import Callable
from pathlib import Path

from evals.baseline import BaselineStatus, RecordingRef
from evals.cve_baseline import CVERunConditions, CVETargetBaseline
from evals.cve_grammar import CVEStatus, MechanismClass
from evals.cve_targets import CVE_TARGETS, DOCKER_DIRECTORY, CVETarget
from evals.gate import ReplayRule
from mcp_auditor.domain.ports import MCPClientPort

type TargetChange = Callable[[CVETarget, Path], CVETarget]

KUBERNETES_TARGET = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53355")
SYMLINK_TARGET = next(target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53109")
PREFIX_COLLISION_TARGET = next(
    target for target in CVE_TARGETS if target.cve_id == "CVE-2025-53110"
)
RECORDED_COMMIT = "0123abc"


def a_docker_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "docker"
    directory.mkdir()
    for dockerfile in DOCKER_DIRECTORY.glob("Dockerfile.*"):
        shutil.copy(dockerfile, directory / dockerfile.name)
    return directory


def _appending_to_its_dockerfile(line: str) -> TargetChange:
    def change(target: CVETarget, docker_directory: Path) -> CVETarget:
        dockerfile = docker_directory / f"Dockerfile.{target.images[0]}"
        dockerfile.write_text(f"{dockerfile.read_text()}\n{line}\n")
        return target

    return change


def _replacing(**fields: object) -> TargetChange:
    def change(target: CVETarget, _docker_directory: Path) -> CVETarget:
        return dataclasses.replace(target, **fields)

    return change


async def _another_exploit(client: MCPClientPort) -> None:
    await client.call_tool("kubectl_generic", {"command": "version && id"})


FINGERPRINTED_CHANGES: dict[str, TargetChange] = {
    "dockerfile instruction": _appending_to_its_dockerfile("RUN true"),
    "aim": _replacing(aim=re.compile(r"[;&]")),
    "mechanism": _replacing(mechanism=MechanismClass.READ_OUTSIDE_SCOPE),
    "tools filter": _replacing(tools_filter=frozenset({"kubectl_generic", "kubectl_get"})),
    "builder argument": _replacing(builder_args=("another-image:local",)),
}

UNFINGERPRINTED_CHANGES: dict[str, TargetChange] = {
    "dockerfile comment": _appending_to_its_dockerfile("# a comment"),
    "dockerfile blank line": _appending_to_its_dockerfile("   "),
    "note": _replacing(note="another note"),
    "severity": _replacing(severity="CVSS 9.8 (v3.1, CNA)"),
    "awaited capability": _replacing(awaited_capability="cross-tool chains"),
    "exploit": _replacing(exploit=_another_exploit),
    "sentinel": _replacing(sentinel="MCPAUDIT-another"),
}


def a_prefix_collision_target_built_like_the_symlink_one() -> CVETarget:
    return dataclasses.replace(PREFIX_COLLISION_TARGET, builder=SYMLINK_TARGET.builder)


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
