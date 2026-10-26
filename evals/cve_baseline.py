import hashlib
import json
import os
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from pydantic import BaseModel

from evals import (
    cve_endpoint_address,
    cve_environments,
    cve_grammar,
    cve_layout,
    cve_places,
    cve_planting,
    cve_planting_base,
    cve_planting_docker,
    cve_planting_spec,
    cve_proofs,
    cve_report_units,
    cve_units,
)
from evals.baseline import BaselineStatus, RecordingRef, fingerprint_sources
from evals.cve_grammar import DETECTION_RUNGS, CVEStatus
from evals.cve_images import dockerfile_instructions
from evals.cve_places import Coordinates, Place, Places, PlantKind, kept_records
from evals.cve_planting import PlantingHost
from evals.cve_targets import (
    DOCKER_DIRECTORY,
    CVETarget,
    LaunchMode,
    image_dockerfile,
    image_tag,
)
from evals.gate import ReplayRule

CVE_BASELINE_DIRECTORY = Path(__file__).parent / "baselines" / "cve"
# Fingerprinted in this fixed order, so the fingerprint names one version of the grammar.
GRAMMAR_PATHS = (
    Path(cve_grammar.__file__),
    Path(cve_proofs.__file__),
    Path(cve_units.__file__),
    Path(cve_report_units.__file__),
)
# Fingerprinted in this fixed order, as part of every target's fixture. The planting layer
# decides what reaches the auditor, so a semantic change to it moves every target's fingerprint.
_ENVIRONMENT_PATHS = (
    Path(cve_environments.__file__),
    Path(cve_layout.__file__),
    Path(cve_places.__file__),
    Path(cve_planting.__file__),
    Path(cve_planting_base.__file__),
    Path(cve_planting_spec.__file__),
    Path(cve_planting_docker.__file__),
    Path(cve_endpoint_address.__file__),
)


class CVERunConditions(BaseModel):
    runs: int
    budget: int
    # Always True today, recorded because a capability number needs False (ADR 015).
    tools_filtered: bool
    provider: str
    model: str
    judge_model: str
    reasoning: str | None
    judge_reasoning: str | None
    grammar_fingerprint: str


class CVETargetBaseline(BaseModel):
    cve_id: str
    status: BaselineStatus
    conditions: CVERunConditions
    fixture_fingerprint: str
    replay_rule: ReplayRule
    commit: str
    recorded_at: str
    # One status per run, the rung kept for the reader: the planted nonce is the one detection.
    runs: list[CVEStatus]
    confirms: RecordingRef | None = None
    replaces: RecordingRef | None = None
    # Image name to image ID at recording: provenance, not a condition (ADR 024).
    image_ids: dict[str, str]

    def detected_runs(self) -> list[bool]:
        return [status in DETECTION_RUNGS for status in self.runs]

    def gated(self) -> bool:
        return self.status == BaselineStatus.CONFIRMED and all(self.detected_runs())


def fixture_fingerprint(
    target: CVETarget, places: Places, docker_directory: Path = DOCKER_DIRECTORY
) -> str:
    """What builds, seeds and launches the target, and what of it reaches the auditor or
    the oracle (ADR 020's principle, read per target by ADR 024).

    In: the environment and places modules (AST fingerprint, so comments, formatting
    and module docstrings are out), each Dockerfile of the target's images and the patched
    twin's Dockerfile (both without their comment and blank lines, so a patched pin that moves
    moves the fingerprint), the builder's name, the server image, the mechanism, the aim, the
    tools filter, the flaw's reach, the planting host, the loaded record of each kept place
    (its id, kind, coordinates and reach, in kept_places order), the launch-mode field (and the
    fallback scope under the fallback launch-mode, holdout-rule.md:231), the backend images the
    builder pulls outside the compose build (when any), and the sentinel Dockerfile
    whenever a kept record is an http_endpoint, since the sentinel image serves it on any
    target. Out:
    the exploits and benign call (calibration only), the severity, the note, the awaited
    capability (report text), the drawn nonces (random per launch), the CI skip, the kept
    places' family (plants nothing), and what each caller chooses to plant and launch (the
    kept places for a graded run, every candidate for the survey), which live in the callers.
    A change to the shared environment code moves every target's fingerprint.

    The environment modules are fingerprinted whole, the admission reference arm
    (`build_empty_layout`, inert on the graded run) included, by choice of granularity: a rare
    false-positive reset is the price of an instrument with no silent hole.
    """
    records = kept_records(target.kept_places, places)
    parts: list[object] = [
        fingerprint_sources([path.read_text() for path in _ENVIRONMENT_PATHS]),
        [
            dockerfile_instructions(image_dockerfile(name, docker_directory))
            for name in target.images
        ],
        dockerfile_instructions(image_dockerfile(target.patched_image, docker_directory)),
        target.builder.__name__,
        target.server_image,
        None if target.mechanism is None else target.mechanism.value,
        target.aim.pattern,
        None if target.tools_filter is None else sorted(target.tools_filter),
        sorted(target.reaches),
        planting_host_parts(target.planting_host),
        [_record_parts(record) for record in records],
        target.launch_mode.value,
    ]
    # The fingerprint covers the launch the target runs under with the fallback included
    # (holdout-rule.md:231): under the fallback launch-mode the fallback scope is part of it.
    if target.launch_mode is LaunchMode.FALLBACK:
        parts.append([target.fallback_scope.kind.value, target.fallback_scope.path])
    if target.backend_images:
        parts.append(sorted(target.backend_images))
    if any(record.kind is PlantKind.HTTP_ENDPOINT for record in records):
        parts.append(dockerfile_instructions(image_dockerfile("sentinel", docker_directory)))
    return hashlib.sha256(json.dumps(parts).encode()).hexdigest()


def planting_host_parts(host: PlantingHost) -> list[object]:
    return [host.user.value, host.working_directory, host.has_network]


def _record_parts(record: Place) -> list[object]:
    return [
        record.id,
        record.kind.value,
        _coordinate_parts(record.coordinates),
        sorted(record.reachable_by),
    ]


def _coordinate_parts(coordinates: Coordinates) -> dict[str, object]:
    fields: dict[str, object | None] = {
        "path": coordinates.path,
        "paths": None if coordinates.paths is None else list(coordinates.paths),
        "name": coordinates.name,
        "host": coordinates.host,
        "anchor": None if coordinates.anchor is None else coordinates.anchor.value,
        "relpath": coordinates.relpath,
    }
    return {key: fields[key] for key in sorted(fields) if fields[key] is not None}


def grammar_fingerprint() -> str:
    return fingerprint_sources([path.read_text() for path in GRAMMAR_PATHS])


def image_ids(names: Sequence[str], tag: Callable[[str], str] = image_tag) -> dict[str, str]:
    return {
        name: subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", tag(name)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        for name in names
    }


def backend_image_ids(tags: Sequence[str]) -> dict[str, str]:
    # check=False, keeping the tags that resolve: a provenance lookup never raises. A target
    # dropped before launch never reaches assembly, so its backend image is never looked up.
    ids: dict[str, str] = {}
    for tag in tags:
        inspected = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", tag],
            check=False,
            capture_output=True,
            text=True,
        )
        if inspected.returncode == 0:
            ids[tag] = inspected.stdout.strip()
    return ids


def load_baselines(directory: Path) -> dict[str, CVETargetBaseline]:
    baselines: dict[str, CVETargetBaseline] = {}
    for path in sorted(directory.glob("*.json")):
        baseline = CVETargetBaseline.model_validate_json(path.read_text())
        if baseline.cve_id != path.stem:
            raise ValueError(f"{path.name} holds the baseline of {baseline.cve_id}")
        baselines[baseline.cve_id] = baseline
    return baselines


def write_baseline(directory: Path, baseline: CVETargetBaseline) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{baseline.cve_id}.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(baseline.model_dump_json(indent=2))
    os.replace(temporary, path)


def baseline_integrity(baseline: CVETargetBaseline) -> list[str]:
    """What the file holds that its conditions do not claim, checked when the runner loads it."""
    held = len(baseline.runs)
    if not held:
        return [f"{baseline.cve_id}: the baseline holds no run"]
    if baseline.confirms is None:
        claimed, claimants = baseline.conditions.runs, "its conditions"
    else:  # a confirmation holds the runs of both recordings (ADR 023)
        claimed, claimants = baseline.conditions.runs * 2, "its conditions and its confirmation"
    if held == claimed:
        return []
    return [f"{baseline.cve_id}: the baseline holds {held} runs, {claimants} claim {claimed}"]
