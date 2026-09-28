import hashlib
import json
import os
from pathlib import Path

from pydantic import BaseModel

from evals import cve_environments, cve_seeding
from evals.baseline import BaselineStatus, RecordingRef, fingerprint_sources
from evals.cve_grammar import DETECTION_RUNGS, CVEStatus
from evals.cve_targets import DOCKER_DIRECTORY, CVETarget, image_dockerfile
from evals.gate import ReplayRule

CVE_BASELINE_DIRECTORY = Path(__file__).parent / "baselines" / "cve"
# Fingerprinted in this fixed order, as part of every target's fixture.
_ENVIRONMENT_PATHS = (Path(cve_environments.__file__), Path(cve_seeding.__file__))


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
    # One status per run, the rung kept for the reader: either detection rung detects.
    runs: list[CVEStatus]
    confirms: RecordingRef | None = None
    replaces: RecordingRef | None = None
    # Image name to image ID at recording: provenance, not a condition (ADR 024).
    image_ids: dict[str, str]

    def detected_runs(self) -> list[bool]:
        return [status in DETECTION_RUNGS for status in self.runs]

    def gated(self) -> bool:
        return self.status == BaselineStatus.CONFIRMED and all(self.detected_runs())


def fixture_fingerprint(target: CVETarget, docker_directory: Path = DOCKER_DIRECTORY) -> str:
    """What builds, seeds and launches the target, and what of it reaches the auditor or
    the oracle (ADR 020's principle, read per target by ADR 024).

    In: the environment and seeding modules (AST fingerprint, so comments, formatting and
    module docstrings are out), each Dockerfile of the target's images without its comment
    and blank lines, the builder's name and arguments, the mechanism, the aim and the tools
    filter. Out: the exploit and benign call (calibration only), the severity, the note,
    the awaited capability (report text), the sentinel (random per process) and the CI skip.
    A change to the shared environment code moves every target's fingerprint.
    """
    parts: list[object] = [
        fingerprint_sources([path.read_text() for path in _ENVIRONMENT_PATHS]),
        [
            _dockerfile_instructions(image_dockerfile(name, docker_directory))
            for name in target.images
        ],
        target.builder.__name__,
        list(target.builder_args),
        target.mechanism.value,
        target.aim.pattern,
        None if target.tools_filter is None else sorted(target.tools_filter),
    ]
    return hashlib.sha256(json.dumps(parts).encode()).hexdigest()


def _dockerfile_instructions(path: Path) -> list[str]:
    lines = (line.strip() for line in path.read_text().splitlines())
    return [line for line in lines if line and not line.startswith("#")]


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
