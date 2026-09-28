"""The judge isolation baseline (ADR 025): what each run observed on each case of the fixture,
with no label, so a rubric revision re-scores it and a redraw resets it."""

import os
from pathlib import Path

from pydantic import BaseModel

from evals.baseline import BaselineStatus, RecordingRef
from evals.gate import Observation, ProtectedCells, ReplayRule
from evals.honeypots import REPO_ROOT
from evals.judge_fixture import JudgeFixture, inputs_fingerprint

JUDGE_BASELINE_PATH = REPO_ROOT / "evals" / "baselines" / "judge_isolation.json"


class JudgeConditions(BaseModel):
    runs: int
    provider: str
    judge_model: str
    judge_reasoning: str | None
    inputs_fingerprint: str


class JudgeBaseline(BaseModel):
    status: BaselineStatus
    conditions: JudgeConditions
    replay_rule: ReplayRule
    commit: str
    recorded_at: str
    runs: list[dict[str, Observation]]  # case id -> observation, every case of the fixture
    confirms: RecordingRef | None = None
    replaces: RecordingRef | None = None
    disagreements: list[str] = []
    protected: ProtectedCells


def load_judge_baseline(path: Path) -> JudgeBaseline | None:
    if not path.exists():
        return None
    return JudgeBaseline.model_validate_json(path.read_text())


def write_judge_baseline(path: Path, baseline: JudgeBaseline) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(baseline.model_dump_json(indent=2))
    os.replace(temporary, path)


def judge_baseline_integrity(baseline: JudgeBaseline, fixture: JudgeFixture) -> list[str]:
    """What the file holds that its conditions do not claim. The cases are checked only against
    the draw the baseline was recorded on: another draw is a condition mismatch."""
    problems = _run_count_problems(baseline)
    if baseline.conditions.inputs_fingerprint != inputs_fingerprint(fixture):
        return problems
    expected = {case.id for case in fixture.cases}
    for index, run in enumerate(baseline.runs):
        problems += _run_problems(index, set(run), expected)
    return problems


def _run_count_problems(baseline: JudgeBaseline) -> list[str]:
    held = len(baseline.runs)
    if not held:
        return ["the baseline holds no run"]
    if baseline.confirms is None:
        claimed, claimants = baseline.conditions.runs, "its conditions"
    else:  # a confirmation holds the runs of both recordings (ADR 023)
        claimed, claimants = baseline.conditions.runs * 2, "its conditions and its confirmation"
    if held == claimed:
        return []
    return [f"the baseline holds {held} runs, {claimants} claim {claimed}"]


def _run_problems(index: int, held: set[str], expected: set[str]) -> list[str]:
    missing, extra = sorted(expected - held), sorted(held - expected)
    sides: list[str] = []
    if missing:
        sides.append(f"{missing} missing")
    if extra:
        sides.append(f"{extra} unknown")
    return [f"run {index}: cases {', '.join(sides)}"] if sides else []


def judge_condition_mismatches(recorded: JudgeConditions, candidate: JudgeConditions) -> list[str]:
    candidate_fields = candidate.model_dump()
    return [
        f"{field}: baseline {value}, candidate {candidate_fields[field]}"
        for field, value in recorded.model_dump().items()
        if value != candidate_fields[field]
    ]
