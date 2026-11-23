"""The judge eval baseline (ADR 025): what each run observed on each case of the fixture,
with no label, so a rubric revision re-scores it and a redraw resets it."""

from pathlib import Path

from pydantic import BaseModel

from evals.baseline import (
    BaselineStatus,
    RecordingRef,
    field_mismatches,
    missing_and_unknown_keys,
    run_count_problems,
    write_json_atomically,
)
from evals.gate import Observation, ProtectedCells, RetestRule
from evals.judge.fixture import JudgeFixture, inputs_fingerprint
from evals.model_conditions import ModelConditions
from evals.repository import REPO_ROOT
from mcp_auditor.config import Settings

JUDGE_BASELINE_PATH = REPO_ROOT / "evals" / "baselines" / "judge.json"


class JudgeConditions(BaseModel):
    runs: int
    provider: str
    judge_model: str
    judge_reasoning: str | None
    inputs_fingerprint: str


def judge_conditions(settings: Settings, runs: int, fingerprint: str) -> JudgeConditions:
    models = ModelConditions.of(settings)
    return JudgeConditions(
        runs=runs,
        provider=models.provider,
        judge_model=models.judge_model,
        judge_reasoning=models.judge_reasoning,
        inputs_fingerprint=fingerprint,
    )


class JudgeBaseline(BaseModel):
    status: BaselineStatus
    conditions: JudgeConditions
    retest_rule: RetestRule
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
    write_json_atomically(path, baseline)


def judge_baseline_integrity(baseline: JudgeBaseline, fixture: JudgeFixture) -> list[str]:
    """What the file holds that its conditions do not claim. The cases are checked only against
    the draw the baseline was recorded on: another draw is a condition mismatch."""
    problems = run_count_problems(len(baseline.runs), baseline.conditions.runs, baseline.confirms)
    if baseline.conditions.inputs_fingerprint != inputs_fingerprint(fixture):
        return problems
    expected = {case.id for case in fixture.cases}
    for index, run in enumerate(baseline.runs):
        problems += missing_and_unknown_keys(f"run {index}: cases", set(run), expected)
    return problems


def judge_condition_mismatches(recorded: JudgeConditions, candidate: JudgeConditions) -> list[str]:
    return field_mismatches("", recorded.model_dump(), candidate.model_dump())
