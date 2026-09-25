import ast
import hashlib
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from evals.gate import Cell, Observation, ReplayRule, cell_key, parse_cell_key
from evals.ground_truth import GroundTruth
from evals.metrics import EvalMetrics, VerdictMap, label_scores
from mcp_auditor.domain.models import EvalVerdict


class BaselineStatus(StrEnum):
    EXPLORATORY = "exploratory"
    CONFIRMED = "confirmed"


class FixtureConditions(BaseModel):
    source_fingerprint: str
    chain_budget: int
    max_chain_steps: int


class BaselineConditions(BaseModel):
    runs: int
    budget: int
    tools_filter: list[str] | None = None
    provider: str
    model: str
    judge_model: str
    reasoning: str | None
    judge_reasoning: str | None
    ground_truth_fingerprint: str
    fixtures: dict[str, FixtureConditions]


class RecordingRef(BaseModel):
    commit: str
    recorded_at: str


class Baseline(BaseModel):
    status: BaselineStatus
    conditions: BaselineConditions
    replay_rule: ReplayRule
    commit: str
    recorded_at: str
    runs: list[dict[str, Observation]]
    metrics: EvalMetrics
    confirms: RecordingRef | None = None
    replaces: RecordingRef | None = None
    disagreements: list[str] = []

    def observation_runs(self) -> list[dict[Cell, Observation]]:
        return [
            {parse_cell_key(key): observation for key, observation in run.items()}
            for run in self.runs
        ]


def fingerprint_ground_truth(ground_truth: GroundTruth) -> str:
    lines = sorted(f"{cell_key(cell)}={verdict.value}" for cell, verdict in ground_truth.items())
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def fingerprint_source(source: str) -> str:
    """Hash of what executes or reaches the model: comments, formatting and the module
    docstring are left out (ADR 020). `ast.dump` output belongs to the Python minor version.
    """
    module = ast.parse(source)
    if ast.get_docstring(module, clean=False) is not None:
        module.body = module.body[1:]
    return hashlib.sha256(ast.dump(module).encode()).hexdigest()


def condition_mismatches(recorded: BaselineConditions, candidate: BaselineConditions) -> list[str]:
    # The ground truth fingerprint is provenance: a label revision re-scores (ADR 020).
    excluded = {"fixtures", "ground_truth_fingerprint"}
    mismatches = _field_mismatches(
        "", recorded.model_dump(exclude=excluded), candidate.model_dump(exclude=excluded)
    )
    for name in sorted(recorded.fixtures.keys() | candidate.fixtures.keys()):
        recorded_fixture = recorded.fixtures.get(name)
        candidate_fixture = candidate.fixtures.get(name)
        if recorded_fixture is None or candidate_fixture is None:
            mismatches.append(
                f"fixtures.{name}: baseline {recorded_fixture}, candidate {candidate_fixture}"
            )
            continue
        mismatches += _field_mismatches(
            f"fixtures.{name}.", recorded_fixture.model_dump(), candidate_fixture.model_dump()
        )
    return mismatches


def _field_mismatches(
    prefix: str, recorded: dict[str, object], candidate: dict[str, object]
) -> list[str]:
    return [
        f"{prefix}{field}: baseline {recorded[field]}, candidate {candidate[field]}"
        for field in recorded
        if recorded[field] != candidate[field]
    ]


@dataclass(frozen=True)
class RescoredBaseline:
    ground_truth: GroundTruth
    metrics: EvalMetrics


def rescore(baseline: Baseline, ground_truth: GroundTruth) -> RescoredBaseline:
    """The baseline under the current labels (ADR 020).

    An observation is what one run saw on a cell, pass, fail or uncovered, and carries no
    label, so a label revision re-scores the stored runs instead of resetting the baseline.
    A cell the revision added has no observation: it stays out of the comparison until a
    recording covers it, and `ground_truth` here holds only the cells the baseline recorded.
    Whether a baseline is confirmed depends on its observations alone, so a confirmed
    baseline stays confirmed under a revision. Consistency and distribution coverage are
    kept as recorded: no delta reads the first, and the second does not depend on the labels.
    """
    runs = baseline.observation_runs()
    recorded = {cell: verdict for cell, verdict in ground_truth.items() if cell in runs[0]}
    verdict_maps: list[VerdictMap] = [
        {
            cell: None if seen == Observation.UNCOVERED else EvalVerdict(seen.value)
            for cell, seen in run.items()
        }
        for run in runs
    ]
    return RescoredBaseline(
        ground_truth=recorded,
        metrics=baseline.metrics.model_copy(update=label_scores(verdict_maps, recorded)),
    )


def baseline_integrity(baseline: Baseline, ground_truth: GroundTruth) -> list[str]:
    """What the file holds that its conditions do not claim, checked when the runner loads it."""
    problems: list[str] = []
    claimed = baseline.conditions.runs
    if not baseline.runs:
        problems.append("the baseline holds no run")
    elif len(baseline.runs) != claimed:
        problems.append(
            f"the baseline holds {len(baseline.runs)} runs, its conditions claim {claimed}"
        )
    same_ground_truth = baseline.conditions.ground_truth_fingerprint == fingerprint_ground_truth(
        ground_truth
    )
    for index, run in enumerate(baseline.runs):
        problems += _run_problems(index, run, ground_truth if same_ground_truth else None)
    return problems


def _run_problems(
    index: int, run: dict[str, Observation], ground_truth: GroundTruth | None
) -> list[str]:
    unreadable = [key for key in run if _unreadable(key)]
    if unreadable:
        return [f"run {index}: unreadable cell key {key!r}" for key in unreadable]
    if ground_truth is None:
        return []
    expected = {cell_key(cell) for cell in ground_truth}
    missing, extra = sorted(expected - run.keys()), sorted(run.keys() - expected)
    sides: list[str] = []
    if missing:
        sides.append(f"{missing} missing")
    if extra:
        sides.append(f"{extra} unknown")
    return [f"run {index}: cells {', '.join(sides)}"] if sides else []


def _unreadable(key: str) -> bool:
    try:
        parse_cell_key(key)
    except ValueError:
        return True
    return False


def load_baseline(path: Path) -> Baseline | None:
    if not path.exists():
        return None
    return Baseline.model_validate_json(path.read_text())


def write_baseline(path: Path, baseline: Baseline) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(baseline.model_dump_json(indent=2))
    os.replace(temporary, path)
