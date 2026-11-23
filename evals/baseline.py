import ast
import functools
import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel

from evals.gate import Observation, ProtectedCells, RetestRule, protected_cells
from evals.ground_truth import Cell, GroundTruth, cell_key, parse_cell_key
from evals.metrics import HoneypotMetrics, KeyedVerdicts, label_scores


class BaselineStatus(StrEnum):
    UNCONFIRMED = "unconfirmed"
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


class RecordedBaseline(Protocol):
    @property
    def status(self) -> BaselineStatus: ...

    @property
    def commit(self) -> str: ...

    @property
    def recorded_at(self) -> str: ...


class RecordingRef(BaseModel):
    commit: str
    recorded_at: str

    @classmethod
    def of(cls, baseline: RecordedBaseline) -> "RecordingRef":
        return cls(commit=baseline.commit, recorded_at=baseline.recorded_at)


class Baseline(BaseModel):
    status: BaselineStatus
    conditions: BaselineConditions
    retest_rule: RetestRule
    commit: str
    recorded_at: str
    runs: list[dict[str, Observation]]
    metrics: HoneypotMetrics
    confirms: RecordingRef | None = None
    replaces: RecordingRef | None = None
    disagreements: list[str] = []
    # The recording-time summary, for the reader: `None` in a file written before it existed.
    protected: ProtectedCells | None = None

    def observation_runs(self) -> list[dict[Cell, Observation]]:
        return [
            {parse_cell_key(key): observation for key, observation in run.items()}
            for run in self.runs
        ]


def fingerprint_sources(sources: Sequence[str]) -> str:
    """Each module is fingerprinted on its own, so every module docstring is left out."""
    digests = "\n".join(fingerprint_source(source) for source in sources)
    return hashlib.sha256(digests.encode()).hexdigest()


@functools.cache
def fingerprint_source(source: str) -> str:
    """Hash of what executes or reaches the model: comments, formatting and the module
    docstring are left out (ADR 020). The format of `ast.dump` can change with a Python
    version, which the pinned fingerprint test catches.
    """
    module = ast.parse(source)
    if ast.get_docstring(module, clean=False) is not None:
        module.body = module.body[1:]
    return hashlib.sha256(ast.dump(module).encode()).hexdigest()


def condition_mismatches(recorded: BaselineConditions, candidate: BaselineConditions) -> list[str]:
    # The ground truth fingerprint is provenance: a label revision re-scores (ADR 020).
    excluded = {"fixtures", "ground_truth_fingerprint"}
    mismatches = field_mismatches(
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
        mismatches += field_mismatches(
            f"fixtures.{name}.", recorded_fixture.model_dump(), candidate_fixture.model_dump()
        )
    return mismatches


def field_mismatches(
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
    metrics: HoneypotMetrics
    protected: ProtectedCells


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
    return RescoredBaseline(
        ground_truth=recorded,
        metrics=baseline.metrics.model_copy(update=label_scores(verdict_maps_of(runs), recorded)),
        protected=protected_cells(runs, recorded),
    )


def verdict_maps_of[K](runs: list[dict[K, Observation]]) -> list[KeyedVerdicts[K]]:
    return [{cell: seen.verdict for cell, seen in run.items()} for run in runs]


def baseline_integrity(baseline: Baseline, ground_truth: GroundTruth) -> list[str]:
    """What the file holds that its conditions do not claim, checked when the runner loads it."""
    problems = run_count_problems(len(baseline.runs), baseline.conditions.runs, baseline.confirms)
    same_ground_truth = baseline.conditions.ground_truth_fingerprint == fingerprint_ground_truth(
        ground_truth
    )
    for index, run in enumerate(baseline.runs):
        problems += _run_problems(index, run, ground_truth if same_ground_truth else None)
    return problems


def fingerprint_ground_truth(ground_truth: GroundTruth) -> str:
    lines = sorted(f"{cell_key(cell)}={verdict.value}" for cell, verdict in ground_truth.items())
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def run_count_problems(held: int, claimed_runs: int, confirms: RecordingRef | None) -> list[str]:
    if not held:
        return ["the baseline holds no run"]
    if confirms is None:
        claimed, claimants = claimed_runs, "its conditions"
    else:  # a confirmation holds the runs of both recordings (ADR 023)
        claimed, claimants = claimed_runs * 2, "its conditions and its confirmation"
    if held == claimed:
        return []
    return [f"the baseline holds {held} runs, {claimants} claim {claimed}"]


def _run_problems(
    index: int, run: dict[str, Observation], ground_truth: GroundTruth | None
) -> list[str]:
    unreadable = [key for key in run if _unreadable(key)]
    if unreadable:
        return [f"run {index}: unreadable cell key {key!r}" for key in unreadable]
    if ground_truth is None:
        return []
    expected = {cell_key(cell) for cell in ground_truth}
    return missing_and_unknown_keys(f"run {index}: cells", set(run), expected)


def missing_and_unknown_keys(prefix: str, held: set[str], expected: set[str]) -> list[str]:
    missing, extra = sorted(expected - held), sorted(held - expected)
    sides: list[str] = []
    if missing:
        sides.append(f"{missing} missing")
    if extra:
        sides.append(f"{extra} unknown")
    return [f"{prefix} {', '.join(sides)}"] if sides else []


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
    write_json_atomically(path, baseline)


def write_json_atomically(path: Path, model: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(model.model_dump_json(indent=2))
    os.replace(temporary, path)
