import hashlib
import io
import tokenize
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from evals.gate import Cell, Observation, ReplayRule, cell_key, parse_cell_key
from evals.ground_truth import GroundTruth
from evals.metrics import EvalMetrics


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
    """Hash of the token stream, blind to comments, blank lines and positions.

    Types are hashed by name: their numbers shift between Python minor versions.
    """
    ignored = {tokenize.COMMENT, tokenize.NL}
    tokens = [
        (tokenize.tok_name[token.type], token.string)
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type not in ignored
    ]
    return hashlib.sha256(repr(tokens).encode()).hexdigest()


def condition_mismatches(recorded: BaselineConditions, candidate: BaselineConditions) -> list[str]:
    mismatches = _field_mismatches(
        "", recorded.model_dump(exclude={"fixtures"}), candidate.model_dump(exclude={"fixtures"})
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


def load_baseline(path: Path) -> Baseline | None:
    if not path.exists():
        return None
    return Baseline.model_validate_json(path.read_text())


def write_baseline(path: Path, baseline: Baseline) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(baseline.model_dump_json(indent=2))
