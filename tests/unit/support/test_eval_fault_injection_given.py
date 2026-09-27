"""Faulted candidates built from the observations of the recording refused on 2026-09-27.

A candidate holds observations, not cases, so its distribution coverage cannot be computed
from it: each fault states the coverage its generator would give (`compute_distribution_coverage`
counts the categories among a tool's judged cases, chains excluded).
"""

import random
from dataclasses import dataclass

from evals.baseline import Baseline, load_baseline
from evals.gate import Cell, Observation, cell_key
from evals.honeypots import MERGED_GROUND_TRUTH, REPO_ROOT
from evals.metrics import EvalMetrics, VerdictMap, compute_consistency, label_scores
from mcp_auditor.domain.models import AuditCategory, EvalVerdict
from tests.fakes.fixture_judge import CHAIN_ONLY_FLAWS

FIXTURE_PATH = REPO_ROOT / "evals" / "fixtures" / "fault_injection_baseline.json"

STABLE_CORRECT_FAILS: list[Cell] = [
    ("get_user", AuditCategory.ERROR_HANDLING),
    ("execute_query", AuditCategory.INFO_LEAKAGE),
    ("delete_record", AuditCategory.INPUT_VALIDATION),
]
# Every PASS cell is stable and correct in the recording.
EXPECTED_PASSES: list[Cell] = [
    cell for cell, verdict in MERGED_GROUND_TRUTH.items() if verdict == EvalVerdict.PASS
]
STABLE_CORRECT_CELLS = STABLE_CORRECT_FAILS + EXPECTED_PASSES

# The stable and correct cells that the random judge of seed 0 leaves correct in every run.
SPARED_BY_THE_RANDOM_JUDGE: list[Cell] = [
    ("execute_query", AuditCategory.RESOURCE_ABUSE),
    ("list_items", AuditCategory.INPUT_VALIDATION),
    ("list_items", AuditCategory.ERROR_HANDLING),
    ("search_users", AuditCategory.RESOURCE_ABUSE),
    ("delete_record", AuditCategory.INJECTION),
    ("project_manager", AuditCategory.RESOURCE_ABUSE),
]

# The stable and correct FAIL cells whose detection the half-loss draw of seed 0 loses in a run.
LOST_BY_THE_HALF_LOSS_DRAW: list[Cell] = [
    ("get_user", AuditCategory.ERROR_HANDLING),
    ("delete_record", AuditCategory.INPUT_VALIDATION),
]

# Replays under the rule of 4 reproductions out of at most 5, stopping early.
REPRODUCING = [True, True, True, True]
REPRODUCING_TWICE = [True, False, True, False, False]
REPRODUCING_THREE_TIMES = [True, True, False, True, False]

ObservationRuns = list[dict[Cell, Observation]]


@dataclass(frozen=True)
class FaultedCandidate:
    runs: ObservationRuns
    distribution_coverage: float


def the_fault_injection_baseline() -> Baseline:
    baseline = load_baseline(FIXTURE_PATH)
    assert baseline is not None
    return baseline


def a_judge_passing_everything() -> FaultedCandidate:
    return _every_cell_observed(Observation.PASS, distribution_coverage=1.0)


def a_judge_failing_everything() -> FaultedCandidate:
    return _every_cell_observed(Observation.FAIL, distribution_coverage=1.0)


def no_verdict() -> FaultedCandidate:
    return _every_cell_observed(Observation.UNCOVERED, distribution_coverage=0.0)


def a_judge_failing_at_random(seed: int) -> FaultedCandidate:
    runs = [
        {cell: Observation.FAIL if _coin(seed, index, cell) else Observation.PASS for cell in run}
        for index, run in enumerate(_recorded_runs())
    ]
    return FaultedCandidate(runs=runs, distribution_coverage=1.0)


def half_the_detections_lost(seed: int) -> FaultedCandidate:
    runs = [
        {
            cell: Observation.PASS
            if seen == Observation.FAIL and _coin(seed, index, cell)
            else seen
            for cell, seen in run.items()
        }
        for index, run in enumerate(_recorded_runs())
    ]
    return FaultedCandidate(runs=runs, distribution_coverage=1.0)


def a_generator_dropping(category: AuditCategory) -> FaultedCandidate:
    """Four categories of five per tool are left, so coverage reads 0.80."""
    runs = [
        {cell: Observation.UNCOVERED if cell[1] == category else seen for cell, seen in run.items()}
        for run in _recorded_runs()
    ]
    return FaultedCandidate(runs=runs, distribution_coverage=0.8)


def chain_steps_refused() -> FaultedCandidate:
    """The cells of `CHAIN_ONLY_FLAWS` keep only single-step verdicts, which pass."""
    runs = [
        {cell: Observation.PASS if cell in CHAIN_ONLY_FLAWS else seen for cell, seen in run.items()}
        for run in _recorded_runs()
    ]
    return FaultedCandidate(runs=runs, distribution_coverage=1.0)


def metrics_of(candidate: FaultedCandidate) -> EvalMetrics:
    """Recall and precision from the observations, as `rescore` computes them."""
    verdict_maps: list[VerdictMap] = [
        {
            cell: None if seen == Observation.UNCOVERED else EvalVerdict(seen.value)
            for cell, seen in run.items()
        }
        for run in candidate.runs
    ]
    consistency, _ = compute_consistency(verdict_maps, MERGED_GROUND_TRUTH)
    return EvalMetrics(
        **label_scores(verdict_maps, MERGED_GROUND_TRUTH),
        consistency=consistency,
        distribution_coverage=candidate.distribution_coverage,
    )


def _every_cell_observed(seen: Observation, distribution_coverage: float) -> FaultedCandidate:
    runs = [{cell: seen for cell in run} for run in _recorded_runs()]
    return FaultedCandidate(runs=runs, distribution_coverage=distribution_coverage)


def _recorded_runs() -> ObservationRuns:
    return the_fault_injection_baseline().observation_runs()


def _coin(seed: int, run_index: int, cell: Cell) -> bool:
    return random.Random(f"{seed}/{run_index}/{cell_key(cell)}").random() < 0.5
