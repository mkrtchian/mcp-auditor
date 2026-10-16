"""The result value objects of a holdout run, defined here so the statistic, the report and the
orchestrator all import them without a cycle (holdout_run imports the statistic and the report,
which both consume these, so they cannot live in holdout_run as the plan's prose placed them)."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from evals.census_draw import Side
from evals.holdout_conditions import Cutoff


@dataclass(frozen=True)
class HoldoutTargetResult:
    cve_id: str
    side: Side  # the drawn side (composition only); the split recomputes against the run cutoff
    disclosure_date: date
    mechanism_label: str | None
    tools_count: int
    ran_in_fallback: bool
    runs: int
    detected_runs: int
    detection_share: float
    detected_runs_if_unchecked_missed: int
    surfaced_places: list[list[str]]  # per run, place ids only
    struck_places: list[list[str]]  # per run, the credits the replay refused, ids only
    unchecked_places: list[list[str]]  # per run, the credits the replay could not check, ids only
    aimed_runs: int
    fail_without_proof_runs: int
    refused_runs: int
    run_cost: float  # dollars over its runs, refused runs included


@dataclass(frozen=True)
class NotRunTarget:
    cve_id: str
    reason: str


@dataclass(frozen=True)
class HoldoutRunResult:
    runs: int
    budget: int
    provider: str
    model: str
    judge_model: str
    reasoning: str | None
    judge_reasoning: str | None
    cutoffs: dict[str, Cutoff]
    chain_budget: int | None
    max_chain_steps: int | None
    tool_call_timeout: int | None
    grammar_fingerprint: str
    fixture_fingerprints: dict[str, str]
    commit: str
    census_commit: str
    image_ids: dict[str, str]
    targets: Sequence[HoldoutTargetResult]
    not_run: Sequence[NotRunTarget]
    refused_run_count: int
    refused_run_targets: Sequence[str]
    total_cost: float
    prices_as_of: date
