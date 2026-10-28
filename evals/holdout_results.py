"""The result value objects of a holdout run, defined here so the statistic, the report and the
orchestrator all import them without a cycle (holdout_run imports the statistic and the report,
which both consume these, so they cannot live in holdout_run as the plan's prose placed them).
The per-run facts of a target live in its run statuses and the aggregates are computed from them,
so no two fields can disagree."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from evals.holdout_conditions import Cutoff


@dataclass(frozen=True)
class HoldoutRunStatus:
    detected: bool
    detected_if_unchecked_missed: bool
    surfaced_places: list[str]  # place ids only, empty on an incomplete run
    struck_places: list[str]  # the credits the replay refused, ids only
    unchecked_places: list[str]  # the credits the replay could not check, ids only
    aimed: bool
    fail_without_proof: bool
    incomplete: bool


@dataclass(frozen=True)
class HoldoutTargetResult:
    cve_id: str
    disclosure_date: date
    mechanism_label: str | None
    tools_count: int
    ran_in_fallback: bool
    statuses: tuple[HoldoutRunStatus, ...]
    run_cost: float  # dollars over its runs, incomplete runs included

    @property
    def runs(self) -> int:
        return len(self.statuses)

    @property
    def detected_runs(self) -> int:
        return sum(status.detected for status in self.statuses)

    @property
    def detection_share(self) -> float:
        return self.detected_runs / self.runs

    @property
    def detected_runs_if_unchecked_missed(self) -> int:
        return sum(status.detected_if_unchecked_missed for status in self.statuses)

    @property
    def surfaced_places(self) -> list[list[str]]:
        return [status.surfaced_places for status in self.statuses]

    @property
    def struck_places(self) -> list[list[str]]:
        return [status.struck_places for status in self.statuses]

    @property
    def unchecked_places(self) -> list[list[str]]:
        return [status.unchecked_places for status in self.statuses]

    @property
    def aimed_runs(self) -> int:
        return sum(status.aimed for status in self.statuses)

    @property
    def fail_without_proof_runs(self) -> int:
        return sum(status.fail_without_proof for status in self.statuses)

    @property
    def incomplete_runs(self) -> int:
        return sum(status.incomplete for status in self.statuses)


class NotRunCause(StrEnum):
    PRE_RUN_CHECK = "pre_run_check"
    LAUNCH_FAILURE = "launch_failure"
    THROTTLED = "throttled"


# The reasons of a target dropped during the run, one per cause, so the report counts them.
DROPPED_RUN_REASONS = {
    NotRunCause.LAUNCH_FAILURE: "a run failed to launch after retries",
    NotRunCause.THROTTLED: "throttled by the model provider past every retry",
}


@dataclass(frozen=True)
class NotRunTarget:
    cve_id: str
    reason: str
    cause: NotRunCause


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
    recorded_at: str  # ISO timestamp: a model can change behind one identifier
    targets: Sequence[HoldoutTargetResult]
    not_run: Sequence[NotRunTarget]
    incomplete_run_count: int
    total_cost: float
    prices_as_of: date
    concurrency: int
    throttled_requests: int
