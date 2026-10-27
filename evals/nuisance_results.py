"""The result value objects of a nuisance run, defined here so the statistic, the report and the
orchestrator all import them without a cycle (the orchestrator imports the statistic and the
report, which both consume these). The per-run facts of a server live in its run statuses and the
aggregates are computed from them, so no two fields can disagree."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from evals.holdout_conditions import Cutoff


@dataclass(frozen=True)
class NuisanceRunStatus:
    flagged: bool
    split_flagged: bool  # flagged through a counted tool of the split flaw
    incomplete: bool  # a step refused or unreadable
    raw_fail_count: int  # report-only


@dataclass(frozen=True)
class NuisanceServerResult:
    server_package: str
    split_flaw: str | None  # None when the server leaves the split
    split_disclosure_date: date | None
    statuses: tuple[NuisanceRunStatus, ...]
    counted_tools_count: int
    tools_count: int
    run_cost: float  # dollars over its runs, incomplete runs included

    @property
    def runs(self) -> int:
        return len(self.statuses)

    @property
    def flagged_per_run(self) -> list[bool]:
        return [status.flagged for status in self.statuses]

    @property
    def flagged_runs(self) -> int:
        return sum(status.flagged for status in self.statuses)

    @property
    def flagged_share(self) -> float:
        return self.flagged_runs / self.runs

    @property
    def split_flagged_runs(self) -> int:
        return sum(status.split_flagged for status in self.statuses)

    @property
    def incomplete_runs(self) -> int:
        return sum(status.incomplete for status in self.statuses)

    @property
    def incomplete_unflagged_runs(self) -> int:
        return sum(status.incomplete and not status.flagged for status in self.statuses)

    @property
    def raw_fail_per_run(self) -> list[int]:
        return [status.raw_fail_count for status in self.statuses]


class NotRunCause(StrEnum):
    BENIGN_CALL_FAILED = "benign_call_failed"
    LAUNCH_FAILURE = "launch_failure"
    THROTTLED = "throttled"


# The reasons of a server dropped during the runs, one per cause, so the report counts them. A
# benign-call failure has none: its row carries the check's own reason.
DROPPED_RUN_REASONS = {
    NotRunCause.LAUNCH_FAILURE: "a run failed to launch after retries",
    NotRunCause.THROTTLED: "throttled by the model provider past every retry",
}


@dataclass(frozen=True)
class NotRunServer:
    server_package: str
    reason: str
    cause: NotRunCause


@dataclass(frozen=True)
class FigureExit:
    server_package: str
    reason: str


@dataclass(frozen=True)
class NuisanceRunResult:
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
    counter_fingerprint: str
    fixture_fingerprints: dict[str, str]
    commit: str
    census_commit: str
    image_ids: dict[str, str]
    recorded_at: str  # ISO timestamp: a model can change behind one identifier
    servers: Sequence[NuisanceServerResult]
    not_run: Sequence[NotRunServer]
    outside_figure: Sequence[FigureExit]
    incomplete_run_count: int
    total_cost: float
    prices_as_of: date
    concurrency: int
    throttled_requests: int
