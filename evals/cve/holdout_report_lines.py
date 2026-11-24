"""The report lines both holdout reports share, and how they read in markdown. The two holdout
rates are published side by side, so their interval, run cutoff, conclusion, incomplete-run and
health lines read the same."""

from collections.abc import Mapping, Sequence
from datetime import date
from typing import Protocol

from pydantic import BaseModel

from evals.cve.holdout_conditions import Cutoff
from evals.cve.holdout_intervals import Interval
from evals.cve.holdout_statistic import Conclusion, MethodPlacement, Side


class IntervalModel(BaseModel):
    low: float
    high: float

    @classmethod
    def of(cls, interval: Interval) -> "IntervalModel":
        return cls(low=interval.low, high=interval.high)


class MethodLine(BaseModel):
    method: str
    interval: IntervalModel
    placement: str

    @classmethod
    def of(cls, method: MethodPlacement) -> "MethodLine":
        return cls(
            method=method.method,
            interval=IntervalModel.of(method.interval),
            placement=method.placement.value,
        )


class ConclusionLine(BaseModel):
    placement: str | None
    inconclusive: bool
    cited: MethodLine
    disagreeing: list[MethodLine]

    @classmethod
    def of(cls, conclusion: Conclusion) -> "ConclusionLine":
        return cls(
            placement=None if conclusion.placement is None else conclusion.placement.value,
            inconclusive=conclusion.inconclusive,
            cited=MethodLine.of(conclusion.cited),
            disagreeing=[MethodLine.of(method) for method in conclusion.disagreeing],
        )


class CutoffModel(BaseModel):
    date: date
    type: str | None
    source: str | None
    note: str | None

    @classmethod
    def of(cls, cutoff: Cutoff) -> "CutoffModel":
        return cls(date=cutoff.date, type=cutoff.type, source=cutoff.source, note=cutoff.note)


class RunCutoffModel(BaseModel):
    model: str
    date: date
    type: str | None
    source: str | None
    note: str | None

    @classmethod
    def latest(cls, cutoffs: Mapping[str, Cutoff]) -> "RunCutoffModel":
        # max keeps the first on a tie, so the generator is named when it shares the judge's date.
        model, cutoff = max(cutoffs.items(), key=lambda item: item[1].date)
        return cls(
            model=model,
            date=cutoff.date,
            type=cutoff.type,
            source=cutoff.source,
            note=cutoff.note,
        )


class HealthCounts(Protocol):
    @property
    def non_protocol_lines(self) -> int: ...

    @property
    def lost_connection_responses(self) -> int: ...

    @property
    def relaunches(self) -> int: ...

    @property
    def unsent_calls(self) -> int: ...

    @property
    def cut_responses(self) -> int: ...


def two_sides[S](split: Mapping[Side, S]) -> tuple[S, S] | None:
    if Side.PRE_CUTOFF in split and Side.POST_CUTOFF in split:
        return split[Side.PRE_CUTOFF], split[Side.POST_CUTOFF]
    return None


def run_cutoff_line(cutoff: RunCutoffModel) -> str:
    line = f"- run cutoff: {cutoff.date} ({cutoff.type}), {cutoff.model}, {cutoff.source}"
    return line if cutoff.note is None else f"{line}, note: {cutoff.note}"


def conclusion_text(conclusion: ConclusionLine | None) -> str:
    if conclusion is None:
        return "none"
    if conclusion.inconclusive:
        methods = ", ".join(method.method for method in conclusion.disagreeing)
        return f"inconclusive (disagreeing: {methods})"
    return f"{conclusion.placement} zero"


def controls_section(controls: Mapping[str, IntervalModel]) -> list[str]:
    lines = [f"- {name}: {span(interval)}" for name, interval in sorted(controls.items())]
    return ["## Controls", *lines, ""]


def span(interval: IntervalModel) -> str:
    return f"{interval.low:.3f} to {interval.high:.3f}"


INCOMPLETE_RUNS = "Incomplete runs (a model call missed: refused, unreadable or too long)"


def incomplete_runs_lines(
    count: int, touched: Sequence[str], by_cause: Mapping[str, int]
) -> list[str]:
    """The count with the members it touches (detection-suite-rule.md, Run conditions and statistic
    (An audit with a model call refused by the model provider)), then one line per cause."""
    count_line = f"{INCOMPLETE_RUNS}: {count}"
    cause_lines = [f"- {cause}: {runs} run(s)" for cause, runs in sorted(by_cause.items())]
    return [f"{count_line} ({', '.join(touched)})" if touched else count_line, *cause_lines]


def health_facts(counts: HealthCounts) -> list[str]:
    facts: list[str] = []
    if counts.non_protocol_lines:
        facts.append(f"non-protocol lines {counts.non_protocol_lines}")
    if counts.lost_connection_responses:
        facts.append(f"connection lost on {counts.lost_connection_responses} call(s)")
    if counts.relaunches:
        facts.append(f"relaunched {counts.relaunches} time(s)")
    if counts.unsent_calls:
        facts.append(f"{counts.unsent_calls} call(s) not sent")
    if counts.cut_responses:
        facts.append(f"{counts.cut_responses} response(s) shown cut")
    return facts
