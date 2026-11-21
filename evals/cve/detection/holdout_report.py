"""The holdout report model. It holds only the aggregated numbers and the proof-free per-target
lines (place ids and counts), never evidence, judge input or a per-case verdict, so a detection
holdout run cannot write proof text even by mistake."""

from collections import Counter
from collections.abc import Mapping
from datetime import date

from pydantic import BaseModel

from evals.cve.detection.holdout_not_run import NotRunLine
from evals.cve.detection.holdout_results import DetectionHoldoutRunResult
from evals.cve.detection.holdout_target_line import TargetLine
from evals.cve.holdout_conditions import Cutoff
from evals.cve.holdout_intervals import Interval
from evals.cve.holdout_statistic import (
    MethodPlacement,
    Side,
    SideStatistic,
    check_conclusion,
    cited_interval,
    contrast,
    detection_rate_controls,
    holdout_detection_rate,
    split_by_side,
)


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


class SideLine(BaseModel):
    side: Side
    number: float
    interval: IntervalModel
    targets: int


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


class HoldoutReport(BaseModel):
    holdout_detection_rate: float
    cited_interval: IntervalModel
    controls: dict[str, IntervalModel]
    run_cutoff: RunCutoffModel
    sides: list[SideLine]
    contrast: IntervalModel | None
    conclusion: ConclusionLine | None
    ladder: dict[int, int]  # detected-run count -> number of targets reaching it
    targets: list[TargetLine]
    not_run: list[NotRunLine]
    second_pass: list[str]
    incomplete_run_count: int
    incomplete_runs_by_cause: dict[str, int]  # a run missing model calls of two causes counts twice
    total_cost: float
    prices_as_of: date
    commit: str
    census_commit: str
    recorded_at: str  # ISO timestamp: a model can change behind one identifier
    # The run conditions and provenance, so a reader can tell two runs apart
    # (detection-suite-rule.md, Run conditions and statistic).
    provider: str
    model: str
    judge_model: str
    reasoning: str | None
    judge_reasoning: str | None
    runs: int
    budget: int
    cutoffs: dict[str, CutoffModel]
    chain_budget: int | None
    max_chain_steps: int | None
    tool_call_timeout: int | None
    grammar_fingerprint: str
    fixture_fingerprints: dict[str, str]
    image_ids: dict[str, str]
    concurrency: int
    throttled_requests: int


def build_report(run: DetectionHoldoutRunResult) -> HoldoutReport:
    model, cutoff = run_cutoff(run.cutoffs)
    split = split_by_side(run.targets, cutoff.date)
    pair = _two_sides(split)
    return HoldoutReport(
        holdout_detection_rate=holdout_detection_rate(run.targets),
        cited_interval=IntervalModel.of(cited_interval(run.targets)),
        controls={
            name: IntervalModel.of(interval)
            for name, interval in detection_rate_controls(run.targets, run.runs).items()
        },
        run_cutoff=RunCutoffModel(
            model=model,
            date=cutoff.date,
            type=cutoff.type,
            source=cutoff.source,
            note=cutoff.note,
        ),
        sides=[_side_line(side) for side in split.values()],
        contrast=_contrast_line(pair),
        conclusion=_conclusion_line(pair, run.runs),
        ladder=dict(Counter(target.detected_runs for target in run.targets)),
        targets=[TargetLine.of(target) for target in run.targets],
        not_run=[NotRunLine.of(target) for target in run.not_run],
        second_pass=list(run.second_pass),
        incomplete_run_count=run.incomplete_run_count,
        incomplete_runs_by_cause=dict(
            Counter(
                cause
                for target in run.targets
                for status in target.statuses
                for cause in status.missed_call_causes
            )
        ),
        total_cost=run.total_cost,
        prices_as_of=run.prices_as_of,
        commit=run.commit,
        census_commit=run.census_commit,
        recorded_at=run.recorded_at,
        provider=run.provider,
        model=run.model,
        judge_model=run.judge_model,
        reasoning=run.reasoning,
        judge_reasoning=run.judge_reasoning,
        runs=run.runs,
        budget=run.budget,
        cutoffs={model: CutoffModel.of(cutoff) for model, cutoff in run.cutoffs.items()},
        chain_budget=run.chain_budget,
        max_chain_steps=run.max_chain_steps,
        tool_call_timeout=run.tool_call_timeout,
        grammar_fingerprint=run.grammar_fingerprint,
        fixture_fingerprints=run.fixture_fingerprints,
        image_ids=run.image_ids,
        concurrency=run.concurrency,
        throttled_requests=run.throttled_requests,
    )


def run_cutoff(cutoffs: Mapping[str, Cutoff]) -> tuple[str, Cutoff]:
    # max keeps the first on a tie, so the generator is named when it shares the judge's date.
    return max(cutoffs.items(), key=lambda item: item[1].date)


def _two_sides(split: dict[Side, SideStatistic]) -> tuple[SideStatistic, SideStatistic] | None:
    if Side.PRE_CUTOFF in split and Side.POST_CUTOFF in split:
        return split[Side.PRE_CUTOFF], split[Side.POST_CUTOFF]
    return None


def _contrast_line(pair: tuple[SideStatistic, SideStatistic] | None) -> IntervalModel | None:
    if pair is None:
        return None
    result = contrast(*pair)
    return None if result is None else IntervalModel.of(result.interval)


def _conclusion_line(
    pair: tuple[SideStatistic, SideStatistic] | None, runs: int
) -> ConclusionLine | None:
    if pair is None:
        return None
    conclusion = check_conclusion(*pair, runs)
    if conclusion is None:
        return None
    return ConclusionLine(
        placement=None if conclusion.placement is None else conclusion.placement.value,
        inconclusive=conclusion.inconclusive,
        cited=MethodLine.of(conclusion.cited),
        disagreeing=[MethodLine.of(method) for method in conclusion.disagreeing],
    )


def _side_line(side: SideStatistic) -> SideLine:
    return SideLine(
        side=side.side,
        number=side.number,
        interval=IntervalModel.of(side.interval),
        targets=side.targets,
    )
