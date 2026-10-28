"""The holdout report model. It holds only the aggregated numbers and the proof-free per-target
lines (place ids and counts), never evidence, judge input or a per-case verdict, so a holdout run
cannot write proof text even by mistake."""

from collections import Counter
from collections.abc import Mapping
from datetime import date

from pydantic import BaseModel

from evals.holdout_conditions import Cutoff
from evals.holdout_intervals import Interval
from evals.holdout_not_run import NotRunLine
from evals.holdout_results import HoldoutRunResult, HoldoutRunStatus, HoldoutTargetResult
from evals.holdout_statistic import (
    MethodPlacement,
    Side,
    SideStatistic,
    check_conclusion,
    cited_interval,
    contrast,
    primary_controls,
    primary_number,
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


class TargetRunLine(BaseModel):
    detected: bool
    detected_if_unchecked_missed: bool
    aimed: bool
    fail_without_proof: bool
    incomplete: bool
    non_protocol_lines: int
    lost_connection_responses: int
    unchecked_reason: str | None
    replay_attempt_failures: list[str]
    miss_causes: list[str]


class TargetLine(BaseModel):
    cve_id: str
    disclosure_date: date  # with per_run, lets a stored report recompute the statistic and split
    mechanism_label: str | None
    detection_share: float
    surfaced_places: list[list[str]]
    struck_places: list[list[str]]
    unchecked_places: list[list[str]]
    aimed_runs: int
    fail_without_proof_runs: int
    incomplete_runs: int
    ran_in_fallback: bool
    tools_count: int
    cost: float
    non_protocol_lines: int
    lost_connection_responses: int
    unchecked_runs_by_reason: dict[str, int]
    replay_attempt_failures_by_cause: dict[str, int]
    incomplete_runs_by_cause: dict[str, int]
    per_run: list[TargetRunLine]


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
    primary_number: float
    cited_interval: IntervalModel
    controls: dict[str, IntervalModel]
    run_cutoff: RunCutoffModel
    sides: list[SideLine]
    contrast: IntervalModel | None
    conclusion: ConclusionLine | None
    ladder: dict[int, int]  # detected-run count -> number of targets reaching it
    targets: list[TargetLine]
    not_run: list[NotRunLine]
    incomplete_run_count: int
    incomplete_runs_by_cause: dict[str, int]  # a run missing steps of two causes counts twice
    total_cost: float
    prices_as_of: date
    commit: str
    census_commit: str
    recorded_at: str  # ISO timestamp: a model can change behind one identifier
    # The run conditions and provenance, so a reader can tell two runs apart (holdout-rule.md:247).
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


def build_report(run: HoldoutRunResult) -> HoldoutReport:
    model, cutoff = run_cutoff(run.cutoffs)
    split = split_by_side(run.targets, cutoff.date)
    pair = _two_sides(split)
    return HoldoutReport(
        primary_number=primary_number(run.targets),
        cited_interval=IntervalModel.of(cited_interval(run.targets)),
        controls={
            name: IntervalModel.of(interval)
            for name, interval in primary_controls(run.targets, run.runs).items()
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
        targets=[_target_line(target) for target in run.targets],
        not_run=[NotRunLine.of(target) for target in run.not_run],
        incomplete_run_count=run.incomplete_run_count,
        incomplete_runs_by_cause=dict(
            Counter(
                cause
                for target in run.targets
                for status in target.statuses
                for cause in status.miss_causes
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
    verdict = check_conclusion(*pair, runs)
    if verdict is None:
        return None
    return ConclusionLine(
        placement=None if verdict.placement is None else verdict.placement.value,
        inconclusive=verdict.inconclusive,
        cited=MethodLine.of(verdict.cited),
        disagreeing=[MethodLine.of(method) for method in verdict.disagreeing],
    )


def _side_line(side: SideStatistic) -> SideLine:
    return SideLine(
        side=side.side,
        number=side.number,
        interval=IntervalModel.of(side.interval),
        targets=side.targets,
    )


def _target_line(target: HoldoutTargetResult) -> TargetLine:
    return TargetLine(
        cve_id=target.cve_id,
        disclosure_date=target.disclosure_date,
        mechanism_label=target.mechanism_label,
        detection_share=target.detection_share,
        surfaced_places=target.surfaced_places,
        struck_places=target.struck_places,
        unchecked_places=target.unchecked_places,
        aimed_runs=target.aimed_runs,
        fail_without_proof_runs=target.fail_without_proof_runs,
        incomplete_runs=target.incomplete_runs,
        ran_in_fallback=target.ran_in_fallback,
        tools_count=target.tools_count,
        cost=target.run_cost,
        non_protocol_lines=target.non_protocol_lines,
        lost_connection_responses=target.lost_connection_responses,
        unchecked_runs_by_reason=target.unchecked_runs_by_reason,
        replay_attempt_failures_by_cause=target.replay_attempt_failures_by_cause,
        incomplete_runs_by_cause=target.incomplete_runs_by_cause,
        per_run=[_run_line(status) for status in target.statuses],
    )


def _run_line(status: HoldoutRunStatus) -> TargetRunLine:
    return TargetRunLine(
        detected=status.detected,
        detected_if_unchecked_missed=status.detected_if_unchecked_missed,
        aimed=status.aimed,
        fail_without_proof=status.fail_without_proof,
        incomplete=status.incomplete,
        non_protocol_lines=status.non_protocol_lines,
        lost_connection_responses=status.lost_connection_responses,
        unchecked_reason=status.unchecked_reason,
        replay_attempt_failures=status.replay_attempt_failures,
        miss_causes=status.miss_causes,
    )
