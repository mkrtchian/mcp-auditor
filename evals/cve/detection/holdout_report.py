"""The holdout report model. It holds only the aggregated numbers and the proof-free per-target
lines (place ids and counts), never evidence, judge input or a per-case verdict, so a detection
holdout run cannot write proof text even by mistake."""

from collections import Counter
from datetime import date

from pydantic import BaseModel

from evals.cve.detection.holdout_not_run import NotRunLine
from evals.cve.detection.holdout_results import DetectionHoldoutRunResult
from evals.cve.detection.holdout_target_line import TargetLine
from evals.cve.holdout_hierarchical import DEFAULT_GRID, Grid
from evals.cve.holdout_report_lines import (
    ConclusionLine,
    CutoffModel,
    IntervalModel,
    RunCutoffModel,
    two_sides,
)
from evals.cve.holdout_statistic import (
    Conclusion,
    Side,
    SideStatistic,
    check_conclusion,
    cited_interval,
    detection_rate_controls,
    holdout_detection_rate,
    split_by_side,
)


class SideLine(BaseModel):
    side: Side
    number: float
    interval: IntervalModel
    targets: int


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


def build_report(run: DetectionHoldoutRunResult, *, grid: Grid = DEFAULT_GRID) -> HoldoutReport:
    cutoff = RunCutoffModel.latest(run.cutoffs)
    split = split_by_side(run.targets, cutoff.date)
    pair = two_sides(split)
    conclusion = None if pair is None else check_conclusion(*pair, run.runs, grid=grid)
    return HoldoutReport(
        holdout_detection_rate=holdout_detection_rate(run.targets),
        cited_interval=IntervalModel.of(cited_interval(run.targets)),
        controls={
            name: IntervalModel.of(interval)
            for name, interval in detection_rate_controls(run.targets, run.runs, grid=grid).items()
        },
        run_cutoff=cutoff,
        sides=[_side_line(side) for side in split.values()],
        contrast=_contrast_line(conclusion),
        conclusion=_conclusion_line(conclusion),
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


def _contrast_line(conclusion: Conclusion | None) -> IntervalModel | None:
    # The contrast is the cited Newcombe interval of the conclusion check (detection suite rule,
    # Run conditions and statistic).
    return None if conclusion is None else IntervalModel.of(conclusion.cited.interval)


def _conclusion_line(conclusion: Conclusion | None) -> ConclusionLine | None:
    return None if conclusion is None else ConclusionLine.of(conclusion)


def _side_line(side: SideStatistic) -> SideLine:
    return SideLine(
        side=side.side,
        number=side.number,
        interval=IntervalModel.of(side.interval),
        targets=side.targets,
    )
