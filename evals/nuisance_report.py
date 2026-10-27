"""The nuisance report model. It holds only the aggregated numbers and the proof-free per-server
lines (statuses and counts), never evidence, judge input or a per-case verdict, so a nuisance run
cannot write proof text even by mistake."""

from datetime import date

from pydantic import BaseModel

from evals.holdout_report import (
    ConclusionLine,
    CutoffModel,
    IntervalModel,
    MethodLine,
    RunCutoffModel,
    run_cutoff,
)
from evals.holdout_statistic import Side
from evals.nuisance_results import (
    FigureExit,
    NotRunCause,
    NotRunServer,
    NuisanceRunResult,
    NuisanceServerResult,
)
from evals.nuisance_statistic import (
    SideStatistic,
    check_conclusion,
    cited_interval,
    contrast,
    figure,
    primary_controls,
    split_by_side,
)


class SideLine(BaseModel):
    side: Side
    number: float
    interval: IntervalModel
    servers: int


class ServerLine(BaseModel):
    server_package: str
    flagged_share: float
    flagged_per_run: list[bool]
    incomplete_runs: int
    counted_tools_count: int
    tools_count: int
    raw_fail_per_run: list[int]  # report-only, never compared
    cost: float


class NotRunLine(BaseModel):
    server_package: str
    reason: str
    cause: NotRunCause

    @classmethod
    def of(cls, server: NotRunServer) -> "NotRunLine":
        return cls(server_package=server.server_package, reason=server.reason, cause=server.cause)


class FigureExitLine(BaseModel):
    server_package: str
    reason: str

    @classmethod
    def of(cls, exit_row: FigureExit) -> "FigureExitLine":
        return cls(server_package=exit_row.server_package, reason=exit_row.reason)


class NuisanceReport(BaseModel):
    figure: float
    cited_interval: IntervalModel
    controls: dict[str, IntervalModel]
    run_cutoff: RunCutoffModel
    sides: list[SideLine]
    contrast: IntervalModel | None
    conclusion: ConclusionLine | None
    servers: list[ServerLine]
    not_run: list[NotRunLine]
    outside_figure: list[FigureExitLine]
    incomplete_run_count: int
    total_cost: float
    prices_as_of: date
    commit: str
    census_commit: str
    # The run conditions and provenance, so a reader can tell two runs apart.
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
    counter_fingerprint: str
    fixture_fingerprints: dict[str, str]
    image_ids: dict[str, str]
    recorded_at: str
    concurrency: int
    throttled_requests: int


def build_report(run: NuisanceRunResult) -> NuisanceReport:
    model, cutoff = run_cutoff(run.cutoffs)
    split = split_by_side(run.servers, cutoff.date)
    pair = _two_sides(split)
    return NuisanceReport(
        figure=figure(run.servers),
        cited_interval=IntervalModel.of(cited_interval(run.servers)),
        controls={
            name: IntervalModel.of(interval)
            for name, interval in primary_controls(run.servers, run.runs).items()
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
        servers=[_server_line(server) for server in run.servers],
        not_run=[NotRunLine.of(server) for server in run.not_run],
        outside_figure=[FigureExitLine.of(exit_row) for exit_row in run.outside_figure],
        incomplete_run_count=run.incomplete_run_count,
        total_cost=run.total_cost,
        prices_as_of=run.prices_as_of,
        commit=run.commit,
        census_commit=run.census_commit,
        provider=run.provider,
        model=run.model,
        judge_model=run.judge_model,
        reasoning=run.reasoning,
        judge_reasoning=run.judge_reasoning,
        runs=run.runs,
        budget=run.budget,
        cutoffs={name: CutoffModel.of(cutoff) for name, cutoff in run.cutoffs.items()},
        chain_budget=run.chain_budget,
        max_chain_steps=run.max_chain_steps,
        tool_call_timeout=run.tool_call_timeout,
        grammar_fingerprint=run.grammar_fingerprint,
        counter_fingerprint=run.counter_fingerprint,
        fixture_fingerprints=run.fixture_fingerprints,
        image_ids=run.image_ids,
        recorded_at=run.recorded_at,
        concurrency=run.concurrency,
        throttled_requests=run.throttled_requests,
    )


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
        servers=side.servers,
    )


def _server_line(server: NuisanceServerResult) -> ServerLine:
    return ServerLine(
        server_package=server.server_package,
        flagged_share=server.flagged_share,
        flagged_per_run=server.flagged_per_run,
        incomplete_runs=server.incomplete_runs,
        counted_tools_count=server.counted_tools_count,
        tools_count=server.tools_count,
        raw_fail_per_run=server.raw_fail_per_run,
        cost=server.run_cost,
    )
