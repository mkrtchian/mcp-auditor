"""The holdout report model and its markdown. The model holds only the aggregated numbers and
the proof-free per-target lines (place ids and counts), never evidence, judge input or a per-case
verdict, so a holdout run cannot write proof text even by mistake."""

from collections import Counter
from datetime import date

from pydantic import BaseModel

from evals.census_draw import Side
from evals.holdout_conditions import Cutoff
from evals.holdout_intervals import Interval
from evals.holdout_not_run import NotRunLine, not_run_section
from evals.holdout_results import HoldoutRunResult, HoldoutTargetResult
from evals.holdout_statistic import (
    MethodPlacement,
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


class TargetLine(BaseModel):
    cve_id: str
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


class CutoffModel(BaseModel):
    date: date
    type: str | None
    note: str | None

    @classmethod
    def of(cls, cutoff: Cutoff) -> "CutoffModel":
        return cls(date=cutoff.date, type=cutoff.type, note=cutoff.note)


class HoldoutReport(BaseModel):
    primary_number: float
    cited_interval: IntervalModel
    controls: dict[str, IntervalModel]
    sides: list[SideLine]
    contrast: IntervalModel | None
    conclusion: ConclusionLine | None
    ladder: dict[int, int]  # detected-run count -> number of targets reaching it
    targets: list[TargetLine]
    not_run: list[NotRunLine]
    incomplete_run_count: int
    total_cost: float
    prices_as_of: date
    commit: str
    census_commit: str
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


def build_report(run: HoldoutRunResult, run_cutoff: date) -> HoldoutReport:
    split = split_by_side(run.targets, run_cutoff)
    pair = _two_sides(split)
    return HoldoutReport(
        primary_number=primary_number(run.targets),
        cited_interval=IntervalModel.of(cited_interval(run.targets)),
        controls={
            name: IntervalModel.of(interval)
            for name, interval in primary_controls(run.targets, run.runs).items()
        },
        sides=[_side_line(side) for side in split.values()],
        contrast=_contrast_line(pair),
        conclusion=_conclusion_line(pair, run.runs),
        ladder=dict(Counter(target.detected_runs for target in run.targets)),
        targets=[_target_line(target) for target in run.targets],
        not_run=[NotRunLine.of(target) for target in run.not_run],
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
        cutoffs={model: CutoffModel.of(cutoff) for model, cutoff in run.cutoffs.items()},
        chain_budget=run.chain_budget,
        max_chain_steps=run.max_chain_steps,
        tool_call_timeout=run.tool_call_timeout,
        grammar_fingerprint=run.grammar_fingerprint,
        fixture_fingerprints=run.fixture_fingerprints,
        image_ids=run.image_ids,
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
        cited=_method_line(verdict.cited),
        disagreeing=[_method_line(method) for method in verdict.disagreeing],
    )


def _method_line(method: MethodPlacement) -> MethodLine:
    return MethodLine(
        method=method.method,
        interval=IntervalModel.of(method.interval),
        placement=method.placement.value,
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
    )


def render_markdown(report: HoldoutReport) -> str:
    return "\n".join(
        [
            "# Holdout capability",
            "",
            f"Capability: {report.primary_number:.3f} (95% Wilson {_span(report.cited_interval)})",
            "",
            *_ladder_section(report),
            *_split_section(report),
            *_controls_section(report),
            *not_run_section(report.not_run, len(report.targets)),
            _incomplete_runs_line(report),
            f"Total cost: ${report.total_cost:.2f}",
        ]
    )


def _ladder_section(report: HoldoutReport) -> list[str]:
    lines = [
        f"- {detected} detecting run(s): {count} target(s)"
        for detected, count in sorted(report.ladder.items(), reverse=True)
    ]
    return ["## Ladder", *lines, ""]


def _split_section(report: HoldoutReport) -> list[str]:
    lines = [
        f"- {line.side.value}: {line.number:.3f} ({_span(line.interval)}), {line.targets} target(s)"
        for line in report.sides
    ]
    if report.contrast is None:
        lines.append("- contrast: not computed (a side has fewer than 5 targets)")
    else:
        lines.append(f"- contrast: {_span(report.contrast)}")
        lines.append(f"- conclusion: {_conclusion_text(report.conclusion)}")
    return ["## Split by cutoff side", *lines, ""]


def _conclusion_text(conclusion: ConclusionLine | None) -> str:
    if conclusion is None:
        return "none"
    if conclusion.inconclusive:
        methods = ", ".join(method.method for method in conclusion.disagreeing)
        return f"inconclusive (disagreeing: {methods})"
    return f"{conclusion.placement} zero"


def _controls_section(report: HoldoutReport) -> list[str]:
    lines = [f"- {name}: {_span(interval)}" for name, interval in sorted(report.controls.items())]
    return ["## Controls", *lines, ""]


_INCOMPLETE_RUNS = "Incomplete runs (a step refused or unreadable)"


def _incomplete_runs_line(report: HoldoutReport) -> str:
    """The count with the targets it touches (holdout-rule.md:249), derived from the per-target
    incomplete-run counts."""
    touched = [target.cve_id for target in report.targets if target.incomplete_runs > 0]
    if not touched:
        return f"{_INCOMPLETE_RUNS}: {report.incomplete_run_count}"
    return f"{_INCOMPLETE_RUNS}: {report.incomplete_run_count} ({', '.join(touched)})"


def _span(interval: IntervalModel) -> str:
    return f"{interval.low:.3f} to {interval.high:.3f}"
