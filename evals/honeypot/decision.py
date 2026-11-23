from dataclasses import dataclass, field, replace

from evals.baseline import BaselineConditions, RescoredBaseline, rescore
from evals.declared_flips import apply_declarations
from evals.gate import Observation, compare, observe
from evals.gate_metrics import (
    DetectionCount,
    MetricDelta,
    count_detections,
    metric_deltas,
    metric_resolutions,
)
from evals.gate_outcome import GateInput, GateMode, GateResult, decide_gate
from evals.ground_truth import Cell
from evals.honeypot.retest import Retester
from evals.honeypot.session import GateBasis
from evals.honeypots import MERGED_GROUND_TRUTH, TOOL_COUNT
from evals.metrics import (
    ConsistencyDetail,
    HoneypotMetrics,
    RunDetail,
    VerdictMap,
    average_distribution_coverage,
    build_run_detail,
    compute_consistency,
    label_scores,
)
from evals.recording import Recording
from mcp_auditor.domain.models import AuditReport


@dataclass(frozen=True)
class CompletedRun:
    detail: RunDetail
    verdicts: VerdictMap
    report: AuditReport

    @classmethod
    def of(cls, index: int, verdicts: VerdictMap, report: AuditReport) -> "CompletedRun":
        return cls(build_run_detail(index, verdicts, report, MERGED_GROUND_TRUTH), verdicts, report)


@dataclass
class RunsOutcome:
    runs: list[CompletedRun] = field(default_factory=list[CompletedRun])

    @property
    def details(self) -> list[RunDetail]:
        return [run.detail for run in self.runs]

    @property
    def verdict_maps(self) -> list[VerdictMap]:
        return [run.verdicts for run in self.runs]

    @property
    def audits(self) -> list[tuple[int, AuditReport]]:
        return [(run.detail.run_index, run.report) for run in self.runs]

    def completed_all(self, requested: int) -> bool:
        return len(self.runs) >= requested

    def observations(self) -> list[dict[Cell, Observation]]:
        return [observe(verdicts, MERGED_GROUND_TRUTH) for verdicts in self.verdict_maps]

    def detections(self) -> DetectionCount:
        return count_detections(self.observations(), MERGED_GROUND_TRUTH)

    def metrics(self) -> HoneypotMetrics:
        return HoneypotMetrics(
            **label_scores(self.verdict_maps, MERGED_GROUND_TRUTH),
            consistency=compute_consistency(self.verdict_maps, MERGED_GROUND_TRUTH)[0],
            distribution_coverage=average_distribution_coverage(self.details),
        )

    def consistency_details(self) -> dict[str, ConsistencyDetail]:
        return compute_consistency(self.verdict_maps, MERGED_GROUND_TRUTH)[1]

    def recording(self, conditions: BaselineConditions, commit: str, recorded_at: str) -> Recording:
        return Recording(
            conditions=conditions,
            commit=commit,
            recorded_at=recorded_at,
            runs=self.observations(),
            metrics=self.metrics(),
            completed_all=self.completed_all(conditions.runs),
            ground_truth=MERGED_GROUND_TRUTH,
        )


async def decide_runs(basis: GateBasis, outcome: RunsOutcome, retester: Retester) -> GateResult:
    metrics = outcome.metrics()
    floors_input = GateInput(
        mode=basis.mode,
        metrics=metrics,
        detections=outcome.detections(),
        mismatches=_incomplete_runs(basis.requested_runs, outcome),
    )
    baseline = basis.baseline
    if baseline is None:
        return decide_gate(floors_input)

    compared = compare(baseline.observation_runs(), outcome.observations(), MERGED_GROUND_TRUTH)
    cells = apply_declarations(compared, basis.declared)
    mismatches = floors_input.mismatches
    if basis.mode == GateMode.PAIRED and not mismatches:
        cells, mismatches = await retester.retest_flips(cells, baseline.retest_rule)
    rescored = rescore(baseline, MERGED_GROUND_TRUTH)
    return decide_gate(
        replace(
            floors_input,
            baseline_status=baseline.status,
            cells=cells,
            mismatches=mismatches,
            deltas=_deltas(rescored, outcome, metrics),
            protected=rescored.protected,
            declared=basis.declared,
        )
    )


def _incomplete_runs(requested_runs: int, outcome: RunsOutcome) -> list[str]:
    if outcome.completed_all(requested_runs):
        return []
    return [f"{len(outcome.runs)} of {requested_runs} runs completed"]


def _deltas(
    rescored: RescoredBaseline, outcome: RunsOutcome, metrics: HoneypotMetrics
) -> dict[str, MetricDelta]:
    candidate = metrics.model_copy(update=label_scores(outcome.verdict_maps, rescored.ground_truth))
    resolutions = metric_resolutions(outcome.verdict_maps, rescored.ground_truth, TOOL_COUNT)
    return metric_deltas(rescored.metrics, candidate, resolutions)
