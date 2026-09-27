from dataclasses import dataclass, field

from evals.baseline import RescoredBaseline, rescore
from evals.eval_session import EvalSession
from evals.gate import (
    Cell,
    DetectionCount,
    MetricDelta,
    Observation,
    ProtectedCells,
    compare,
    count_detections,
    metric_deltas,
    metric_resolutions,
    observe,
    protected_cells,
)
from evals.gate_verdict import GateInput, GateMode, GateResult, judge_gate
from evals.honeypots import MERGED_GROUND_TRUTH, TOOL_COUNT
from evals.metrics import (
    ConsistencyDetail,
    EvalMetrics,
    RunDetail,
    VerdictMap,
    average_distribution_coverage,
    compute_consistency,
    label_scores,
)
from evals.replay import Replayer
from mcp_auditor.domain.models import AuditReport


@dataclass
class RunsOutcome:
    details: list[RunDetail] = field(default_factory=list[RunDetail])
    verdict_maps: list[VerdictMap] = field(default_factory=list[VerdictMap])
    audits: list[tuple[int, AuditReport]] = field(default_factory=list[tuple[int, AuditReport]])

    def completed_all(self, requested: int) -> bool:
        return len(self.details) >= requested

    def observations(self) -> list[dict[Cell, Observation]]:
        return [observe(verdicts, MERGED_GROUND_TRUTH) for verdicts in self.verdict_maps]

    def detections(self) -> DetectionCount:
        return count_detections(self.observations(), MERGED_GROUND_TRUTH)

    def protected(self) -> ProtectedCells:
        return protected_cells(self.observations(), MERGED_GROUND_TRUTH)

    def metrics(self) -> tuple[EvalMetrics, dict[str, ConsistencyDetail]]:
        consistency, consistency_details = compute_consistency(
            self.verdict_maps, MERGED_GROUND_TRUTH
        )
        metrics = EvalMetrics(
            recall=sum(run.recall for run in self.details) / len(self.details),
            precision=sum(run.precision for run in self.details) / len(self.details),
            consistency=consistency,
            distribution_coverage=average_distribution_coverage(self.details),
        )
        return metrics, consistency_details


async def judge_runs(session: EvalSession, outcome: RunsOutcome, replayer: Replayer) -> GateResult:
    metrics, _ = outcome.metrics()
    mismatches = _incomplete_runs(session, outcome)
    baseline = session.baseline
    if baseline is None:
        return judge_gate(
            GateInput(
                mode=session.mode,
                metrics=metrics,
                detections=outcome.detections(),
                mismatches=mismatches,
            )
        )

    rescored = rescore(baseline, MERGED_GROUND_TRUTH)
    cells = compare(baseline.observation_runs(), outcome.observations(), MERGED_GROUND_TRUTH)
    if session.mode == GateMode.PAIRED and not mismatches:
        cells, mismatches = await replayer.settle_flips(cells, baseline.replay_rule)
    return judge_gate(
        GateInput(
            mode=session.mode,
            metrics=metrics,
            detections=outcome.detections(),
            baseline_status=baseline.status,
            cells=cells,
            mismatches=mismatches,
            deltas=_deltas(rescored, outcome, metrics),
            protected=rescored.protected,
        )
    )


def _incomplete_runs(session: EvalSession, outcome: RunsOutcome) -> list[str]:
    requested = session.conditions.runs
    if outcome.completed_all(requested):
        return []
    return [f"{len(outcome.details)} of {requested} runs completed"]


def _deltas(
    rescored: RescoredBaseline, outcome: RunsOutcome, metrics: EvalMetrics
) -> dict[str, MetricDelta]:
    candidate = metrics.model_copy(update=label_scores(outcome.verdict_maps, rescored.ground_truth))
    resolutions = metric_resolutions(outcome.verdict_maps, rescored.ground_truth, TOOL_COUNT)
    return metric_deltas(rescored.metrics, candidate, resolutions)
