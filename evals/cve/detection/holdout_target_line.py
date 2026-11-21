"""The holdout report's per-target line and its per-run lines: place ids and counts only, never
evidence, judge input or a per-case verdict. The server health counts, the replay causes and the
missed-call causes are report-only: no statistic, grading or retry reads them."""

from datetime import date

from pydantic import BaseModel

from evals.cve.detection.holdout_results import DetectionHoldoutRunStatus, HoldoutTargetResult


class TargetRunLine(BaseModel):
    detected: bool
    detected_if_unchecked_missed: bool
    aimed: bool
    fail_without_proof: bool
    incomplete: bool
    non_protocol_lines: int
    lost_connection_responses: int
    relaunches: int
    unsent_calls: int
    cut_responses: int
    unchecked_reason: str | None
    replay_attempt_failures: list[str]
    missed_call_causes: list[str]

    @classmethod
    def of(cls, status: DetectionHoldoutRunStatus) -> "TargetRunLine":
        return cls(
            detected=status.detected,
            detected_if_unchecked_missed=status.detected_if_unchecked_missed,
            aimed=status.aimed,
            fail_without_proof=status.fail_without_proof,
            incomplete=status.incomplete,
            non_protocol_lines=status.non_protocol_lines,
            lost_connection_responses=status.lost_connection_responses,
            relaunches=status.relaunches,
            unsent_calls=status.unsent_calls,
            cut_responses=status.cut_responses,
            unchecked_reason=status.unchecked_reason,
            replay_attempt_failures=status.replay_attempt_failures,
            missed_call_causes=status.missed_call_causes,
        )


class TargetLine(BaseModel):
    flaw_id: str
    disclosure_date: date  # with per_run, lets a stored report recompute the statistic and split
    class_labels: list[str]
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
    relaunches: int
    unsent_calls: int
    cut_responses: int
    unchecked_runs_by_reason: dict[str, int]
    replay_attempt_failures_by_cause: dict[str, int]
    incomplete_runs_by_cause: dict[str, int]
    per_run: list[TargetRunLine]

    @classmethod
    def of(cls, target: HoldoutTargetResult) -> "TargetLine":
        return cls(
            flaw_id=target.flaw_id,
            disclosure_date=target.disclosure_date,
            class_labels=list(target.class_labels),
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
            relaunches=target.relaunches,
            unsent_calls=target.unsent_calls,
            cut_responses=target.cut_responses,
            unchecked_runs_by_reason=target.unchecked_runs_by_reason,
            replay_attempt_failures_by_cause=target.replay_attempt_failures_by_cause,
            incomplete_runs_by_cause=target.incomplete_runs_by_cause,
            per_run=[TargetRunLine.of(status) for status in target.statuses],
        )
