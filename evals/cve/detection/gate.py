"""The detection gate (ADR 024): a target detected in every run of a confirmed baseline is
gated, and a candidate that misses it is retested under the retest rule of ADR 016. A target
that failed the no-LLM pre-run check reads NOT_RUN and leaves the gate not comparable, whatever
its baseline, so a gate cannot read green with a target missing. A target with a run whose
status would change if its unchecked credits were misses reads UNCHECKED_DECIDES and is not
comparable either, whatever its baseline, so a gate outcome never rests on a credit the replay
could not check (ADR 030)."""

from collections.abc import Mapping, Sequence
from enum import StrEnum

from pydantic import BaseModel

from evals.baseline import BaselineStatus
from evals.cve.detection.baseline import DetectionBaseline, DetectionRunConditions
from evals.cve_grammar import DETECTION_RUNGS, CVEStatus, RunGrade
from evals.gate import RetestRule
from evals.gate_outcome import GateOutcome

_BASELINE_DIRECTORY = "evals/baselines/detection"
WHOLE_RESET = (
    f"Reset the whole baseline: delete {_BASELINE_DIRECTORY}/ in a commit of its own, "
    "then record twice at one commit (ADR 020)."
)


class TargetOutcome(StrEnum):
    HELD = "held"
    REGRESSION = "regression"
    MISS_NOT_REPRODUCED = "miss_not_reproduced"
    PENDING_RETEST = "pending_retest"
    NOT_GATED = "not_gated"
    FIXTURE_CHANGED = "fixture_changed"
    NO_BASELINE = "no_baseline"
    INCOMPLETE = "incomplete"
    NOT_RUN = "not_run"
    UNCHECKED_DECIDES = "unchecked_decides"


class TargetCandidate(BaseModel):
    flaw_id: str
    fixture_fingerprint: str
    runs: list[CVEStatus]
    # False when a run did not complete: the runs then hold the completed ones only.
    completed: bool
    # True when a run's status would change if its unchecked credits were misses.
    depends_on_unchecked: bool = False


def depends_on_unchecked(grade: RunGrade) -> bool:
    """A run whose status rests on credits the replay could not check: its status differs from
    the status it would have if every unchecked credit counted as a miss."""
    missed = grade.status_if_unchecked_missed
    return missed is not None and grade.status != missed


class TargetComparison(BaseModel):
    flaw_id: str
    outcome: TargetOutcome
    candidate_runs: list[CVEStatus]
    baseline_runs: list[CVEStatus] = []  # empty without a baseline
    retests: list[bool] = []  # True: the miss reproduced
    detail: str | None = None


class DetectionGateResult(BaseModel):
    outcome: GateOutcome
    reasons: list[str]
    targets: list[TargetComparison]


def condition_mismatches(
    baselines: Mapping[str, DetectionBaseline], candidate: DetectionRunConditions
) -> list[str]:
    expected = candidate.model_dump()
    return [
        f"{_file_name(flaw_id)}: {field} is {recorded!r}, the run has {expected[field]!r}"
        for flaw_id, baseline in sorted(baselines.items())
        for field, recorded in baseline.conditions.model_dump().items()
        if recorded != expected[field]
    ]


def compare_target(
    baseline: DetectionBaseline | None, candidate: TargetCandidate
) -> TargetComparison:
    def outcome(value: TargetOutcome, detail: str | None = None) -> TargetComparison:
        return TargetComparison(
            flaw_id=candidate.flaw_id,
            outcome=value,
            candidate_runs=candidate.runs,
            baseline_runs=[] if baseline is None else baseline.runs,
            detail=detail,
        )

    if candidate.depends_on_unchecked:
        return outcome(TargetOutcome.UNCHECKED_DECIDES, _unchecked_detail(candidate))
    if baseline is None:
        return outcome(TargetOutcome.NO_BASELINE)
    if baseline.fixture_fingerprint != candidate.fixture_fingerprint:
        return outcome(TargetOutcome.FIXTURE_CHANGED, target_reset(candidate.flaw_id))
    if not baseline.gated():
        return outcome(TargetOutcome.NOT_GATED, _why_not_gated(baseline))
    if not candidate.completed:
        return outcome(TargetOutcome.INCOMPLETE, "a run did not complete")
    if all(status in DETECTION_RUNGS for status in candidate.runs):
        return outcome(TargetOutcome.HELD)
    return outcome(TargetOutcome.PENDING_RETEST)


def _unchecked_detail(candidate: TargetCandidate) -> str:
    runs = ", ".join(status.value for status in candidate.runs)
    return f"a run's status rests on credits the replay could not check (runs: {runs})"


def _file_name(flaw_id: str) -> str:
    return f"{flaw_id}.json"


def target_reset(flaw_id: str) -> str:
    return (
        f"fixture changed since the baseline: delete {_BASELINE_DIRECTORY}/{_file_name(flaw_id)} "
        f"in the commit that changes its fixture, then record it twice at one commit "
        f"with --flaw {flaw_id}"
    )


def _why_not_gated(baseline: DetectionBaseline) -> str:
    if baseline.status == BaselineStatus.UNCONFIRMED:
        return (
            f"unconfirmed baseline recorded at {baseline.commit}: confirm it with a second "
            "recording at that commit, or delete it in a commit of its own"
        )
    return "not detected in every baseline run"


def apply_retests(
    comparison: TargetComparison, retests: list[bool | None], rule: RetestRule
) -> TargetComparison:
    completed = [retest for retest in retests if retest is not None]
    if len(completed) < len(retests):
        return comparison.model_copy(
            update={
                "outcome": TargetOutcome.INCOMPLETE,
                "retests": completed,
                "detail": "a retest did not complete",
            }
        )
    decision = rule.decide_retests(completed)
    if decision is None:
        return comparison.model_copy(update={"retests": completed})
    outcome = TargetOutcome.REGRESSION if decision else TargetOutcome.MISS_NOT_REPRODUCED
    return comparison.model_copy(update={"outcome": outcome, "retests": completed})


def decide(comparisons: Sequence[TargetComparison], mismatches: list[str]) -> DetectionGateResult:
    # A not-run target, a target whose unchecked credits decide it, and a miss whose retests
    # never decided say nothing either way.
    not_comparable = [
        *_named(comparisons, TargetOutcome.NOT_RUN),
        *_named(comparisons, TargetOutcome.UNCHECKED_DECIDES),
        *_named(comparisons, TargetOutcome.INCOMPLETE),
        *_named(comparisons, TargetOutcome.PENDING_RETEST),
    ]
    if mismatches or not_comparable:
        reasons = [*mismatches, WHOLE_RESET] if mismatches else []
        return _result(GateOutcome.NOT_COMPARABLE, [*reasons, *not_comparable], comparisons)
    regressions = _named(comparisons, TargetOutcome.REGRESSION)
    if regressions:
        return _result(GateOutcome.RED, regressions, comparisons)
    return _result(GateOutcome.GREEN, _green_reasons(comparisons), comparisons)


def _named(comparisons: Sequence[TargetComparison], outcome: TargetOutcome) -> list[str]:
    return [
        f"{comparison.flaw_id}: {_describe(comparison)}"
        for comparison in comparisons
        if comparison.outcome == outcome
    ]


def _describe(comparison: TargetComparison) -> str:
    if comparison.retests:
        reproduced = sum(comparison.retests)
        retests = f", the miss reproduced in {reproduced} of {len(comparison.retests)} retests"
    else:
        retests = ""
    detail = f" ({comparison.detail})" if comparison.detail else ""
    return f"{comparison.outcome.value}{retests}{detail}"


def _green_reasons(comparisons: Sequence[TargetComparison]) -> list[str]:
    gated = {TargetOutcome.HELD, TargetOutcome.MISS_NOT_REPRODUCED}
    reasons = [
        *_named(comparisons, TargetOutcome.MISS_NOT_REPRODUCED),
        *_named(comparisons, TargetOutcome.FIXTURE_CHANGED),
    ]
    if not any(comparison.outcome in gated for comparison in comparisons):
        reasons.append("no target is gated")
    return reasons


def _result(
    outcome: GateOutcome, reasons: list[str], comparisons: Sequence[TargetComparison]
) -> DetectionGateResult:
    return DetectionGateResult(outcome=outcome, reasons=reasons, targets=list(comparisons))


def exit_code(outcome: GateOutcome) -> int:
    return {GateOutcome.GREEN: 0, GateOutcome.RED: 1, GateOutcome.NOT_COMPARABLE: 3}[outcome]
