"""The CVE acceptance gate (ADR 024): a target detected in every run of a confirmed baseline
is gated, and a candidate that misses it is replayed under the replay rule of ADR 016."""

from collections.abc import Mapping, Sequence
from enum import StrEnum

from pydantic import BaseModel

from evals.baseline import BaselineStatus
from evals.cve_baseline import CVERunConditions, CVETargetBaseline
from evals.cve_grammar import DETECTION_RUNGS, CVEStatus
from evals.gate import ReplayRule

_BASELINE_DIRECTORY = "evals/baselines/cve"
_WHOLE_RESET = (
    f"Reset the whole baseline: delete {_BASELINE_DIRECTORY}/ in a commit of its own, "
    "then record twice at one commit (ADR 020)."
)


class TargetOutcome(StrEnum):
    HELD = "held"
    REGRESSION = "regression"
    MISS_NOT_REPRODUCED = "miss_not_reproduced"
    PENDING_REPLAY = "pending_replay"
    NOT_GATED = "not_gated"
    FIXTURE_CHANGED = "fixture_changed"
    NO_BASELINE = "no_baseline"
    INCOMPLETE = "incomplete"


class CVEGateVerdict(StrEnum):
    GREEN = "green"
    RED = "red"
    NOT_COMPARABLE = "not_comparable"


class TargetCandidate(BaseModel):
    cve_id: str
    fixture_fingerprint: str
    runs: list[CVEStatus]
    # False when a run did not complete: the runs then hold the completed ones only.
    completed: bool


class TargetComparison(BaseModel):
    cve_id: str
    outcome: TargetOutcome
    candidate_runs: list[CVEStatus]
    replays: list[bool] = []  # True: the miss reproduced
    detail: str | None = None


class CVEGateResult(BaseModel):
    verdict: CVEGateVerdict
    reasons: list[str]
    targets: list[TargetComparison]


def condition_mismatches(
    baselines: Mapping[str, CVETargetBaseline], candidate: CVERunConditions
) -> list[str]:
    expected = candidate.model_dump()
    return [
        f"{_file_name(cve_id)}: {field} is {recorded!r}, the run has {expected[field]!r}"
        for cve_id, baseline in sorted(baselines.items())
        for field, recorded in baseline.conditions.model_dump().items()
        if recorded != expected[field]
    ]


def compare_target(
    baseline: CVETargetBaseline | None, candidate: TargetCandidate
) -> TargetComparison:
    def outcome(value: TargetOutcome, detail: str | None = None) -> TargetComparison:
        return TargetComparison(
            cve_id=candidate.cve_id, outcome=value, candidate_runs=candidate.runs, detail=detail
        )

    if baseline is None:
        return outcome(TargetOutcome.NO_BASELINE)
    if baseline.fixture_fingerprint != candidate.fixture_fingerprint:
        return outcome(TargetOutcome.FIXTURE_CHANGED, _target_reset(candidate.cve_id))
    if not baseline.gated():
        return outcome(TargetOutcome.NOT_GATED, _why_not_gated(baseline))
    if not candidate.completed:
        return outcome(TargetOutcome.INCOMPLETE, "a run did not complete")
    if all(status in DETECTION_RUNGS for status in candidate.runs):
        return outcome(TargetOutcome.HELD)
    return outcome(TargetOutcome.PENDING_REPLAY)


def _file_name(cve_id: str) -> str:
    return f"{cve_id}.json"


def _target_reset(cve_id: str) -> str:
    return (
        f"fixture changed since the baseline: delete {_BASELINE_DIRECTORY}/{_file_name(cve_id)} "
        f"in the commit that changes its fixture, then record it twice at one commit "
        f"with --cve {cve_id}"
    )


def _why_not_gated(baseline: CVETargetBaseline) -> str:
    if baseline.status == BaselineStatus.EXPLORATORY:
        return (
            f"exploratory baseline recorded at {baseline.commit}: confirm it with a second "
            "recording at that commit, or delete it in a commit of its own"
        )
    return "not detected in every baseline run"


def settle(
    comparison: TargetComparison, replays: list[bool | None], rule: ReplayRule
) -> TargetComparison:
    completed = [replay for replay in replays if replay is not None]
    if len(completed) < len(replays):
        return comparison.model_copy(
            update={
                "outcome": TargetOutcome.INCOMPLETE,
                "replays": completed,
                "detail": "a replay did not complete",
            }
        )
    decision = rule.decide_replays(completed)
    if decision is None:
        return comparison.model_copy(update={"replays": completed})
    outcome = TargetOutcome.REGRESSION if decision else TargetOutcome.MISS_NOT_REPRODUCED
    return comparison.model_copy(update={"outcome": outcome, "replays": completed})


def judge(comparisons: Sequence[TargetComparison], mismatches: list[str]) -> CVEGateResult:
    # A miss whose replays never decided says nothing either way on a gated target.
    incomplete = [
        *_named(comparisons, TargetOutcome.INCOMPLETE),
        *_named(comparisons, TargetOutcome.PENDING_REPLAY),
    ]
    if mismatches or incomplete:
        reasons = [*mismatches, _WHOLE_RESET] if mismatches else []
        return _result(CVEGateVerdict.NOT_COMPARABLE, [*reasons, *incomplete], comparisons)
    regressions = _named(comparisons, TargetOutcome.REGRESSION)
    if regressions:
        return _result(CVEGateVerdict.RED, regressions, comparisons)
    return _result(CVEGateVerdict.GREEN, _green_reasons(comparisons), comparisons)


def _named(comparisons: Sequence[TargetComparison], outcome: TargetOutcome) -> list[str]:
    return [
        f"{comparison.cve_id}: {_describe(comparison)}"
        for comparison in comparisons
        if comparison.outcome == outcome
    ]


def _describe(comparison: TargetComparison) -> str:
    if comparison.replays:
        reproduced = sum(comparison.replays)
        replays = f", the miss reproduced in {reproduced} of {len(comparison.replays)} replays"
    else:
        replays = ""
    detail = f" ({comparison.detail})" if comparison.detail else ""
    return f"{comparison.outcome.value}{replays}{detail}"


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
    verdict: CVEGateVerdict, reasons: list[str], comparisons: Sequence[TargetComparison]
) -> CVEGateResult:
    return CVEGateResult(verdict=verdict, reasons=reasons, targets=list(comparisons))


def exit_code(verdict: CVEGateVerdict) -> int:
    return {CVEGateVerdict.GREEN: 0, CVEGateVerdict.RED: 1, CVEGateVerdict.NOT_COMPARABLE: 3}[
        verdict
    ]
