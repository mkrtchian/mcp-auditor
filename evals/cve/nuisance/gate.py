"""The nuisance gate on the nuisance acceptance servers: a server with no alarm in any run of a
confirmed baseline is gated, and a candidate alarm on it is retested under the retest rule of ADR
016. A server with an alarm in its baseline is unstable, and a new alarm on it is reported
inconclusive.

The mirror of `evals.cve.detection.gate`, with the server in place of the target and an alarm in
place of a miss.
"""

from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel

from evals.baseline import BaselineStatus
from evals.cve.nuisance.gate_baseline import WHOLE_RESET, NuisanceServerBaseline, server_reset
from evals.gate import RetestRule
from evals.gate_outcome import GateOutcome


class ServerOutcome(StrEnum):
    HELD = "held"
    REGRESSION = "regression"
    ALARM_NOT_REPRODUCED = "alarm_not_reproduced"
    PENDING_RETEST = "pending_retest"
    NOT_GATED = "not_gated"
    INCONCLUSIVE = "inconclusive"
    FIXTURE_CHANGED = "fixture_changed"
    NO_BASELINE = "no_baseline"
    INCOMPLETE = "incomplete"
    NOT_RUN = "not_run"


class ServerCandidate(BaseModel):
    server_package: str
    fixture_fingerprint: str
    runs: list[bool]  # flagged per completed run
    # False when a run did not complete: the runs then hold the completed ones only.
    completed: bool


class ServerComparison(BaseModel):
    server_package: str
    outcome: ServerOutcome
    candidate_runs: list[bool]
    baseline_runs: list[bool] = []  # empty without a baseline
    retests: list[bool] = []  # True: the alarm reproduced
    detail: str | None = None


class NuisanceGateResult(BaseModel):
    outcome: GateOutcome
    reasons: list[str]
    servers: list[ServerComparison]


def compare_server(
    baseline: NuisanceServerBaseline | None, candidate: ServerCandidate
) -> ServerComparison:
    def outcome(value: ServerOutcome, detail: str | None = None) -> ServerComparison:
        return ServerComparison(
            server_package=candidate.server_package,
            outcome=value,
            candidate_runs=candidate.runs,
            baseline_runs=[] if baseline is None else baseline.runs,
            detail=detail,
        )

    if baseline is None:
        return outcome(ServerOutcome.NO_BASELINE)
    if baseline.fixture_fingerprint != candidate.fixture_fingerprint:
        return outcome(ServerOutcome.FIXTURE_CHANGED, server_reset(candidate.server_package))
    if baseline.status == BaselineStatus.UNCONFIRMED:
        return outcome(ServerOutcome.NOT_GATED, _why_not_gated(baseline))
    # Flagged in some baseline runs or in all of them, the server is unstable either way:
    # no new alarm can show on it.
    if baseline.alarmed():
        unstable = ServerOutcome.INCONCLUSIVE if any(candidate.runs) else ServerOutcome.NOT_GATED
        return outcome(unstable, _why_not_gated(baseline))
    if not candidate.completed:
        return outcome(ServerOutcome.INCOMPLETE, "a run did not complete")
    if not any(candidate.runs):
        return outcome(ServerOutcome.HELD)
    return outcome(ServerOutcome.PENDING_RETEST)


def _why_not_gated(baseline: NuisanceServerBaseline) -> str:
    if baseline.status == BaselineStatus.UNCONFIRMED:
        return (
            f"unconfirmed baseline recorded at {baseline.commit}: confirm it with a second "
            "recording at that commit, or delete it in a commit of its own"
        )
    return f"flagged in {sum(baseline.runs)} of {len(baseline.runs)} baseline runs"


def apply_retests(
    comparison: ServerComparison, retests: list[bool | None], rule: RetestRule
) -> ServerComparison:
    completed = [retest for retest in retests if retest is not None]
    if len(completed) < len(retests):
        return comparison.model_copy(
            update={
                "outcome": ServerOutcome.INCOMPLETE,
                "retests": completed,
                "detail": "a retest did not complete",
            }
        )
    decision = rule.decide_retests(completed)
    if decision is None:
        return comparison.model_copy(update={"retests": completed})
    outcome = ServerOutcome.REGRESSION if decision else ServerOutcome.ALARM_NOT_REPRODUCED
    return comparison.model_copy(update={"outcome": outcome, "retests": completed})


def decide(comparisons: Sequence[ServerComparison], mismatches: list[str]) -> NuisanceGateResult:
    not_comparable = [
        *_named(comparisons, ServerOutcome.NOT_RUN),
        *_named(comparisons, ServerOutcome.INCOMPLETE),
        *_named(comparisons, ServerOutcome.PENDING_RETEST),
    ]
    if mismatches or not_comparable:
        reasons = [*mismatches, WHOLE_RESET] if mismatches else []
        return _result(GateOutcome.NOT_COMPARABLE, [*reasons, *not_comparable], comparisons)
    regressions = _named(comparisons, ServerOutcome.REGRESSION)
    if regressions:
        return _result(GateOutcome.RED, regressions, comparisons)
    return _result(GateOutcome.GREEN, _green_reasons(comparisons), comparisons)


def _named(comparisons: Sequence[ServerComparison], outcome: ServerOutcome) -> list[str]:
    return [
        f"{comparison.server_package}: {_describe(comparison)}"
        for comparison in comparisons
        if comparison.outcome == outcome
    ]


def _describe(comparison: ServerComparison) -> str:
    if comparison.retests:
        reproduced = sum(comparison.retests)
        retests = f", the alarm reproduced in {reproduced} of {len(comparison.retests)} retests"
    else:
        retests = ""
    detail = f" ({comparison.detail})" if comparison.detail else ""
    return f"{comparison.outcome.value}{retests}{detail}"


def _green_reasons(comparisons: Sequence[ServerComparison]) -> list[str]:
    gated = {ServerOutcome.HELD, ServerOutcome.ALARM_NOT_REPRODUCED}
    reasons = [
        *_named(comparisons, ServerOutcome.ALARM_NOT_REPRODUCED),
        *_named(comparisons, ServerOutcome.FIXTURE_CHANGED),
        *_named(comparisons, ServerOutcome.INCONCLUSIVE),
    ]
    if not any(comparison.outcome in gated for comparison in comparisons):
        reasons.append("no server is gated")
    return reasons


def _result(
    outcome: GateOutcome, reasons: list[str], comparisons: Sequence[ServerComparison]
) -> NuisanceGateResult:
    return NuisanceGateResult(outcome=outcome, reasons=reasons, servers=list(comparisons))


def exit_code(outcome: GateOutcome) -> int:
    return {GateOutcome.GREEN: 0, GateOutcome.RED: 1, GateOutcome.NOT_COMPARABLE: 3}[outcome]
