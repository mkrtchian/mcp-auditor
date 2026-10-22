"""The nuisance gate on the acceptance servers: a server with no alarm in any run of a confirmed
baseline is gated, and a candidate alarm on it is replayed under the replay rule of ADR 016. A
server with an alarm in its baseline is unstable, and a new alarm on it is reported inconclusive.

The mirror of `cve_gate`, with the server in place of the target and an alarm in place of a miss.
"""

from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel

from evals.baseline import BaselineStatus
from evals.gate import ReplayRule
from evals.gate_verdict import GateVerdict
from evals.nuisance_gate_baseline import WHOLE_RESET, NuisanceServerBaseline, server_reset


class ServerOutcome(StrEnum):
    HELD = "held"
    REGRESSION = "regression"
    ALARM_NOT_REPRODUCED = "alarm_not_reproduced"
    PENDING_REPLAY = "pending_replay"
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
    replays: list[bool] = []  # True: the alarm reproduced
    detail: str | None = None


class NuisanceGateResult(BaseModel):
    verdict: GateVerdict
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
            detail=detail,
        )

    if baseline is None:
        return outcome(ServerOutcome.NO_BASELINE)
    if baseline.fixture_fingerprint != candidate.fixture_fingerprint:
        return outcome(ServerOutcome.FIXTURE_CHANGED, server_reset(candidate.server_package))
    if baseline.status == BaselineStatus.EXPLORATORY:
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
    return outcome(ServerOutcome.PENDING_REPLAY)


def _why_not_gated(baseline: NuisanceServerBaseline) -> str:
    if baseline.status == BaselineStatus.EXPLORATORY:
        return (
            f"exploratory baseline recorded at {baseline.commit}: confirm it with a second "
            "recording at that commit, or delete it in a commit of its own"
        )
    return f"flagged in {sum(baseline.runs)} of {len(baseline.runs)} baseline runs"


def settle(
    comparison: ServerComparison, replays: list[bool | None], rule: ReplayRule
) -> ServerComparison:
    completed = [replay for replay in replays if replay is not None]
    if len(completed) < len(replays):
        return comparison.model_copy(
            update={
                "outcome": ServerOutcome.INCOMPLETE,
                "replays": completed,
                "detail": "a replay did not complete",
            }
        )
    decision = rule.decide_replays(completed)
    if decision is None:
        return comparison.model_copy(update={"replays": completed})
    outcome = ServerOutcome.REGRESSION if decision else ServerOutcome.ALARM_NOT_REPRODUCED
    return comparison.model_copy(update={"outcome": outcome, "replays": completed})


def judge(comparisons: Sequence[ServerComparison], mismatches: list[str]) -> NuisanceGateResult:
    not_comparable = [
        *_named(comparisons, ServerOutcome.NOT_RUN),
        *_named(comparisons, ServerOutcome.INCOMPLETE),
        *_named(comparisons, ServerOutcome.PENDING_REPLAY),
    ]
    if mismatches or not_comparable:
        reasons = [*mismatches, WHOLE_RESET] if mismatches else []
        return _result(GateVerdict.NOT_COMPARABLE, [*reasons, *not_comparable], comparisons)
    regressions = _named(comparisons, ServerOutcome.REGRESSION)
    if regressions:
        return _result(GateVerdict.RED, regressions, comparisons)
    return _result(GateVerdict.GREEN, _green_reasons(comparisons), comparisons)


def _named(comparisons: Sequence[ServerComparison], outcome: ServerOutcome) -> list[str]:
    return [
        f"{comparison.server_package}: {_describe(comparison)}"
        for comparison in comparisons
        if comparison.outcome == outcome
    ]


def _describe(comparison: ServerComparison) -> str:
    if comparison.replays:
        reproduced = sum(comparison.replays)
        replays = f", the alarm reproduced in {reproduced} of {len(comparison.replays)} replays"
    else:
        replays = ""
    detail = f" ({comparison.detail})" if comparison.detail else ""
    return f"{comparison.outcome.value}{replays}{detail}"


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
    verdict: GateVerdict, reasons: list[str], comparisons: Sequence[ServerComparison]
) -> NuisanceGateResult:
    return NuisanceGateResult(verdict=verdict, reasons=reasons, servers=list(comparisons))


def exit_code(verdict: GateVerdict) -> int:
    return {GateVerdict.GREEN: 0, GateVerdict.RED: 1, GateVerdict.NOT_COMPARABLE: 3}[verdict]
