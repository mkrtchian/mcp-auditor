"""The replay of ADR 030, outside the grammar fingerprint.

A detecting run is replayed, with no LLM, against one fresh container of the patched version:
its recorded calls are sent again, in the recorded order, and the patched outputs are handed to
the grammar's strike rule, which removes a credit the auditor could have earned without the
flaw. The replay decides nothing about credit itself. What it plants and that it launches the
patched version live here, in the caller, not in the fingerprint (section 3).

A patched server gone mid-call looks like an ordinary error, so the replay counts an attempt as
failed when a response reads as a lost connection at a call the vulnerable run still answered, or
when entering the launch raises, or leaving it before every call was answered. An attempt whose
calls were all answered stands even if leaving the launch raises, since a server that logs its
shutdown to stdout makes the MCP client raise on that line. When the patched connection is lost at a
call the vulnerable run had already lost, the attempt instead ends there, truncated, with the
outputs gathered so far: the vulnerable run earned no credit past its own death. A truncated attempt
is provisional, since only another launch tells a transient patched death from a deterministic one,
so failed and truncated attempts are both retried, up to three attempts in all, and a complete
attempt ends the replay. The run is then decided on the union of the strikes of every attempt that
completed or was truncated: with a complete attempt, or on truncated outputs alone when every
attempt ended where the vulnerable run did. Otherwise (no attempt got through, or truncated and
failed attempts mixed with no complete one) the run's credits are kept unchecked. The calls and
patched outputs stay in memory and are never written.

Beside the credit check, the replay names why a run stayed unchecked: its recorded calls disagree
with its report (no attempt launched), or no attempt decided it. Each attempt that failed carries
its cause: the launch failed (an exception entering it, or leaving it before every call was
answered), or the connection was lost at a call the vulnerable run answered. A truncated attempt is
no failure. A decided run has no reason, but its failed attempts, if any, still carry their causes.
"""

import os
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from evals.cve_environments import TOOL_CALL_TIMEOUT, connect
from evals.cve_grammar import CreditCheck, PlantedTarget
from evals.cve_places import Place
from evals.cve_proofs import GradedRun, UnitPlace, struck_by_replay
from evals.cve_recording_client import Exchange
from evals.cve_report_units import units_of
from evals.cve_targets import CVETarget, TargetVersion
from evals.cve_units import Step, Unit
from evals.server_health import lost_connection
from mcp_auditor.domain.models import AuditReport
from mcp_auditor.domain.ports import MCPClientPort

# Each recorded call keeps the vulnerable response it drew, so the replay can end where the
# vulnerable run itself ended (a lost connection) instead of retrying a death it cannot outlive.
type RecordedCall = Exchange

# One attempt and at most two retries, after a failed or a truncated attempt.
REPLAY_ATTEMPTS = 3


@dataclass(frozen=True)
class RunToCheck:
    target: CVETarget  # the target to launch patched
    run_target: PlantedTarget  # the run's own nonces, planted on the vulnerable version
    report: AuditReport
    recorded_calls: list[RecordedCall]  # every call the audit sent, in order
    records: tuple[Place, ...]  # the kept places to plant on the patched version


@dataclass(frozen=True)
class ReplayedRun:
    nonces: Mapping[str, str]  # the patched launch's fresh nonces
    outputs: list[str]  # the patched outputs, in the recorded order
    complete: bool  # False when the attempt ended at a call the vulnerable run had already lost


class ReplayAttemptFailure(StrEnum):
    LAUNCH_FAILED = "launch_failed"
    LOST_CONNECTION = "lost_connection"  # at a call the vulnerable run answered


class UncheckedReason(StrEnum):
    ARGUMENTS_DISAGREE = "arguments_disagree"  # no attempt launched
    NO_ATTEMPT_DECIDED = "no_attempt_decided"


@dataclass(frozen=True)
class ReplayOutcome:
    check: CreditCheck
    unchecked_reason: UncheckedReason | None  # None on a decided run
    attempt_failures: tuple[ReplayAttemptFailure, ...]  # in attempt order


async def replay_with_causes(
    run: RunToCheck, *, tool_call_timeout: int = TOOL_CALL_TIMEOUT
) -> ReplayOutcome:
    """The strike the replay earns against the patched server, or an unchecked verdict when the
    recorded calls disagree with the report or the patched launches did not settle the run."""
    units = units_of(run.report)
    if not arguments_agree(units, run.recorded_calls):
        return ReplayOutcome(_UNCHECKED, UncheckedReason.ARGUMENTS_DISAGREE, ())
    attempts = [attempt async for attempt in _attempts(run, tool_call_timeout)]
    replayed = [attempt for attempt in attempts if isinstance(attempt, ReplayedRun)]
    failures = tuple(attempt for attempt in attempts if isinstance(attempt, ReplayAttemptFailure))
    if not _decides(replayed):
        return ReplayOutcome(_UNCHECKED, UncheckedReason.NO_ATTEMPT_DECIDED, failures)
    struck = (_struck(run.run_target, units, attempt) for attempt in replayed)
    return ReplayOutcome(
        CreditCheck(frozenset[UnitPlace]().union(*struck), unchecked=False), None, failures
    )


_UNCHECKED = CreditCheck(frozenset(), unchecked=True)

type _Attempt = ReplayedRun | ReplayAttemptFailure


async def _attempts(run: RunToCheck, timeout: int) -> AsyncIterator[_Attempt]:
    for _ in range(REPLAY_ATTEMPTS):
        attempt = await _run_patched(run.target, run.records, run.recorded_calls, timeout)
        yield attempt
        if isinstance(attempt, ReplayedRun) and attempt.complete:
            return


def _decides(replayed: Sequence[ReplayedRun]) -> bool:
    # A failed attempt cannot tell a transient death from a deterministic one, so truncated
    # attempts decide without a complete one only when no attempt failed.
    return any(attempt.complete for attempt in replayed) or len(replayed) == REPLAY_ATTEMPTS


def _struck(
    run_target: PlantedTarget, units: Sequence[Unit], replayed: ReplayedRun
) -> frozenset[UnitPlace]:
    replay_target = PlantedTarget(run_target.mechanism, run_target.aim, replayed.nonces)
    return struck_by_replay(
        GradedRun(run_target, units),
        GradedRun(replay_target, replayed_units(units, replayed.outputs)),
    )


async def _run_patched(
    target: CVETarget, records: tuple[Place, ...], calls: Sequence[RecordedCall], timeout: int
) -> _Attempt:
    """The patched outputs of one fresh launch, or the cause it could not be reached: a lost
    connection at a call the vulnerable run still answered, or a failed launch, an exception
    entering the launch or its client, or leaving it before every call was answered. A patched
    loss at a call the vulnerable run had already lost ends the attempt there, truncated, with the
    outputs gathered so far: it is provisional, since only another launch can tell a transient
    death from a deterministic one."""
    attempt: _Attempt = ReplayAttemptFailure.LAUNCH_FAILED
    try:
        async with target.launched(records, version=TargetVersion.PATCHED) as planted:
            with open(os.devnull, "w") as devnull:
                async with connect(planted.launch, devnull, tool_call_timeout=timeout) as client:
                    attempt = await _sent_again(client, planted.nonces, calls)
    except Exception:
        # The records arrive pre-resolved and pre-planted by `attempt_once` on the vulnerable
        # version, so a `planting_spec` config error cannot reach here: only launch and connection
        # failures of this fresh patched launch are. Narrowing this to a hand-picked exception set
        # would crash the whole benchmark on a transient infra blip, worse than the unchecked it
        # returns. A complete attempt survives a raising teardown, as the vulnerable run does in
        # `attempt_once`: a server that logs its shutdown to stdout makes the client raise there.
        # A connection already lost keeps its cause, since a dead server's teardown raises too.
        if isinstance(attempt, ReplayedRun) and not attempt.complete:
            return ReplayAttemptFailure.LAUNCH_FAILED
    return attempt


async def _sent_again(
    client: MCPClientPort, nonces: Mapping[str, str], calls: Sequence[RecordedCall]
) -> _Attempt:
    outputs: list[str] = []
    vulnerable_lost = False
    for name, args, vulnerable in calls:
        vulnerable_lost = vulnerable_lost or lost_connection(vulnerable)
        response = await client.call_tool(name, args)
        if lost_connection(response):
            if not vulnerable_lost:
                return ReplayAttemptFailure.LOST_CONNECTION
            return ReplayedRun(nonces, outputs, complete=False)
        outputs.append(response.content)
    return ReplayedRun(nonces, outputs, complete=True)


def replayed_units(units: Sequence[Unit], outputs: Sequence[str]) -> list[Unit]:
    remaining = iter(outputs)
    return [
        Unit(
            tuple(
                Step(step.arguments, _next_output(remaining) if _sent_a_call(unit, step) else ())
                for step in unit.steps
            ),
            unit.verdict,
            unit.category,
            unit.blocked,
        )
        for unit in units
    ]


def _next_output(remaining: Iterator[str]) -> tuple[str, ...]:
    # A unit straddling the crash has sending steps past the last patched output: those take no
    # output rather than raising, so the replay keeps its pre-crash outputs and empty later steps.
    output = next(remaining, None)
    return () if output is None else (output,)


def arguments_agree(units: Sequence[Unit], calls: Sequence[RecordedCall]) -> bool:
    """Each recorded call attaches to the next step that sent one, and its arguments must equal
    the step's. A count or argument mismatch means the sequence and the report disagree."""
    sending = [step for unit in units for step in unit.steps if _sent_a_call(unit, step)]
    if len(sending) != len(calls):
        return False
    return all(step.arguments == args for step, (_, args, _) in zip(sending, calls, strict=True))


def _sent_a_call(unit: Unit, step: Step) -> bool:
    # A blocked case and a chain blocked at its first step carry one step that reached no server,
    # so it has no output. Every step that ran carries the output the call returned.
    return not unit.blocked or bool(step.outputs)
