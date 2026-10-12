"""The replay of ADR 030, outside the grammar fingerprint.

A detecting run is replayed, with no LLM, against one fresh container of the patched version:
its recorded calls are sent again, in the recorded order, and the patched outputs are handed to
the grammar's strike rule, which removes a credit the auditor could have earned without the
flaw. The replay decides nothing about credit itself. What it plants and that it launches the
patched version live here, in the caller, not in the fingerprint (section 3).

A patched server gone mid-call looks like an ordinary error, so the replay counts an attempt as
failed when a response reads as a lost connection at a call the vulnerable run still answered, or
when entering or leaving the launch raises. A failed attempt is retried at most twice, and the
run's credits are then kept unchecked. When the patched connection is lost at a call the vulnerable
run had already lost, the replay instead ends there, with the outputs gathered so far: the
vulnerable run earned no credit past its own death, so the replay need not outlive it either. The
calls and patched outputs stay in memory and are never written.
"""

import os
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass

from evals.cve_environments import TOOL_CALL_TIMEOUT, connect
from evals.cve_grammar import CreditCheck, PlantedTarget
from evals.cve_places import Place
from evals.cve_proofs import GradedRun, UnitPlace, struck_by_replay
from evals.cve_recording_client import Exchange
from evals.cve_report_units import units_of
from evals.cve_targets import CVETarget, TargetVersion
from evals.cve_units import Step, Unit
from mcp_auditor.domain.models import AuditReport, ToolResponse

# Each recorded call keeps the vulnerable response it drew, so the replay can end where the
# vulnerable run itself ended (a lost connection) instead of retrying a death it cannot outlive.
type RecordedCall = Exchange

# A patched server gone mid-call looks like an ordinary error: SDK 1.30 turns a call in flight
# when the server exits into an McpError reading "Connection closed", and the stdio transport
# surfaces a closed or broken stream under anyio's own error names. Any other McpError (invalid
# params, a removed tool) and a TimeoutError on a live server are ordinary responses.
LOST_CONNECTION_RESPONSES: tuple[tuple[str, str | None], ...] = (
    ("McpError", "Connection closed"),
    ("ClosedResourceError", None),
    ("BrokenResourceError", None),
)

# One attempt and at most two retries, then the run's credits are kept unchecked.
REPLAY_ATTEMPTS = 3


@dataclass(frozen=True)
class RunToCheck:
    target: CVETarget  # the target to launch patched
    run_target: PlantedTarget  # the run's own nonces, planted on the vulnerable version
    report: AuditReport
    recorded_calls: list[RecordedCall]  # every call the audit sent, in order
    records: tuple[Place, ...]  # the kept places to plant on the patched version


async def replay_credit(
    run: RunToCheck, *, tool_call_timeout: int = TOOL_CALL_TIMEOUT
) -> CreditCheck:
    """The strike the replay earns against the patched server, or an unchecked verdict when the
    recorded calls disagree with the report or the patched launch could not be reached."""
    units = units_of(run.report)
    if not _arguments_agree(units, run.recorded_calls):
        return CreditCheck(frozenset(), unchecked=True)
    for _ in range(REPLAY_ATTEMPTS):
        replayed = await _run_patched(
            run.target, run.records, run.recorded_calls, tool_call_timeout
        )
        if replayed is not None:
            return CreditCheck(_struck(run.run_target, units, replayed), unchecked=False)
    return CreditCheck(frozenset(), unchecked=True)


def _struck(
    run_target: PlantedTarget, units: Sequence[Unit], replayed: tuple[Mapping[str, str], list[str]]
) -> frozenset[UnitPlace]:
    fresh_nonces, outputs = replayed
    replay_target = PlantedTarget(run_target.mechanism, run_target.aim, fresh_nonces)
    return struck_by_replay(
        GradedRun(run_target, units),
        GradedRun(replay_target, _replayed_units(units, outputs)),
    )


async def _run_patched(
    target: CVETarget, records: tuple[Place, ...], calls: Sequence[RecordedCall], timeout: int
) -> tuple[Mapping[str, str], list[str]] | None:
    """The patched outputs of one fresh launch, or None when the launch could not be reached:
    a lost connection at a call the vulnerable run still answered, or an exception entering or
    leaving the launch or its client. A patched loss at a call the vulnerable run had already
    lost ends the replay where that run itself ended, with the outputs gathered so far."""
    try:
        async with target.launched(records, version=TargetVersion.PATCHED) as planted:
            with open(os.devnull, "w") as devnull:
                async with connect(planted.launch, devnull, tool_call_timeout=timeout) as client:
                    outputs: list[str] = []
                    vulnerable_lost = False
                    for name, args, vulnerable in calls:
                        vulnerable_lost = vulnerable_lost or _lost_connection(vulnerable)
                        response = await client.call_tool(name, args)
                        if _lost_connection(response):
                            return (planted.nonces, outputs) if vulnerable_lost else None
                        outputs.append(response.content)
                    return planted.nonces, outputs
    except Exception:
        # The records arrive pre-resolved and pre-planted by `_attempt` on the vulnerable version,
        # so a `planting_spec` config error cannot reach here: only launch and connection failures
        # of this fresh patched launch are. Narrowing this to a hand-picked exception set would
        # crash the whole benchmark on a transient infra blip, worse than the unchecked it returns.
        return None


def _replayed_units(units: Sequence[Unit], outputs: Sequence[str]) -> list[Unit]:
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


def _arguments_agree(units: Sequence[Unit], calls: Sequence[RecordedCall]) -> bool:
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


def _lost_connection(response: ToolResponse) -> bool:
    return response.is_error and any(
        response.error_type == error_type and (content is None or response.content == content)
        for error_type, content in LOST_CONNECTION_RESPONSES
    )
