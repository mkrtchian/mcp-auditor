"""The replay of ADR 030, outside the grammar fingerprint.

A detecting run is replayed, with no LLM, against one fresh container of the patched version:
its recorded calls are sent again, in the recorded order, and the patched outputs are handed to
the grammar's strike rule, which removes a credit the auditor could have earned without the
flaw. The replay decides nothing about credit itself. What it plants and that it launches the
patched version live here, in the caller, not in the fingerprint (section 3).

A patched server gone mid-call looks like an ordinary error, so the replay counts an attempt as
failed when a response reads as a lost connection or when entering or leaving the launch raises.
It stops at the first lost-connection response, retries at most twice, and then keeps the run's
credits unchecked. The calls and patched outputs stay in memory and are never written.
"""

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from evals.cve_environments import TOOL_CALL_TIMEOUT, connect
from evals.cve_grammar import CreditCheck, PlantedTarget
from evals.cve_places import Place
from evals.cve_proofs import GradedRun, UnitPlace, struck_by_replay
from evals.cve_report_units import units_of
from evals.cve_targets import CVETarget, TargetVersion
from evals.cve_units import Step, Unit
from mcp_auditor.domain.models import AuditReport, ToolResponse

type RecordedCall = tuple[str, dict[str, Any]]

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
    a lost-connection response, or an exception entering or leaving the launch or its client."""
    try:
        async with target.launched(records, version=TargetVersion.PATCHED) as planted:
            with open(os.devnull, "w") as devnull:
                async with connect(planted.launch, devnull, tool_call_timeout=timeout) as client:
                    outputs: list[str] = []
                    for name, args in calls:
                        response = await client.call_tool(name, args)
                        if _lost_connection(response):
                            return None
                        outputs.append(response.content)
                    return planted.nonces, outputs
    except Exception:
        return None


def _replayed_units(units: Sequence[Unit], outputs: Sequence[str]) -> list[Unit]:
    remaining = iter(outputs)
    return [
        Unit(
            tuple(
                Step(step.arguments, (next(remaining),) if _sent_a_call(unit, step) else ())
                for step in unit.steps
            ),
            unit.verdict,
            unit.category,
            unit.blocked,
        )
        for unit in units
    ]


def _arguments_agree(units: Sequence[Unit], calls: Sequence[RecordedCall]) -> bool:
    """Each recorded call attaches to the next step that sent one, and its arguments must equal
    the step's. A count or argument mismatch means the sequence and the report disagree."""
    sending = [step for unit in units for step in unit.steps if _sent_a_call(unit, step)]
    if len(sending) != len(calls):
        return False
    return all(step.arguments == args for step, (_, args) in zip(sending, calls, strict=True))


def _sent_a_call(unit: Unit, step: Step) -> bool:
    # A blocked case and a chain blocked at its first step carry one step that reached no server,
    # so it has no output. Every step that ran carries the output the call returned.
    return not unit.blocked or bool(step.outputs)


def _lost_connection(response: ToolResponse) -> bool:
    return response.is_error and any(
        response.error_type == error_type and (content is None or response.content == content)
        for error_type, content in LOST_CONNECTION_RESPONSES
    )
