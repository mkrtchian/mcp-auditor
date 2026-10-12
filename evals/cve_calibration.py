"""Calibration: replays each target's hand-written exploits and benign call with no LLM on both
the vulnerable and the patched version, and grades each through the grammar's own proof and aim
evaluation, every exploit its own unit.

On the vulnerable version a target is live when it keeps at least one place, the nonce of every
kept place surfaces in at least one exploit, every exploit reads as aimed, and its benign call, a
call inside the declared scope, surfaces no nonce and does not read as aimed. On the patched
version no exploit surfaces a nonce and the benign call returns no error. The benign call runs
first, so the negative control reads a state the exploits have not touched, and the patched launch
starts only once the vulnerable one is torn down.
"""

import asyncio
import json
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Any, cast

from rich.console import Console
from rich.markup import escape

from evals.cve_environments import connect
from evals.cve_grammar import GradedTarget, PlantedTarget, ProofKind
from evals.cve_places import Place, Places, kept_records
from evals.cve_proofs import is_aimed, proofs_in
from evals.cve_targets import CVETarget, TargetVersion
from evals.cve_units import Unit, unit_of_exchanges
from mcp_auditor.domain.models import ToolDefinition, ToolResponse
from mcp_auditor.domain.ports import MCPClientPort

console = Console()

type Exchange = tuple[str, dict[str, Any], ToolResponse]


async def calibrate_all(
    targets: list[CVETarget],
    calibrate: Callable[[CVETarget], Awaitable[bool]],
    ci: bool = False,
) -> bool:
    console.print("[bold]Calibration[/bold] (no LLM): exploit and benign call per target\n")
    calibrated: list[CVETarget] = []
    for target in targets:
        if ci and target.ci_skip_reason is not None:
            console.print(f"[yellow]skip[/yellow]  {target.cve_id}: {target.ci_skip_reason}")
        else:
            calibrated.append(target)
    verdicts = await asyncio.gather(*(calibrate(target) for target in calibrated))
    for target, live in zip(calibrated, verdicts, strict=True):
        status = "[green]live[/green]" if live else "[red]dead[/red]"
        console.print(f"{status}  {target.cve_id}")
    all_live = all(verdicts)
    if not all_live:
        console.print(
            "\n[red]Some fixtures calibrate dead[/red]: fix fixture/exploit/benign call/aim."
        )
    return all_live


def dead_conditions(target: GradedTarget, exploits: Sequence[Unit], benign: Unit) -> list[str]:
    nonce = ProofKind.PLANTED_NONCE.value
    conditions: list[str] = []
    if not target.nonces:
        conditions.append("keeps no place")
    for index, exploit in enumerate(exploits):
        if not is_aimed(exploit, target.aim):
            conditions.append(f"exploit {index} not aimed")
    surfaced = {place for exploit in exploits for place in proofs_in(exploit, target)}
    for place_id in sorted(target.nonces):
        if place_id not in surfaced:
            conditions.append(f"exploit surfaces no nonce for {place_id}")
    if proofs_in(benign, target):
        conditions.append(f"negative control: benign call surfaces {nonce}")
    if is_aimed(benign, target.aim):
        conditions.append("negative control: benign call reads as aimed")
    return conditions


def patched_dead_conditions(
    target: GradedTarget, exploits: Sequence[Unit], benign_errored: bool
) -> list[str]:
    conditions = [
        f"patched: exploit {index} still surfaces {place_id}"
        for index, exploit in enumerate(exploits)
        for place_id in sorted(proofs_in(exploit, target))
    ]
    if benign_errored:
        conditions.append("patched: benign call errored")
    return conditions


async def calibrate_one(target: CVETarget, places: Places) -> bool:
    # An unknown kept id or a planting_spec refusal is a configuration error, resolved and
    # checked before any launch, so it propagates instead of reading dead.
    records = kept_records(target.kept_places, places)
    target.planting_spec(records)
    vulnerable = await _exercise(target, records, TargetVersion.VULNERABLE)
    if vulnerable is None:
        return False
    conditions = dead_conditions(
        _graded(target, vulnerable), _units(vulnerable.exploits), _unit(vulnerable.benign)
    )
    patched = await _exercise(target, records, TargetVersion.PATCHED)
    if patched is None:
        return False
    conditions += patched_dead_conditions(
        _graded(target, patched), _units(patched.exploits), _any_error(patched.benign)
    )
    if conditions:
        _report_dead(target.cve_id, conditions, vulnerable.exploits, vulnerable.benign)
    return not conditions


@dataclass(frozen=True)
class _Exercised:
    nonces: Mapping[str, str]
    exploits: list[list[Exchange]]
    benign: list[Exchange]


async def _exercise(
    target: CVETarget, records: tuple[Place, ...], version: TargetVersion
) -> _Exercised | None:
    # Any failure reads as not live and the next target still runs. A server that dies before
    # the handshake only says "Connection closed", so its stderr carries the cause. Reports
    # print with no await between their lines, so targets calibrated side by side do not
    # interleave them.
    with tempfile.TemporaryFile("w+") as server_stderr:
        try:
            async with (
                target.launched(records, version=version) as planted,
                connect(planted.launch, server_stderr) as client,
            ):
                benign = RecordingClient(client)
                await target.benign(benign)
                exploits: list[RecordingClient] = []
                for exploit in target.exploits:
                    recorder = RecordingClient(client)
                    await exploit(recorder)
                    exploits.append(recorder)
        except Exception as exc:
            cause = _root_cause(exc)
            reason = f"{type(cause).__name__}: {cause}"
            console.print(f"[yellow]{target.cve_id} calibration error:[/yellow] {escape(reason)}")
            _print_tail(server_stderr)
            return None
    return _Exercised(planted.nonces, [r.exchanges for r in exploits], benign.exchanges)


def _graded(target: CVETarget, exercised: _Exercised) -> PlantedTarget:
    return PlantedTarget(target.mechanism, target.aim, exercised.nonces)


def _units(exploits: list[list[Exchange]]) -> list[Unit]:
    return [_unit(exchanges) for exchanges in exploits]


def _any_error(exchanges: list[Exchange]) -> bool:
    return any(response.is_error for _, _, response in exchanges)


def _unit(exchanges: list[Exchange]) -> Unit:
    return unit_of_exchanges([(args, response.content) for _, args, response in exchanges])


def _root_cause(exc: BaseException) -> BaseException:
    if not isinstance(exc, BaseExceptionGroup):
        return exc
    group = cast("BaseExceptionGroup[BaseException]", exc)
    return _root_cause(group.exceptions[0]) if len(group.exceptions) == 1 else group


def _print_tail(server_stderr: IO[str], lines: int = 10) -> None:
    server_stderr.seek(0)
    for line in server_stderr.read().splitlines()[-lines:]:
        console.print(f"  {line}", markup=False, highlight=False)


class RecordingClient:
    """Records each tool call and its response, so calibration grades what the server
    returned and a dead fixture can be post-mortemed: the exchanges show which step
    swallowed the proof (a server-side error-as-value or an empty response), or what the
    benign call surfaced."""

    def __init__(self, inner: MCPClientPort) -> None:
        self._inner = inner
        self.exchanges: list[Exchange] = []

    async def list_tools(self) -> list[ToolDefinition]:
        return await self._inner.list_tools()

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        response = await self._inner.call_tool(name, args)
        self.exchanges.append((name, args, response))
        return response


def _report_dead(
    cve_id: str, conditions: list[str], exploits: list[list[Exchange]], benign: list[Exchange]
) -> None:
    for condition in conditions:
        console.print(f"[yellow]{cve_id} dead:[/yellow] {escape(condition)}")
    for index, exchanges in enumerate(exploits):
        _dump_exchanges(f"{cve_id} exploit {index}", exchanges)
    _dump_exchanges(f"{cve_id} benign call", benign)


def _dump_exchanges(label: str, exchanges: list[Exchange]) -> None:
    console.print(f"[yellow]{label}, tool exchanges:[/yellow]")
    for name, args, response in exchanges:
        marker = "error" if response.is_error else "ok"
        body = response.content[:500]
        console.print(f"  {name}({json.dumps(args)}) -> [{marker}] {body!r}", markup=False)
