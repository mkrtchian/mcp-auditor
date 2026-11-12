"""The calibration check: runs each target's hand-written exploits and benign call with no LLM
on both the vulnerable and the patched version, and grades each through the grammar's own proof
and aim evaluation, every exploit its own unit.

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
from typing import IO, cast

from rich.markup import escape

from evals.cve.detection.targets import Target, TargetVersion
from evals.cve.environments import connect
from evals.cve.exchange_log import Exchange, ExchangeLog
from evals.cve.failure_text import FULL_DETAIL, ReportDetail
from evals.cve.grammar import GradedTarget, PlantedTarget, ProofKind
from evals.cve.places import Place, Places, kept_records
from evals.cve.proofs import is_aimed, proofs_in
from evals.cve.units import Unit, unit_of_exchanges
from evals.eval_display import console
from mcp_auditor.domain.ports import MCPClientPort

# A launch or handshake that fails is retried up to this many launches of the version: one
# observation of a version may take that many launches. A launch that ran is never retried.
PRE_RUN_LAUNCH_ATTEMPTS = 3


async def check_calibrations(
    targets: list[Target],
    check: Callable[[Target], Awaitable[bool]],
    ci: bool = False,
) -> bool:
    console.print("[bold]Calibration check[/bold] (no LLM): exploits and benign call per target\n")
    checked: list[Target] = []
    for target in targets:
        if ci and target.ci_skip_reason is not None:
            console.print(f"[yellow]skip[/yellow]  {target.flaw_id}: {target.ci_skip_reason}")
        else:
            checked.append(target)
    passed = await asyncio.gather(*(check(target) for target in checked))
    for target, passes in zip(checked, passed, strict=True):
        status = "[green]ok[/green]" if passes else "[red]out of calibration[/red]"
        console.print(f"{status}  {target.flaw_id}")
    all_pass = all(passed)
    if not all_pass:
        console.print(
            "\n[red]Some targets are out of calibration[/red]: fix fixture/exploit/benign call/aim."
        )
    return all_pass


def not_live_reasons(target: GradedTarget, exploits: Sequence[Unit], benign: Unit) -> list[str]:
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


def not_fixed_reasons(
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


async def check_target(
    target: Target, places: Places, *, report_detail: ReportDetail = FULL_DETAIL
) -> list[str]:
    """The out-of-calibration reasons of a target on both versions, empty when it is live and
    fixed: the no-LLM check the pre-run check (`session`, `holdout_run`) and the calibration check
    share. It resolves the kept records and checks the spec before any launch, so a configuration
    error (an unknown kept id, a planting_spec refusal) propagates instead of reading out of
    calibration, then exercises the vulnerable version and, once it is torn down, the patched one.
    `report_detail` sets how much server text the log shows."""
    records = kept_records(target.kept_places, places)
    target.planting_spec(records)
    exercise = _Exercise(target, records, places, report_detail)
    vulnerable = await first_launch(lambda: exercise.version(TargetVersion.VULNERABLE))
    if vulnerable is None:
        return [_launch_failed(TargetVersion.VULNERABLE)]
    reasons = not_live_reasons(
        _graded(target, vulnerable), _units(vulnerable.exploits), _unit(vulnerable.benign)
    )
    patched = await first_launch(lambda: exercise.version(TargetVersion.PATCHED))
    if patched is None:
        reasons.append(_launch_failed(TargetVersion.PATCHED))
    else:
        reasons += _not_fixed_reasons(target, patched)
    if reasons:
        _report_out_of_calibration(target.flaw_id, reasons, vulnerable, report_detail)
    return reasons


async def passes_calibration_check(target: Target, places: Places) -> bool:
    return not await check_target(target, places)


class NotLaunched(Exception):
    """A launch or handshake that failed: the one failure the pre-run check retries."""


async def first_launch[T](attempt: Callable[[], Awaitable[T]]) -> T | None:
    """What the first launch that ran observed, in up to `PRE_RUN_LAUNCH_ATTEMPTS` launches, or
    None when none of them launched."""
    for _ in range(PRE_RUN_LAUNCH_ATTEMPTS):
        try:
            return await attempt()
        except NotLaunched:
            continue
    return None


def _launch_failed(version: TargetVersion) -> str:
    return f"the {version.value} version did not launch"


@dataclass(frozen=True)
class _Exercised:
    nonces: Mapping[str, str]
    exploits: list[list[Exchange]]
    benign: list[Exchange]


def _not_fixed_reasons(target: Target, patched: _Exercised) -> list[str]:
    return not_fixed_reasons(
        _graded(target, patched), _units(patched.exploits), _any_error(patched.benign)
    )


@dataclass(frozen=True)
class _Exercise:
    target: Target
    records: tuple[Place, ...]
    places: Places
    report_detail: ReportDetail

    async def version(self, version: TargetVersion) -> _Exercised | None:
        # A failure before the server is up raises NotLaunched, for a retry. Any later failure
        # reads as not live, and the next target still runs. A server that dies before the
        # handshake only says "Connection closed", so its stderr carries the cause. Reports print
        # with no await between their lines, so targets checked side by side do not interleave.
        with tempfile.TemporaryFile("w+") as server_stderr:
            launched = False
            try:
                async with (
                    self.target.launched(self.records, version=version) as planted,
                    connect(planted.launch, server_stderr) as client,
                ):
                    launched = True
                    benign, exploits = await self._calls(client)
            except Exception as exc:
                _report_error(self.target.flaw_id, exc, server_stderr, self.report_detail)
                if not launched:
                    raise NotLaunched from exc
                return None
        return _Exercised(planted.nonces, exploits, benign)

    async def _calls(self, client: MCPClientPort) -> tuple[list[Exchange], list[list[Exchange]]]:
        benign = ExchangeLog(client)
        await self.target.benign(self.places, benign)
        exploits: list[list[Exchange]] = []
        for exploit in self.target.exploits:
            log = ExchangeLog(client)
            await exploit(self.places, log)
            exploits.append(log.exchanges)
        return benign.exchanges, exploits


def _graded(target: Target, exercised: _Exercised) -> PlantedTarget:
    return PlantedTarget(target.classes, target.aim, exercised.nonces)


def _units(exploits: list[list[Exchange]]) -> list[Unit]:
    return [_unit(exchanges) for exchanges in exploits]


def _any_error(exchanges: list[Exchange]) -> bool:
    return any(response.is_error for _, _, response in exchanges)


def _unit(exchanges: list[Exchange]) -> Unit:
    return unit_of_exchanges([(args, response.content) for _, args, response in exchanges])


def _report_error(
    flaw_id: str, exc: Exception, server_stderr: IO[str], report_detail: ReportDetail
) -> None:
    if report_detail.shows_server_text:
        cause = _root_cause(exc)
        reason = f"{type(cause).__name__}: {cause}"
    else:
        reason = report_detail.describe(exc)
    console.print(f"[yellow]{flaw_id} calibration check error:[/yellow] {escape(reason)}")
    for line in report_detail.server_lines(_tail(server_stderr)):
        console.print(f"  {line}", markup=False, highlight=False)


def _tail(server_stderr: IO[str], lines: int = 10) -> list[str]:
    server_stderr.seek(0)
    return server_stderr.read().splitlines()[-lines:]


def _root_cause(exc: BaseException) -> BaseException:
    if not isinstance(exc, BaseExceptionGroup):
        return exc
    group = cast("BaseExceptionGroup[BaseException]", exc)
    return _root_cause(group.exceptions[0]) if len(group.exceptions) == 1 else group


def _report_out_of_calibration(
    flaw_id: str, reasons: list[str], vulnerable: _Exercised, report_detail: ReportDetail
) -> None:
    for reason in reasons:
        console.print(f"[yellow]{flaw_id} out of calibration:[/yellow] {escape(reason)}")
    dumps = [(f"{flaw_id} exploit {index}", ex) for index, ex in enumerate(vulnerable.exploits)]
    dumps.append((f"{flaw_id} benign call", vulnerable.benign))
    for label, exchanges in report_detail.server_lines(dumps):
        _dump_exchanges(label, exchanges)


def _dump_exchanges(label: str, exchanges: list[Exchange]) -> None:
    console.print(f"[yellow]{label}, tool exchanges:[/yellow]")
    for name, args, response in exchanges:
        marker = "error" if response.is_error else "ok"
        body = response.content[:500]
        console.print(f"  {name}({json.dumps(args)}) -> [{marker}] {body!r}", markup=False)
