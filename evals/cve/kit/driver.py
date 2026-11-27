"""The no-LLM calibration check the agent runs until a fixture reproduces, free of mcp_auditor.

Parity note: it mirrors evals/cve/detection/calibration_check.check_target and
evals/cve/exchange_log.ExchangeLog, rewritten on the kit client and KitTarget. not_live_reasons
and not_fixed_reasons are defined here and the repository's calibration check imports them, so
the grammar golden master and the detection unit tests pin what the kit grades. The grading
logic reuses the clean grammar (evals.cve.grammar, proofs and units) unchanged. Unlike the
repository's calibration check, the builder is entered synchronously (no worker thread): the kit
checks one target's calibration at a time, so there is no event loop to keep free, and the kit
stays clear of evals/concurrency. Beyond the repository's check, `check_target` reports a launch
that runs as any account but the unprivileged one or the one named after a nonce, read from the
Docker options the builder yields.
"""

import json
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from evals.cve.grammar import GradedTarget, PlantedTarget, ProofKind
from evals.cve.kit.argument_validation import (
    PatchedExploits,
    required_arguments,
    unreached_notes,
    unreached_reasons,
)
from evals.cve.kit.client import KitClient, KitMCPClient, KitResponse, KitTool
from evals.cve.kit.launch import LaunchShape, image_tag
from evals.cve.kit.target import KitExploit, KitTarget
from evals.cve.places import Place, Places, kept_records
from evals.cve.planting_base import UNPRIVILEGED_GID, UNPRIVILEGED_UID, PlantingSpec
from evals.cve.proofs import is_aimed, proofs_in
from evals.cve.units import Unit, unit_of_exchanges

type Exchange = tuple[str, dict[str, Any], KitResponse]


class TargetVersion(StrEnum):
    VULNERABLE = "vulnerable"
    PATCHED = "patched"


class KitExchangeLog:
    """The role ExchangeLog plays, rewritten without MCPClientPort: every call kept so a
    target out of calibration can be read back from the exchanges."""

    def __init__(self, inner: KitClient) -> None:
        self._inner = inner
        self.exchanges: list[Exchange] = []

    async def list_tools(self) -> list[KitTool]:
        return await self._inner.list_tools()

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        response = await self._inner.call_tool(name, args)
        self.exchanges.append((name, args, response))
        return response


async def check_target(
    target: KitTarget, places: Places, show_exploit_responses: bool = False
) -> list[str]:
    """The out-of-calibration reasons of a target on both versions, empty when it is live and
    fixed. Resolves the kept records and checks the spec before any launch, exercises the
    vulnerable version, then the patched one once it is torn down. `show_exploit_responses`
    prints each exploit's exchanges on each version, the vulnerable one first, for reading the
    patched responses beside the vulnerable ones."""
    records = kept_records(target.kept_places, places)
    target.planting_spec(records)
    exercise = _Exercise(target, records, places, show_exploit_responses)
    vulnerable = await exercise.version(TargetVersion.VULNERABLE)
    if vulnerable is None:
        return [_launch_failed(TargetVersion.VULNERABLE)]
    reasons = not_live_reasons(
        _graded(target, vulnerable), _units(vulnerable.exploits), unit_of(vulnerable.benign)
    )
    reasons += _account_conditions(TargetVersion.VULNERABLE, vulnerable)
    patched = await exercise.version(TargetVersion.PATCHED)
    if patched is None:
        reasons.append(_launch_failed(TargetVersion.PATCHED))
    else:
        benign_errored = _any_error(patched.benign)
        reasons += not_fixed_reasons(
            _graded(target, patched), _units(patched.exploits), benign_errored
        )
        reasons += _unreached(target, vulnerable, patched)
        reasons += _account_conditions(TargetVersion.PATCHED, patched)
    return reasons


def _unreached(target: KitTarget, vulnerable: "_Exercised", patched: "_Exercised") -> list[str]:
    exploits = PatchedExploits("patched", patched.exploits, patched.required)
    for note in unreached_notes(exploits):
        print(f"{target.flaw_id} {note}")
    surfacing = surfacing_exploits(_graded(target, vulnerable), _units(vulnerable.exploits))
    return unreached_reasons(exploits, surfacing)


def surfacing_exploits(target: GradedTarget, exploits: Sequence[Unit]) -> set[int]:
    """The indices of the exploits whose unit surfaces a planted nonce."""
    return {index for index, exploit in enumerate(exploits) if proofs_in(exploit, target)}


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


@dataclass(frozen=True)
class _Exercised:
    spec: PlantingSpec
    options: list[str]  # the launch's Docker options, before the image
    exploits: list[list[Exchange]]
    benign: list[Exchange]
    required: dict[str, frozenset[str]]  # per listed tool, the arguments its schema requires


@dataclass(frozen=True)
class _Exercise:
    target: KitTarget
    records: tuple[Place, ...]
    places: Places
    show_exploit_responses: bool

    async def version(self, version: TargetVersion) -> _Exercised | None:
        target = self.target
        spec = target.planting_spec(self.records)
        service = target.patched_image if version is TargetVersion.PATCHED else target.server_image
        image = image_tag(service)
        with tempfile.TemporaryFile("w+") as server_stderr:
            try:
                with target.builder(image, spec, LaunchShape.NORMAL) as launch:
                    options = options_before_image(launch.args, image)
                    async with KitMCPClient.connect(launch, errlog=server_stderr) as client:
                        required = required_arguments(await client.list_tools())
                        benign, exploits = await self._calls(client)
            except Exception:
                return None
        if self.show_exploit_responses and exploits:
            print(exploit_transcript(target.flaw_id, version.value, exploits))
        return _Exercised(spec, options, exploits, benign, required)

    async def _calls(self, client: KitClient) -> tuple[list[Exchange], list[list[Exchange]]]:
        benign = await logged_exchanges(self.target.benign, self.places, client)
        exploits = [
            await logged_exchanges(exploit, self.places, client) for exploit in self.target.exploits
        ]
        return benign, exploits


async def logged_exchanges(call: KitExploit, places: Places, client: KitClient) -> list[Exchange]:
    log = KitExchangeLog(client)
    await call(places, log)
    return log.exchanges


def exploit_transcript(flaw: str, label: str, exploits: Sequence[list[Exchange]]) -> str:
    """Each exploit's calls on one version, with their arguments and responses cut at
    _SHOWN_CHARACTERS, labelled by the version or service."""
    return "\n".join(
        f"{flaw} {label}: exploit {index} {tool}({json.dumps(arguments)}) -> "
        f"{'error' if response.is_error else 'ok'} {response.content[:_SHOWN_CHARACTERS]!r}"
        for index, exploit in enumerate(exploits)
        for tool, arguments, response in exploit
    )


_SHOWN_CHARACTERS = 500  # as the calibration check's exchange dumps cut a response


def options_before_image(args: Sequence[str], image: str) -> list[str]:
    """The Docker options of a launch: a server argument after the image may spell `-u` or
    `--user` for its own purpose."""
    return list(args[: args.index(image)]) if image in args else list(args)


def _account_conditions(version: TargetVersion, exercised: _Exercised) -> list[str]:
    condition = launch_user_condition(version, exercised.options, exercised.spec)
    return [] if condition is None else [condition]


def launch_user_condition(
    version: TargetVersion, options: Sequence[str], spec: PlantingSpec
) -> str | None:
    """A builder the agent writes can bypass the planted user, so the launch's own options are
    read: the target runs as the unprivileged account or as the account named after a nonce."""
    user = _last_user(options)
    if user is None:
        return f"{version.value}: the launch sets no --user"
    allowed = {f"{UNPRIVILEGED_UID}:{UNPRIVILEGED_GID}"}
    if spec.account is not None:
        allowed.add(f"{spec.account.uid}:{spec.account.gid}")
    if user in allowed:
        return None
    return f"{version.value}: the launch runs as {user}, not the unprivileged account"


def _last_user(options: Sequence[str]) -> str | None:
    # Every spelling Docker accepts: `--user <v>`, `--user=<v>`, `-u <v>`, `-u=<v>`, `-u<v>`.
    user = None
    tokens = iter(options)
    for option in tokens:
        if option in ("--user", "-u"):
            user = next(tokens, None)
        elif option.startswith(("--user=", "-u=")):
            user = option.partition("=")[2]
        elif option.startswith("-u"):
            user = option.removeprefix("-u")
    return user


def _graded(target: KitTarget, exercised: _Exercised) -> PlantedTarget:
    return PlantedTarget(target.classes, target.aim, exercised.spec.nonces)


def _units(exploits: list[list[Exchange]]) -> list[Unit]:
    return [unit_of(exchanges) for exchanges in exploits]


def unit_of(exchanges: list[Exchange]) -> Unit:
    return unit_of_exchanges([(args, response.content) for _, args, response in exchanges])


def _any_error(exchanges: list[Exchange]) -> bool:
    return any(response.is_error for _, _, response in exchanges)


def _launch_failed(version: TargetVersion) -> str:
    return f"the {version.value} version did not launch"
