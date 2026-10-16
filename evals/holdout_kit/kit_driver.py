"""The no-LLM calibration check the agent runs until a fixture reproduces, free of mcp_auditor.

Parity note: the acceptance twin is evals/cve_calibration.check_target (with dead_conditions /
patched_dead_conditions) and evals/cve_recording_client.RecordingClient. Rewritten on the kit
client and KitTarget; the grading logic reuses the clean grammar (cve_grammar / cve_proofs /
cve_units) unchanged, so the kit grades exactly as the benchmark does. Unlike the twin, the
builder is entered synchronously (no worker thread): the kit calibrates one target at a time, so
there is no event loop to keep free, and the kit stays clear of evals/concurrency.
"""

import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from evals.cve_grammar import GradedTarget, PlantedTarget, ProofKind
from evals.cve_places import Place, Places, kept_records
from evals.cve_proofs import is_aimed, proofs_in
from evals.cve_units import Unit, unit_of_exchanges
from evals.holdout_kit.kit_client import (
    KitClient,
    KitMCPClient,
    KitResponse,
    KitTool,
    docker_client_env,
)
from evals.holdout_kit.kit_launch import LaunchShape, image_tag
from evals.holdout_kit.kit_target import KitTarget

type Exchange = tuple[str, dict[str, Any], KitResponse]


class TargetVersion(StrEnum):
    VULNERABLE = "vulnerable"
    PATCHED = "patched"


class KitRecorder:
    """The role RecordingClient plays, rewritten without MCPClientPort: every call recorded so a
    dead fixture can be read back from the exchanges."""

    def __init__(self, inner: KitClient) -> None:
        self._inner = inner
        self.exchanges: list[Exchange] = []

    async def list_tools(self) -> list[KitTool]:
        return await self._inner.list_tools()

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        response = await self._inner.call_tool(name, args)
        self.exchanges.append((name, args, response))
        return response


async def check_target(target: KitTarget, places: Places) -> list[str]:
    """The dead conditions of a target on both versions, empty when it is live. Resolves the kept
    records and checks the spec before any launch, exercises the vulnerable version, then the
    patched one once it is torn down."""
    records = kept_records(target.kept_places, places)
    target.planting_spec(records)
    vulnerable = await _exercise(target, records, TargetVersion.VULNERABLE, places)
    if vulnerable is None:
        return [_launch_failed(TargetVersion.VULNERABLE)]
    conditions = dead_conditions(
        _graded(target, vulnerable), _units(vulnerable.exploits), _unit(vulnerable.benign)
    )
    patched = await _exercise(target, records, TargetVersion.PATCHED, places)
    if patched is None:
        conditions.append(_launch_failed(TargetVersion.PATCHED))
    else:
        benign_errored = _any_error(patched.benign)
        conditions += patched_dead_conditions(
            _graded(target, patched), _units(patched.exploits), benign_errored
        )
    return conditions


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


@dataclass(frozen=True)
class _Exercised:
    nonces: Mapping[str, str]
    exploits: list[list[Exchange]]
    benign: list[Exchange]


async def _exercise(
    target: KitTarget,
    records: tuple[Place, ...],
    version: TargetVersion,
    places: Places,
) -> _Exercised | None:
    spec = target.planting_spec(records)
    service = target.patched_image if version is TargetVersion.PATCHED else target.server_image
    with tempfile.TemporaryFile("w+") as server_stderr:
        try:
            with target.builder(image_tag(service), spec, LaunchShape.NORMAL) as launch:
                async with KitMCPClient.connect(
                    launch.command,
                    launch.args,
                    env=docker_client_env(os.environ),
                    errlog=server_stderr,
                ) as client:
                    benign = KitRecorder(client)
                    await target.benign(places, benign)
                    exploits: list[KitRecorder] = []
                    for exploit in target.exploits:
                        recorder = KitRecorder(client)
                        await exploit(places, recorder)
                        exploits.append(recorder)
        except Exception:
            return None
    return _Exercised(spec.nonces, [r.exchanges for r in exploits], benign.exchanges)


def _graded(target: KitTarget, exercised: _Exercised) -> PlantedTarget:
    return PlantedTarget(target.mechanism, target.aim, exercised.nonces)


def _units(exploits: list[list[Exchange]]) -> list[Unit]:
    return [_unit(exchanges) for exchanges in exploits]


def _unit(exchanges: list[Exchange]) -> Unit:
    return unit_of_exchanges([(args, response.content) for _, args, response in exchanges])


def _any_error(exchanges: list[Exchange]) -> bool:
    return any(response.is_error for _, _, response in exchanges)


def _launch_failed(version: TargetVersion) -> str:
    return f"the {version.value} version did not launch"
