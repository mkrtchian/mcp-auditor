"""The no-LLM fix check the admission agent runs until a flaw reproduces, free of mcp_auditor.

Parity note: the nuisance twin of kit_driver.check_target. Where kit_driver calibrates a drawn
holdout target against the frozen list, the fix check plants the flaw's own witness at its own
coordinate (no holdout_places.json, no kept-records lookup) and reproduces it on the vulnerable
version, the flaw's patched version and, when it differs, the server's patched version. The
grading reuses the clean grammar (cve_proofs / cve_units) unchanged, entered synchronously like
kit_driver: one flaw at a time, no event loop, no evals/concurrency.

The verdict is a pure function of the exchanges each version records (`fix_check_result`), kept
apart from the launches so the record logic is tested with no Docker, as kit_driver keeps
dead_conditions apart from its _exercise. FixCheckResult mirrors nuisance_admission.FixCheckRecord
field for field; it is kit-local because the kit imports nothing from mcp_auditor and the admission
module reaches it through cve_baseline. A parity test pins the two field sets equal.
"""

import json
import os
import re
import tempfile
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Literal

from evals.cve_grammar import MechanismClass, PlantedTarget
from evals.cve_places import Place, Places
from evals.cve_planting import RANDOM_NONCES, NonceSource, PlantingHost, PlantingSpec
from evals.cve_planting import planting_spec as compute_planting_spec
from evals.cve_proofs import is_aimed, proofs_in
from evals.holdout_kit.kit_client import KitClient, KitMCPClient, docker_client_env
from evals.holdout_kit.kit_driver import Exchange, KitRecorder, unit_of
from evals.holdout_kit.kit_launch import LaunchShape, image_tag
from evals.holdout_kit.kit_target import KitBuilder

FixCheckExploit = Callable[[Places, KitClient], Awaitable[None]]


@dataclass(frozen=True)
class FixCheckTarget:
    flaw: str
    mechanism: MechanismClass | None
    aim: re.Pattern[str]
    witness: Place
    planting_host: PlantingHost
    builder: KitBuilder
    exploits: tuple[FixCheckExploit, ...]  # both agents' exploits: either surfacing counts
    benign_calls: tuple[FixCheckExploit, ...]  # one per tool, in the patched version
    vulnerable_service: str
    patched_service: str
    server_patched_service: str | None  # None when the server's patched version is the flaw's

    def planting_spec(self, nonces: NonceSource = RANDOM_NONCES) -> PlantingSpec:
        return compute_planting_spec((self.witness,), self.planting_host, nonces)


@dataclass(frozen=True)
class Exercised:
    nonces: Mapping[str, str]
    exploits: list[list[Exchange]]
    benign: list[Exchange]


@dataclass(frozen=True)
class FixCheckResult:
    source: Literal["fix_check", "holdout_calibration"]
    witness: str
    exploit_calls: list[str]
    vulnerable_surfaces: bool
    patched_surfaces: bool
    server_patched_surfaces: bool | None
    patched_benign_errored: bool

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


async def check_fix(target: FixCheckTarget) -> FixCheckResult:
    """Reproduce the flaw on each version and build the record. A launch failure has no verdict,
    so it raises rather than reading as a fixed flaw."""
    vulnerable = await _exercise(target, target.vulnerable_service)
    patched = await _exercise(target, target.patched_service)
    server_patched = (
        None
        if target.server_patched_service is None
        else await _exercise(target, target.server_patched_service)
    )
    return fix_check_result(target, vulnerable, patched, server_patched)


def fix_check_result(
    target: FixCheckTarget,
    vulnerable: Exercised,
    patched: Exercised,
    server_patched: Exercised | None,
) -> FixCheckResult:
    return FixCheckResult(
        source="fix_check",
        witness=vulnerable.nonces[target.witness.id],
        exploit_calls=_exploit_calls(vulnerable),
        vulnerable_surfaces=_surfaces(target, vulnerable),
        patched_surfaces=_surfaces(target, patched),
        server_patched_surfaces=(
            None if server_patched is None else _surfaces(target, server_patched)
        ),
        patched_benign_errored=(
            _benign_errored(patched)
            or (server_patched is not None and _benign_errored(server_patched))
        ),
    )


async def _exercise(target: FixCheckTarget, service: str) -> Exercised:
    spec = target.planting_spec()
    places: Places = {target.witness.id: target.witness}
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
                    for benign_call in target.benign_calls:
                        await benign_call(places, benign)
                    exploits: list[KitRecorder] = []
                    for exploit in target.exploits:
                        recorder = KitRecorder(client)
                        await exploit(places, recorder)
                        exploits.append(recorder)
        except Exception as exc:
            raise RuntimeError(f"the {service} version did not launch") from exc
    return Exercised(spec.nonces, [r.exchanges for r in exploits], benign.exchanges)


def _surfaces(target: FixCheckTarget, exercise: Exercised) -> bool:
    planted = PlantedTarget(target.mechanism, target.aim, exercise.nonces)
    return any(
        is_aimed(unit, target.aim) and bool(proofs_in(unit, planted))
        for unit in (unit_of(exchanges) for exchanges in exercise.exploits)
    )


def _exploit_calls(exercise: Exercised) -> list[str]:
    calls: dict[str, None] = {}
    for exploit in exercise.exploits:
        for tool, _, _ in exploit:
            calls.setdefault(tool, None)
    return list(calls)


def _benign_errored(exercise: Exercised) -> bool:
    return any(response.is_error for _, _, response in exercise.benign)
