"""The no-LLM fix check the admission agent runs until a flaw reproduces, free of mcp_auditor.

Parity note: the nuisance counterpart of driver.check_target. Where driver checks the
calibration of a holdout target against the frozen list, the fix check plants the flaw's own
witness at its own coordinate (no holdout_places.json, no kept-records lookup) and reproduces it
on the vulnerable version, the flaw's patched version and, when it differs, the server's patched
version. The
grading reuses the clean grammar (cve_proofs / cve_units) unchanged, entered synchronously like
driver: one flaw at a time, no event loop, no evals/concurrency.

The result is a pure function of the exchanges each version records (`fix_check_result`), kept
apart from the launches so the record logic is tested with no Docker, as driver keeps
dead_conditions apart from its _exercise. FixCheckResult mirrors nuisance_admission.FixCheckRecord
field for field, except relies_on_relaying_stand_in, a judgment the admission records and the kit
does not observe; it is kit-local because the kit imports nothing from mcp_auditor and the admission
module reaches it through evals.cve.detection.baseline. A parity test pins the two field sets equal.
"""

import json
import os
import re
import tempfile
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, dataclass, replace
from typing import Literal

from evals.cve.kit.client import KitClient, KitMCPClient, docker_client_env
from evals.cve.kit.driver import Exchange, KitExchangeLog, unit_of
from evals.cve.kit.launch import LaunchShape, image_tag
from evals.cve.kit.target import KitBuilder
from evals.cve_grammar import MechanismClass, PlantedTarget
from evals.cve_places import Place, Places
from evals.cve_planting import RANDOM_NONCES, NonceSource, PlantingHost, PlantingSpec
from evals.cve_planting import planting_spec as compute_planting_spec
from evals.cve_proofs import is_aimed, proofs_in

FixCheckExploit = Callable[[Places, KitClient], Awaitable[None]]


@dataclass(frozen=True)
class FixCheckFixture:
    flaw: str
    effect_class: MechanismClass | None
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
        # The nuisance rule defines no `/work`: a fix check's is a directory baked into its image.
        host = replace(self.planting_host, baked_work=True)
        return compute_planting_spec((self.witness,), host, nonces)


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


async def check_fix(fixture: FixCheckFixture) -> FixCheckResult:
    """Reproduce the flaw on each version and build the record. A launch failure has no result,
    so it raises rather than reading as a fixed flaw."""
    vulnerable = await _exercise_shown(fixture, fixture.vulnerable_service)
    patched = await _exercise_shown(fixture, fixture.patched_service)
    server_patched = (
        None
        if fixture.server_patched_service is None
        else await _exercise_shown(fixture, fixture.server_patched_service)
    )
    return fix_check_result(fixture, vulnerable, patched, server_patched)


def benign_transcript(flaw: str, service: str, exercise: Exercised) -> str:
    return "\n".join(
        f"{flaw} {service}: benign {tool} -> {'error' if response.is_error else 'ok'} "
        f"{response.content!r}"
        for tool, _, response in exercise.benign
    )


def fix_check_result(
    fixture: FixCheckFixture,
    vulnerable: Exercised,
    patched: Exercised,
    server_patched: Exercised | None,
) -> FixCheckResult:
    return FixCheckResult(
        source="fix_check",
        witness=vulnerable.nonces[fixture.witness.id],
        exploit_calls=_exploit_calls(vulnerable),
        vulnerable_surfaces=_surfaces(fixture, vulnerable),
        patched_surfaces=_surfaces(fixture, patched),
        server_patched_surfaces=(
            None if server_patched is None else _surfaces(fixture, server_patched)
        ),
        patched_benign_errored=(
            _benign_errored(patched)
            or (server_patched is not None and _benign_errored(server_patched))
        ),
    )


async def _exercise_shown(fixture: FixCheckFixture, service: str) -> Exercised:
    # One print per version, so concurrent fix checks do not interleave within a transcript.
    exercise = await _exercise(fixture, service)
    if exercise.benign:
        print(benign_transcript(fixture.flaw, service, exercise))
    return exercise


async def _exercise(fixture: FixCheckFixture, service: str) -> Exercised:
    spec = fixture.planting_spec()
    places: Places = {fixture.witness.id: fixture.witness}
    connected = False
    with tempfile.TemporaryFile("w+") as server_stderr:
        try:
            with fixture.builder(image_tag(service), spec, LaunchShape.NORMAL) as launch:
                async with KitMCPClient.connect(
                    launch.command,
                    launch.args,
                    env=docker_client_env(os.environ),
                    errlog=server_stderr,
                ) as client:
                    connected = True
                    benign = KitExchangeLog(client)
                    for benign_call in fixture.benign_calls:
                        await benign_call(places, benign)
                    exploits: list[KitExchangeLog] = []
                    for exploit in fixture.exploits:
                        exploit_log = KitExchangeLog(client)
                        await exploit(places, exploit_log)
                        exploits.append(exploit_log)
        except Exception as exc:
            # Only a launch or connection failure reads as "did not launch"; an exploit that
            # raises once the client is up is the agent's bug and propagates as itself.
            if connected:
                raise
            raise RuntimeError(f"the {service} version did not launch") from exc
    return Exercised(spec.nonces, [r.exchanges for r in exploits], benign.exchanges)


def _surfaces(fixture: FixCheckFixture, exercise: Exercised) -> bool:
    mechanisms: frozenset[MechanismClass] = (
        frozenset() if fixture.effect_class is None else frozenset({fixture.effect_class})
    )
    planted = PlantedTarget(mechanisms, fixture.aim, exercise.nonces)
    return any(
        is_aimed(unit, fixture.aim) and bool(proofs_in(unit, planted))
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
