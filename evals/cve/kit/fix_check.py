"""The no-LLM fix check the admission agent runs until a flaw reproduces, free of mcp_auditor.

Parity note: the nuisance counterpart of driver.check_target. Where driver checks the
calibration of a holdout target against the frozen list, the fix check plants the flaw's own
witness at its own coordinate (no detection_places.json, no kept-records lookup) and reproduces it
on the vulnerable version, the flaw's patched version and, when it differs, the server's patched
version. The grading reuses the clean grammar (evals.cve.proofs and units) unchanged. The builder
is entered synchronously, as in driver, so fix checks run side by side (`run_nuisance fix-check
--concurrency`) stand and tear down their launches one at a time, and the kit stays clear of
evals/concurrency.

The result is a pure function of the exchanges each version records (`fix_check_result`), kept
apart from the launches so the record logic is tested with no Docker, as driver keeps
not_live_reasons apart from its `_Exercise`. FixCheckResult mirrors
evals.cve.nuisance.admission.admission.FixCheckRecord field for field apart from what the
admission records and the kit does not observe (test_kit_isolation.py names those fields and pins
the rest equal), and beyond them its unreached_patched_exploits, the exploits that surface the
witness on the vulnerable version while a patched version's SDK rejects every call of them for a
missing required argument, which leave its witness unsurfaced whatever the fix and are empty on any
flaw that counts. It is kit-local so that a dossier copying the kit does not carry the admission
model and its import closure.
"""

import json
import re
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from typing import Literal

from evals.cve.grammar import FlawClass, PlantedTarget
from evals.cve.kit.argument_validation import (
    PatchedExploits,
    required_arguments,
    unreached_notes,
    unreached_reasons,
)
from evals.cve.kit.client import KitMCPClient
from evals.cve.kit.driver import Exchange, exploit_transcript, logged_exchanges, unit_of
from evals.cve.kit.launch import LaunchShape, image_tag
from evals.cve.kit.target import KitBuilder, KitExploit
from evals.cve.places import Place, Places
from evals.cve.planting import RANDOM_NONCES, NonceSource, PlantingHost, PlantingSpec
from evals.cve.planting import planting_spec as compute_planting_spec
from evals.cve.proofs import is_aimed, proofs_in

FixCheckExploit = KitExploit


@dataclass(frozen=True)
class FixCheckFixture:
    flaw: str
    effect_class: FlawClass | None
    aim: re.Pattern[str]
    witness: Place
    planting_host: PlantingHost
    builder: KitBuilder
    exploits: tuple[FixCheckExploit, ...]  # both agents' exploits: either surfacing counts
    benign_calls: tuple[FixCheckExploit, ...]  # one per tool, in the patched version
    vulnerable_service: str
    patched_service: str
    server_patched_service: str | None  # None when the server's patched version is the flaw's
    # The compose services the builder stands, refreshed before the check. None: the built services
    # of the run backend of the servers carrying the flaw.
    backend_services: tuple[str, ...] | None = None

    def planting_spec(self, nonces: NonceSource = RANDOM_NONCES) -> PlantingSpec:
        # The nuisance suite rule defines no `/work`: a fix check's is a directory baked into its
        # image.
        host = replace(self.planting_host, baked_work=True)
        return compute_planting_spec((self.witness,), host, nonces)


@dataclass(frozen=True)
class Exercised:
    nonces: Mapping[str, str]
    exploits: list[list[Exchange]]
    benign: list[Exchange]
    required: dict[str, frozenset[str]]  # per listed tool, the arguments its schema requires


@dataclass(frozen=True)
class FixCheckResult:
    source: Literal["fix_check", "detection_holdout_calibration"]
    witness: str
    exploit_calls: list[str]
    vulnerable_surfaces: bool
    patched_surfaces: bool
    server_patched_surfaces: bool | None
    patched_benign_errored: bool
    unreached_patched_exploits: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


async def check_fix(
    fixture: FixCheckFixture, show_exploit_responses: bool = False
) -> FixCheckResult:
    """Reproduce the flaw on each version and build the record, printing each benign response
    and, when asked, each exploit's responses. A launch failure has no result, so it raises
    rather than reading as a fixed flaw."""
    vulnerable = await _exercise_shown(fixture, fixture.vulnerable_service, show_exploit_responses)
    patched = await _exercise_shown(fixture, fixture.patched_service, show_exploit_responses)
    server_patched = (
        None
        if fixture.server_patched_service is None
        else await _exercise_shown(fixture, fixture.server_patched_service, show_exploit_responses)
    )
    for note in fix_check_notes(patched, server_patched):
        print(f"{fixture.flaw} {note}")
    return fix_check_result(fixture, vulnerable, patched, server_patched)


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
        unreached_patched_exploits=[
            reason
            for arm in _patched_arms(patched, server_patched)
            for reason in unreached_reasons(arm, _surfacing(fixture, vulnerable))
        ],
    )


def fix_check_notes(patched: Exercised, server_patched: Exercised | None) -> list[str]:
    """The patched exploit calls the pass condition does not read (see
    argument_validation.unreached_notes)."""
    return [note for arm in _patched_arms(patched, server_patched) for note in unreached_notes(arm)]


def _patched_arms(patched: Exercised, server_patched: Exercised | None) -> list[PatchedExploits]:
    arms = [PatchedExploits("patched version", patched.exploits, patched.required)]
    if server_patched is not None:
        arms.append(
            PatchedExploits(
                "server's patched version", server_patched.exploits, server_patched.required
            )
        )
    return arms


async def _exercise_shown(
    fixture: FixCheckFixture, service: str, show_exploit_responses: bool
) -> Exercised:
    # One print per version, so concurrent fix checks do not interleave within a transcript.
    exercise = await _exercise(fixture, service)
    if exercise.benign:
        print(benign_transcript(fixture.flaw, service, exercise))
    if show_exploit_responses and exercise.exploits:
        print(exploit_transcript(fixture.flaw, service, exercise.exploits))
    return exercise


def benign_transcript(flaw: str, service: str, exercise: Exercised) -> str:
    return "\n".join(
        f"{flaw} {service}: benign {tool} -> {'error' if response.is_error else 'ok'} "
        f"{response.content!r}"
        for tool, _, response in exercise.benign
    )


async def _exercise(fixture: FixCheckFixture, service: str) -> Exercised:
    spec = fixture.planting_spec()
    places: Places = {fixture.witness.id: fixture.witness}
    connected = False
    with tempfile.TemporaryFile("w+") as server_stderr:
        try:
            with fixture.builder(image_tag(service), spec, LaunchShape.NORMAL) as launch:
                async with KitMCPClient.connect(launch, errlog=server_stderr) as client:
                    connected = True
                    required = required_arguments(await client.list_tools())
                    benign: list[Exchange] = []
                    for call in fixture.benign_calls:
                        benign += await logged_exchanges(call, places, client)
                    exploits = [
                        await logged_exchanges(exploit, places, client)
                        for exploit in fixture.exploits
                    ]
        except Exception as exc:
            # Only a launch or connection failure reads as "did not launch"; an exploit that
            # raises once the client is up is the agent's bug and propagates as itself.
            if connected:
                raise
            raise RuntimeError(f"the {service} version did not launch") from exc
    return Exercised(spec.nonces, exploits, benign, required)


def _surfaces(fixture: FixCheckFixture, exercise: Exercised) -> bool:
    return bool(_surfacing(fixture, exercise))


def _surfacing(fixture: FixCheckFixture, exercise: Exercised) -> set[int]:
    classes: frozenset[FlawClass] = (
        frozenset() if fixture.effect_class is None else frozenset({fixture.effect_class})
    )
    planted = PlantedTarget(classes, fixture.aim, exercise.nonces)
    return {
        index
        for index, unit in enumerate(unit_of(exchanges) for exchanges in exercise.exploits)
        if is_aimed(unit, fixture.aim) and proofs_in(unit, planted)
    }


def _exploit_calls(exercise: Exercised) -> list[str]:
    calls: dict[str, None] = {}
    for exploit in exercise.exploits:
        for tool, _, _ in exploit:
            calls.setdefault(tool, None)
    return list(calls)


def _benign_errored(exercise: Exercised) -> bool:
    return any(response.is_error for _, _, response in exercise.benign)
