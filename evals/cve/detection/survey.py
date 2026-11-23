"""Survey (`--survey`, no LLM): plant every in-scope candidate place and report, per candidate,
what the exploits surface on the vulnerable version, what the benign call surfaces there, and what
the exploits surface on the patched version. It gives no live or fixed result and never fails. It
feeds the choice of each target's kept places, which reads the coordinates and is not done here.

Candidates are planted in groups that cannot break a launch, computed before any launch from the
planting host: the file, env and http_endpoint kinds together (file places with equal or nested
paths apart, http_endpoint places with the same host apart), each hostname and each account place
alone. A candidate the launch cannot hold, and an unplaceable one, is set apart as not plantable.
A combined group whose launch fails is retried one launch per place, and a place whose own launch
fails is reported as not surveyed. The report prints place ids and families only.
"""

import asyncio
import tempfile
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from rich.console import Console

from evals.cve.detection.calibration_check import logged_exchanges, unit_of
from evals.cve.detection.targets import Target, TargetVersion
from evals.cve.environments import connect
from evals.cve.exchange_log import Exchange
from evals.cve.grammar import PlantedTarget
from evals.cve.places import Place, PlaceKind, Places
from evals.cve.planting import RANDOM_NONCES, NonceSource, PlantingHost, planting_spec
from evals.cve.proofs import proofs_in

console = Console()

_ALONE = frozenset({PlaceKind.HOSTNAME, PlaceKind.ACCOUNT})


@dataclass(frozen=True)
class SurveyGroups:
    groups: list[tuple[Place, ...]]
    not_plantable: list[Place]


async def survey_all(
    targets: Sequence[Target], survey: Callable[[Target], Awaitable["TargetSurvey"]]
) -> None:
    console.print("[bold]Survey[/bold] (no LLM): candidate places per target\n")
    surveys = await asyncio.gather(*(survey(target) for target in targets))
    for result in surveys:
        _report(result)


@dataclass(frozen=True)
class PlaceFacts:
    place: Place
    surfaced_by_exploit: bool
    surfaced_by_benign_call: bool
    surfaced_on_patched: bool


@dataclass(frozen=True)
class TargetSurvey:
    flaw_id: str
    facts: list[PlaceFacts]
    not_plantable: list[Place]
    not_surveyed: list[Place]


async def survey_one(target: Target, places: Places) -> TargetSurvey:
    candidates = candidates_for(places, target.reaches)
    grouped = survey_groups(candidates, target.planting_host, RANDOM_NONCES)
    facts: list[PlaceFacts] = []
    not_surveyed: list[Place] = []
    for group in grouped.groups:
        surveyed = await _survey_group(target, group, places)
        if surveyed is not None:
            facts += surveyed
        else:
            for place in group:  # retry one launch per place so one bad candidate hides no other
                single = await _survey_group(target, (place,), places)
                facts += single if single is not None else []
                if single is None:
                    not_surveyed.append(place)
    return TargetSurvey(target.flaw_id, facts, grouped.not_plantable, not_surveyed)


def candidates_for(places: Places, reaches: frozenset[str]) -> list[Place]:
    ordered = (places[place_id] for place_id in sorted(places))
    return [place for place in ordered if place.reaches & reaches]


def survey_groups(
    candidates: Sequence[Place], host: PlantingHost, nonces: NonceSource
) -> SurveyGroups:
    plantable: list[Place] = []
    not_plantable: list[Place] = []
    for place in candidates:
        (not_plantable if _refused_alone(place, host, nonces) else plantable).append(place)
    singles = [(place,) for place in plantable if place.kind in _ALONE]
    combined = _pack([place for place in plantable if place.kind not in _ALONE], host, nonces)
    return SurveyGroups(singles + combined, not_plantable)


async def _survey_group(
    target: Target, group: tuple[Place, ...], places: Places
) -> list[PlaceFacts] | None:
    target.planting_spec(group)  # a refusal the grouping should have prevented crashes the survey
    planted_group = _PlantedGroup(target, group, places)
    vulnerable = await planted_group.surfaced(TargetVersion.VULNERABLE, benign=True)
    if vulnerable is None:
        return None
    patched = await planted_group.surfaced(TargetVersion.PATCHED, benign=False)
    if patched is None:
        return None
    return [
        PlaceFacts(
            place,
            surfaced_by_exploit=place.id in vulnerable.exploit_surfaced,
            surfaced_by_benign_call=place.id in vulnerable.benign_surfaced,
            surfaced_on_patched=place.id in patched.exploit_surfaced,
        )
        for place in group
    ]


@dataclass(frozen=True)
class _Surfaced:
    exploit_surfaced: frozenset[str]
    benign_surfaced: frozenset[str]


@dataclass(frozen=True)
class _PlantedGroup:
    target: Target
    group: tuple[Place, ...]
    places: Places

    async def surfaced(self, version: TargetVersion, *, benign: bool) -> _Surfaced | None:
        target = self.target
        with tempfile.TemporaryFile("w+") as server_stderr:
            try:
                async with (
                    target.launched(self.group, version=version) as planted,
                    connect(planted.launch, server_stderr) as client,
                ):
                    benign_exchanges = (
                        await logged_exchanges(target.benign, self.places, client) if benign else []
                    )
                    exploit_exchanges = [
                        await logged_exchanges(exploit, self.places, client)
                        for exploit in target.exploits
                    ]
            except Exception:  # a Docker or setup failure, retried per place, never a spec refusal
                return None
        graded = PlantedTarget(target.classes, target.aim, planted.nonces)
        return _Surfaced(
            _surfaced(exploit_exchanges, graded), _surfaced([benign_exchanges], graded)
        )


def _surfaced(exchange_lists: list[list[Exchange]], graded: PlantedTarget) -> frozenset[str]:
    return frozenset(
        place_id
        for exchanges in exchange_lists
        for place_id in proofs_in(unit_of(exchanges), graded)
    )


def _refused_alone(place: Place, host: PlantingHost, nonces: NonceSource) -> bool:
    return place.kind is PlaceKind.UNPLACEABLE or not _plantable_together((place,), host, nonces)


def _pack(
    places: Sequence[Place], host: PlantingHost, nonces: NonceSource
) -> list[tuple[Place, ...]]:
    groups: list[list[Place]] = []
    for place in places:
        for group in groups:
            if _plantable_together((*group, place), host, nonces):
                group.append(place)
                break
        else:
            groups.append([place])
    return [tuple(group) for group in groups]


def _plantable_together(places: tuple[Place, ...], host: PlantingHost, nonces: NonceSource) -> bool:
    try:
        planting_spec(places, host, nonces)
        return True
    except ValueError:
        return False


def _report(result: TargetSurvey) -> None:
    console.print(f"[bold]{result.flaw_id}[/bold]")
    for line in survey_lines(result):
        console.print(line, highlight=False)


def survey_lines(result: TargetSurvey) -> list[str]:
    facts = [
        f"  {_label(f.place)}: exploit {_yes_or_no(f.surfaced_by_exploit)},"
        f" benign {_yes_or_no(f.surfaced_by_benign_call)},"
        f" patched {_yes_or_no(f.surfaced_on_patched)}"
        for f in result.facts
    ]
    not_plantable = [f"  {_label(place)}: not plantable" for place in result.not_plantable]
    not_surveyed = [
        f"  {_label(place)}: launch failed, not surveyed" for place in result.not_surveyed
    ]
    return facts + not_plantable + not_surveyed


def _label(place: Place) -> str:
    return f"{place.id} ({place.family})"


def _yes_or_no(value: bool) -> str:
    return "yes" if value else "no"
