"""The draw-time schema of the holdout census: the draw record and the calibration cards the
draw and its calibration fill.

Everything here is optional and empty until the maintainer's draw session. `draw_problems`
is the load validation `holdout_census.load_census` runs when a `draw` is present. This module
imports nothing from holdout_census, so holdout_census can import from it with no cycle.
"""

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import date
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel

from evals.census_classification import Criterion
from evals.census_work import AgentRecord, AgentRole
from evals.cve_places import REACHABLE_BY
from evals.fixture_provenance import (
    SoftwareRelease,
    StandInRecord,
    software_release_problems,
    stand_in_problems,
)


class KeptPlace(BaseModel):
    place_id: str
    reason: str


class UnkeptPlace(BaseModel):
    place_id: str
    reason: str
    route_checked: bool | None


class LaunchOption(BaseModel):
    option: str
    value: str
    reason: str
    documentation: str


class SeededFile(BaseModel):
    path: str
    reason: str
    documentation: str


class SeededOutsideLayout(BaseModel):
    item: str
    reason: str
    returned_by: list[str]  # tools that return it in a response
    used_by_default_by: list[str]  # tools that use it by default


class CardStandIn(BaseModel):
    stand_in: StandInRecord
    returned_by: list[str]
    used_by_default_by: list[str]


class Sibling(BaseModel):
    flaw: str
    mechanism: str
    reach: str


class CalibrationCard(BaseModel):
    flaw: str
    mechanism: str
    effect_class: str
    siblings: list[Sibling]
    kept: list[KeptPlace]
    unkept: list[UnkeptPlace]
    launch_options: list[LaunchOption]
    seeded_in_layout: list[SeededFile]
    # Holdout rule v9 adds these two; None reads "not yet recorded", which `run_holdout run`
    # refuses through holdout_card_readiness.
    seeded_outside_layout: list[SeededOutsideLayout] | None = None
    stand_ins: list[CardStandIn] | None = None
    # Holdout rule v11 adds it, with the same None reading; [] records no real software.
    software_releases: list[SoftwareRelease] | None = None
    fallback_scope: str | None
    fallback_documentation: str | None
    exploit_calls: list[str]
    benign_call: str
    patched_result: str
    attempts: int


class ConfirmedGap(BaseModel):
    criterion: str
    reason: str


class CardCheck(BaseModel):
    flaw: str
    reported_gaps: list[str]
    confirmed_gaps: list[ConfirmedGap]
    rule_version: int | None = None  # the holdout rule version the card was checked under


class GiveUpReason(StrEnum):
    NO_PLACE_REACHED = "no_place_reached"
    PLACES_LEFT_OUT = "places_left_out"
    CONTAINER_CANNOT_RUN = "container_cannot_run"
    EXPLOIT_CANNOT_REPRODUCE = "exploit_cannot_reproduce"


class GiveUp(BaseModel):
    flaw: str
    calibration: Literal[1, 2]
    reason: GiveUpReason
    detail: str
    attempts: int
    rule_version: int | None = None  # the walk's version, None before the first re-walk


class Settlement(BaseModel):
    flaw: str
    criterion: Criterion
    verdict: bool
    reason: str


class DrawWalkStep(BaseModel):
    identifier: str
    outcome: Literal["drawn", "skipped", "given_up", "excluded"]
    reason: str
    rule_version: int | None = None  # the deciding version, None before the first re-walk


class DrawRecord(BaseModel):
    rule_commit: str
    grammar_fingerprint: str
    settlements: list[Settlement]
    walk: list[DrawWalkStep]
    cards: list[CalibrationCard]
    card_checks: list[CardCheck]
    give_ups: list[GiveUp]
    drawn: list[str]


def draw_problems(
    draw: DrawRecord,
    order: set[str],
    disclosure_dates: Mapping[str, date],
    place_ids: set[str],
    agents: Sequence[AgentRecord],
) -> list[str]:
    return [
        *_membership_problems(draw, set(disclosure_dates), order),
        *_walk_problems(draw, order),
        *_calibration_problems(draw),
        *_place_problems(draw, place_ids),
        *_stand_in_problems(draw),
        *_software_release_problems(draw),
        *_agent_problems(draw, agents),
    ]


def governing_steps(draw: DrawRecord) -> dict[str, DrawWalkStep]:
    """Each reached flaw's step under the latest version that decided it, in order of first
    reach."""
    governing: dict[str, DrawWalkStep] = {}
    for step in draw.walk:
        current = governing.get(step.identifier, step)
        governing[step.identifier] = max(current, step, key=_version_order)
    return governing


def _membership_problems(draw: DrawRecord, in_census: set[str], order: set[str]) -> list[str]:
    problems: list[str] = []
    for label, flaw in _referenced_flaws(draw):
        if flaw not in in_census:
            problems.append(f"draw {label} names flaw {flaw}, which is not in the census")
        elif flaw not in order:
            problems.append(f"draw {label} names flaw {flaw}, which is not a draw-order candidate")
    return problems


def _referenced_flaws(draw: DrawRecord) -> list[tuple[str, str]]:
    return [
        *(("settlement", settlement.flaw) for settlement in draw.settlements),
        *(("card", card.flaw) for card in draw.cards),
        *(("card check", check.flaw) for check in draw.card_checks),
        *(("give-up", give_up.flaw) for give_up in draw.give_ups),
    ]


def _walk_problems(draw: DrawRecord, order: set[str]) -> list[str]:
    outcomes = _walk_outcomes(draw)
    listed = Counter((step.identifier, step.rule_version) for step in draw.walk)
    problems = [
        f"walk lists flaw {identifier} {count} times under rule version {version}"
        for (identifier, version), count in listed.items()
        if count > 1
    ]
    problems += [
        f"walk names flaw {identifier}, which is not a draw-order candidate"
        for identifier in outcomes
        if identifier not in order
    ]
    problems += [
        f'card for flaw {card.flaw} has no "drawn" walk step'
        for card in draw.cards
        if "drawn" not in outcomes.get(card.flaw, [])
    ]
    return problems + _drawn_problems(draw)


def _drawn_problems(draw: DrawRecord) -> list[str]:
    governing = governing_steps(draw)
    problems: list[str] = []
    for identifier in draw.drawn:
        if identifier not in {card.flaw for card in draw.cards}:
            problems.append(f"drawn flaw {identifier} has no calibration card")
        if identifier not in {check.flaw for check in draw.card_checks}:
            problems.append(f"drawn flaw {identifier} has no card check")
        if identifier not in governing:
            problems.append(f'drawn flaw {identifier} has no "drawn" walk step')
        elif (outcome := governing[identifier].outcome) != "drawn":
            problems.append(
                f'drawn flaw {identifier}: its governing walk step is "{outcome}", not "drawn"'
            )
    return problems


def _calibration_problems(draw: DrawRecord) -> list[str]:
    """Give-ups count within the version that made them: only the governing version's are read
    against the card and the walk."""
    card_flaws = {card.flaw for card in draw.cards}
    governing = governing_steps(draw)
    problems: list[str] = []
    for (flaw, version), give_ups in _give_ups_by_flaw_and_version(draw).items():
        calibrations = {give_up.calibration for give_up in give_ups}
        if 2 in calibrations and 1 not in calibrations:
            problems.append(
                f"flaw {flaw} has a second-calibration give-up with no first"
                f" under rule version {version}"
            )
        step = governing.get(flaw)
        if (step.rule_version if step else None) == version:
            problems += _governing_give_up_problems(give_ups, step, card_flaws)
    return problems


def _governing_give_up_problems(
    give_ups: list[GiveUp], step: DrawWalkStep | None, card_flaws: set[str]
) -> list[str]:
    flaw, version = give_ups[0].flaw, give_ups[0].rule_version
    problems: list[str] = []
    if len(give_ups) == 1 and flaw not in card_flaws:
        problems.append(f"flaw {flaw} gave up once but has no calibration card")
    if len(give_ups) == 2:
        if flaw in card_flaws:
            problems.append(f"flaw {flaw} has two give-ups and a card under rule version {version}")
        if step is None or step.outcome != "given_up":
            problems.append(
                f"flaw {flaw} gave up twice under rule version {version} but its governing"
                ' walk step is not "given_up"'
            )
    return problems


def _place_problems(draw: DrawRecord, place_ids: set[str]) -> list[str]:
    problems: list[str] = []
    for card in draw.cards:
        for place in (*card.kept, *card.unkept):
            if place.place_id not in place_ids:
                problems.append(f"card for flaw {card.flaw} cites unknown place {place.place_id}")
        problems += [
            f"card for flaw {card.flaw} has a sibling reach {sibling.reach} outside the vocabulary"
            for sibling in card.siblings
            if sibling.reach not in REACHABLE_BY
        ]
    return problems


def _stand_in_problems(draw: DrawRecord) -> list[str]:
    return [
        f"card for flaw {card.flaw}: {problem}"
        for card in draw.cards
        for card_stand_in in card.stand_ins or []
        for problem in stand_in_problems(card_stand_in.stand_in)
    ]


def _software_release_problems(draw: DrawRecord) -> list[str]:
    return [
        f"card for flaw {card.flaw}: {problem}"
        for card in draw.cards
        for release in card.software_releases or []
        for problem in software_release_problems(release)
    ]


def _agent_problems(draw: DrawRecord, agents: Sequence[AgentRecord]) -> list[str]:
    counted = [agent for agent in agents if agent.set_aside is None]
    calibrators = {agent.scope for agent in counted if agent.role == AgentRole.CALIBRATOR}
    card_checkers = {agent.scope for agent in counted if agent.role == AgentRole.CARD_CHECKER}
    calibrated = {card.flaw for card in draw.cards} | {give_up.flaw for give_up in draw.give_ups}
    problems = [
        f"flaw {flaw} has no calibrator agent record"
        for flaw in sorted(calibrated)
        if flaw not in calibrators
    ]
    problems += [
        f"card check for flaw {check.flaw} has no card-checker agent record"
        for check in draw.card_checks
        if check.flaw not in card_checkers
    ]
    return problems


def _walk_outcomes(draw: DrawRecord) -> dict[str, list[str]]:
    outcomes: defaultdict[str, list[str]] = defaultdict(list)
    for step in draw.walk:
        outcomes[step.identifier].append(step.outcome)
    return outcomes


def _give_ups_by_flaw_and_version(draw: DrawRecord) -> dict[tuple[str, int | None], list[GiveUp]]:
    grouped: defaultdict[tuple[str, int | None], list[GiveUp]] = defaultdict(list)
    for give_up in draw.give_ups:
        grouped[(give_up.flaw, give_up.rule_version)].append(give_up)
    return grouped


def _version_order(step: DrawWalkStep) -> int:
    return -1 if step.rule_version is None else step.rule_version
