"""The draw-time schema of the holdout census: the side of a flaw on the cutoff, the draw
record and the calibration cards the draw and its calibration fill.

Everything here is optional and empty until the maintainer's draw session. `draw_problems`
is the load validation `holdout_census.load_census` runs when a `draw` is present. This module
imports nothing from holdout_draw or holdout_census, so both can import from it with no cycle.
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


class Side(StrEnum):
    PRE_CUTOFF = "pre_cutoff"
    POST_CUTOFF = "post_cutoff"


def side_of(disclosure_date: date, cutoff: date) -> Side:
    return Side.PRE_CUTOFF if disclosure_date <= cutoff else Side.POST_CUTOFF


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


class Settlement(BaseModel):
    flaw: str
    criterion: Criterion
    verdict: bool
    reason: str


class DrawWalkStep(BaseModel):
    identifier: str
    side: Side
    outcome: Literal["drawn", "skipped", "given_up", "excluded"]
    reason: str


class DrawRecord(BaseModel):
    cutoff: date
    cutoff_type: str
    cutoff_note: str | None
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
        *_agent_problems(draw, agents),
        *_count_problems(draw, disclosure_dates),
    ]


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
    problems = [
        f"walk lists flaw {identifier} {len(steps)} times"
        for identifier, steps in outcomes.items()
        if len(steps) > 1
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
    for identifier in draw.drawn:
        steps = outcomes.get(identifier, [])
        if identifier not in {card.flaw for card in draw.cards}:
            problems.append(f"drawn flaw {identifier} has no calibration card")
        if identifier not in {check.flaw for check in draw.card_checks}:
            problems.append(f"drawn flaw {identifier} has no card check")
        if "drawn" not in steps:
            problems.append(f'drawn flaw {identifier} has no "drawn" walk step')
    return problems


def _calibration_problems(draw: DrawRecord) -> list[str]:
    card_flaws = {card.flaw for card in draw.cards}
    outcomes = _walk_outcomes(draw)
    problems: list[str] = []
    for flaw, give_ups in _give_ups_by_flaw(draw).items():
        calibrations = {give_up.calibration for give_up in give_ups}
        if 2 in calibrations and 1 not in calibrations:
            problems.append(f"flaw {flaw} has a second-calibration give-up with no first")
        if len(give_ups) == 1 and flaw not in card_flaws:
            problems.append(f"flaw {flaw} gave up once but has no calibration card")
        if len(give_ups) == 2:
            if flaw in card_flaws:
                problems.append(f"flaw {flaw} has two give-ups and a card")
            if "given_up" not in outcomes.get(flaw, []):
                problems.append(f'flaw {flaw} gave up twice but has no "given_up" walk step')
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


def _agent_problems(draw: DrawRecord, agents: Sequence[AgentRecord]) -> list[str]:
    calibrators = {agent.scope for agent in agents if agent.role == AgentRole.CALIBRATOR}
    card_checkers = {agent.scope for agent in agents if agent.role == AgentRole.CARD_CHECKER}
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


def _count_problems(draw: DrawRecord, disclosure_dates: Mapping[str, date]) -> list[str]:
    problems: list[str] = []
    if len(draw.drawn) > 20:
        problems.append(f"the draw has {len(draw.drawn)} drawn targets, more than 20")
    per_side = Counter(
        side_of(disclosure_dates[identifier], draw.cutoff)
        for identifier in draw.drawn
        if identifier in disclosure_dates
    )
    problems += [
        f"the draw has {count} drawn targets on side {side}, more than 10"
        for side, count in per_side.items()
        if count > 10
    ]
    return problems


def _walk_outcomes(draw: DrawRecord) -> dict[str, list[str]]:
    outcomes: defaultdict[str, list[str]] = defaultdict(list)
    for step in draw.walk:
        outcomes[step.identifier].append(step.outcome)
    return outcomes


def _give_ups_by_flaw(draw: DrawRecord) -> dict[str, list[GiveUp]]:
    by_flaw: defaultdict[str, list[GiveUp]] = defaultdict(list)
    for give_up in draw.give_ups:
        by_flaw[give_up.flaw].append(give_up)
    return by_flaw
