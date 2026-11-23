"""The draw-time schema of the census: the draw record and the calibration cards the draw and
its calibration fill.

Everything here is optional and empty until the maintainer's draw session. The load validation
`census.load_census` runs when a `draw` is present lives in `draw_record_problems`. This module
imports nothing from the census module, so the census module can import from it with no cycle.
"""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from evals.cve.census.classification import Criterion
from evals.cve.fixture_provenance import SoftwareRelease, StandInRecord


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
    seeded_outside_layout: list[SeededOutsideLayout]
    stand_ins: list[CardStandIn]
    software_releases: list[SoftwareRelease]  # [] records no real software
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
    rule_version: int  # the detection suite rule version the card was checked under


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
    # The committed census and walk record carry the ruling under `verdict`, read and written.
    model_config = ConfigDict(validate_by_name=True, serialize_by_alias=True)

    flaw: str
    criterion: Criterion
    ruling: bool = Field(validation_alias="verdict", serialization_alias="verdict")
    reason: str


class DetectionWalkStep(BaseModel):
    identifier: str
    outcome: Literal["drawn", "skipped", "given_up", "excluded"]
    reason: str
    rule_version: int | None = None  # the deciding version, None before the first re-walk


class DrawRecord(BaseModel):
    rule_commit: str
    grammar_fingerprint: str
    settlements: list[Settlement]
    walk: list[DetectionWalkStep]
    cards: list[CalibrationCard]
    card_checks: list[CardCheck]
    give_ups: list[GiveUp]
    drawn: list[str]


def governing_steps(draw: DrawRecord) -> dict[str, DetectionWalkStep]:
    """Each reached flaw's step under the latest version that decided it, in order of first
    reach."""
    governing: dict[str, DetectionWalkStep] = {}
    for step in draw.walk:
        current = governing.get(step.identifier, step)
        governing[step.identifier] = max(current, step, key=_version_order)
    return governing


def _version_order(step: DetectionWalkStep) -> int:
    return -1 if step.rule_version is None else step.rule_version
