"""The nuisance walk record, `evals/nuisance_walk_record.json`: what the nuisance walk needs
beyond the frozen holdout draw.

It carries the addition that resumes the walk past the holdout walk, the criterion settlements
of the draw-order flaws the walk reaches there, and the identity settlements that name a flaw's
server. `walk_record_problems` holds the load validation, raised joined by `load_walk_record`.
A record settlement never contradicts a draw settlement on the same flaw and criterion: that
is what binds a later holdout walk to the verdicts written here. This module imports nothing
from nuisance_walk, which imports it.
"""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from functools import cached_property
from pathlib import Path

from pydantic import BaseModel

from evals.census_classification import Classification, Criterion, criteria_met
from evals.census_draw import DrawRecord, Settlement
from evals.holdout_census import CLASSIFIERS, HoldoutCensus
from evals.holdout_draw import draw_order


class Addition(BaseModel):
    logged_on: date
    size: int


class IdentitySettlement(BaseModel):
    flaw: str
    server_package: str
    reason: str


class NuisanceWalkRecord(BaseModel):
    rule_commit: str
    addition: Addition
    settlements: list[Settlement]
    identities: list[IdentitySettlement]


@dataclass(frozen=True)
class NuisanceCensus:
    """The census and the record, with the lookups the walk repeats per flaw indexed once:
    rescanning every flaw for every flaw made a population build quadratic."""

    census: HoldoutCensus
    record: NuisanceWalkRecord

    @cached_property
    def classifications_by_flaw(self) -> dict[str, list[Classification]]:
        indexed: dict[str, list[Classification]] = defaultdict(list)
        for own in self.census.classifications.values():
            for classification in own:
                indexed[classification.flaw].append(classification)
        return dict(indexed)

    @cached_property
    def settlements_by_flaw(self) -> dict[tuple[str, Criterion], Settlement]:
        """The draw's settlement first, then the record's."""
        drawn = self.census.draw.settlements if self.census.draw is not None else []
        indexed: dict[tuple[str, Criterion], Settlement] = {}
        for settlement in [*drawn, *self.record.settlements]:
            indexed.setdefault((settlement.flaw, settlement.criterion), settlement)
        return indexed

    @cached_property
    def server_by_flaw(self) -> dict[str, str]:
        """An identity settlement wins, otherwise the first classifier's package."""
        indexed: dict[str, str] = {}
        for classification in self.census.classifications[CLASSIFIERS[0]]:
            indexed.setdefault(
                classification.flaw, normalized_package(classification.server_package)
            )
        identified = {
            identity.flaw: normalized_package(identity.server_package)
            for identity in reversed(self.record.identities)
        }
        return indexed | identified


def load_walk_record(path: Path, census: HoldoutCensus) -> NuisanceCensus:
    if not path.exists():
        raise FileNotFoundError(f"no nuisance walk record at {path}: it has not been committed")
    record = NuisanceWalkRecord.model_validate_json(path.read_text())
    nuisance_census = NuisanceCensus(census=census, record=record)
    problems = walk_record_problems(nuisance_census)
    if problems:
        raise ValueError(f"invalid nuisance walk record {path}: {'; '.join(problems)}")
    return nuisance_census


def walk_record_problems(nuisance_census: NuisanceCensus) -> list[str]:
    census, record = nuisance_census.census, nuisance_census.record
    return [
        *_membership_problems(census, record),
        *_duplicate_problems(record),
        *_contradiction_problems(census, record),
        *_addition_problems(record.addition),
        *_completeness_problems(nuisance_census),
    ]


def reached_identifiers(census: HoldoutCensus) -> list[str]:
    return list(dict.fromkeys(step.identifier for step in _draw(census).walk))


def normalized_package(server_package: str) -> str:
    prefix = "PyPI:"
    if not server_package.startswith(prefix):
        return server_package
    name = server_package[len(prefix) :]
    return prefix + re.sub(r"[-_.]+", "-", name).lower()


def _membership_problems(census: HoldoutCensus, record: NuisanceWalkRecord) -> list[str]:
    candidates = {entry.identifier for entry in draw_order(census)}
    flaws = {flaw.identifier for flaw in census.flaws}
    return [
        *(
            f"settlement on {settlement.flaw}: not a draw-order candidate of the census"
            for settlement in record.settlements
            if settlement.flaw not in candidates
        ),
        *(
            f"identity on {identity.flaw}: not a census flaw"
            for identity in record.identities
            if identity.flaw not in flaws
        ),
    ]


def _duplicate_problems(record: NuisanceWalkRecord) -> list[str]:
    settled = Counter((settlement.flaw, settlement.criterion) for settlement in record.settlements)
    identified = Counter(identity.flaw for identity in record.identities)
    return [
        *(
            f"{flaw}: settled {count} times on {criterion}"
            for (flaw, criterion), count in settled.items()
            if count > 1
        ),
        *(f"{flaw}: identified {count} times" for flaw, count in identified.items() if count > 1),
    ]


def _contradiction_problems(census: HoldoutCensus, record: NuisanceWalkRecord) -> list[str]:
    drawn = {(s.flaw, s.criterion): s.verdict for s in _draw(census).settlements}
    return [
        f"{settlement.flaw}: settled {settlement.verdict} on {settlement.criterion}, "
        f"the draw settles it {not settlement.verdict}"
        for settlement in record.settlements
        if drawn.get((settlement.flaw, settlement.criterion), settlement.verdict)
        != settlement.verdict
    ]


def _addition_problems(addition: Addition) -> list[str]:
    if addition.size < 1:
        return [f"addition size {addition.size}: below 1"]
    return []


def _completeness_problems(nuisance_census: NuisanceCensus) -> list[str]:
    census, record = nuisance_census.census, nuisance_census.record
    reached = set(reached_identifiers(census))
    settled = {(settlement.flaw, settlement.criterion) for settlement in record.settlements}
    identified = {identity.flaw for identity in record.identities}
    problems: list[str] = []
    for entry in draw_order(census):
        if entry.identifier in reached:
            continue
        seen = nuisance_census.classifications_by_flaw.get(entry.identifier, [])
        problems += [
            f"{entry.identifier}: the classifiers disagree on {criterion}, and no settlement"
            for criterion in Criterion
            if len({criteria_met(each)[criterion] for each in seen}) > 1
            and (entry.identifier, criterion) not in settled
        ]
        packages = {normalized_package(each.server_package) for each in seen}
        if len(packages) > 1 and entry.identifier not in identified:
            problems.append(
                f"{entry.identifier}: the classifiers name {sorted(packages)}, and no identity"
            )
    return problems


def _draw(census: HoldoutCensus) -> DrawRecord:
    if census.draw is None:
        raise ValueError("the census has no draw walk to follow")
    return census.draw
