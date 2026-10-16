"""The holdout census, `evals/holdout_census.json`, and its validation on load.

Everything derived in the file is recomputed on load and compared: each flaw's
identifier and disclosure date from its source records, its withdrawn flag, the date
mismatches, the figures and the known gap. The stored copies are a cache, never an
independent claim.
"""

from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, computed_field

from evals import cve_places
from evals.census_classification import Classification, is_consistent
from evals.census_draw import DrawRecord, draw_problems
from evals.census_figures import CensusFigures, Share, compute_figures
from evals.census_grouping import (
    READERS,
    ProofJudgment,
    draw_order_flaws,
    gap_population,
    grouped_flaws,
    known_gap,
)
from evals.census_identity import Flaw, census_identifier, disclosure_date
from evals.census_prefilter import PrefilterTerm
from evals.census_sources import SourceProvenance, SourceRecord
from evals.census_work import AgentRecord, AgentRole, HitDecision, VulnerableMcpEntry

BOUND = date(2026, 10, 7)
CLASSIFIERS = ("classifier_1", "classifier_2")


class Discovery(StrEnum):
    PREFILTER = "prefilter"
    GAP = "gap"
    RECALL = "recall"
    VULNERABLEMCP = "vulnerablemcp"


class CensusFlaw(BaseModel):
    identifier: str
    no_census_identifier: bool
    ids: list[str]
    records: list[SourceRecord] = Field(min_length=1)
    disclosure_date: date
    found_by: list[Discovery]

    @computed_field
    @property
    def withdrawn(self) -> bool:
        return all(record.withdrawn is not None or record.rejected for record in self.records)


class TermHits(BaseModel):
    term: PrefilterTerm
    hit_count: int


class DateMismatch(BaseModel):
    flaw: str
    classifier: str
    classifier_date: date
    computed_date: date


class HoldoutCensus(BaseModel):
    rule_version: Literal[3] = 3
    rule_commit: Literal["0468deb"] = "0468deb"
    bound_commit: Literal["3f09545"] = "3f09545"
    bound: date = BOUND
    sources: SourceProvenance
    agents: list[AgentRecord]
    prefilter: list[TermHits]
    hits: list[HitDecision]
    flaws: list[CensusFlaw]
    vulnerablemcp: list[VulnerableMcpEntry]
    classifications: dict[str, list[Classification]]
    date_mismatches: list[DateMismatch]
    figures: CensusFigures
    groupings: dict[str, list[ProofJudgment]]
    known_gap: dict[str, Share]
    draw: DrawRecord | None = None


def census_flaw(flaw: Flaw, found_by: Sequence[Discovery]) -> CensusFlaw:
    records = [
        SourceRecord.model_validate(record.model_dump(include=set(SourceRecord.model_fields)))
        for record in flaw.records
    ]
    identifier = flaw.identifier or _without_census_identifier(records)
    disclosed = disclosure_date(records)
    if disclosed is None:
        raise ValueError(f"flaw {identifier} has no published date in any source")
    return CensusFlaw(
        identifier=identifier,
        no_census_identifier=flaw.identifier is None,
        ids=sorted(flaw.ids),
        records=records,
        disclosure_date=disclosed,
        found_by=list(found_by),
    )


def date_mismatches(
    classifications: dict[str, list[Classification]], disclosure_dates: dict[str, date]
) -> list[DateMismatch]:
    return [
        DateMismatch(
            flaw=classification.flaw,
            classifier=classifier,
            classifier_date=classification.disclosure_date,
            computed_date=disclosure_dates[classification.flaw],
        )
        for classifier, own in classifications.items()
        for classification in own
        if classification.disclosure_date != disclosure_dates[classification.flaw]
    ]


def draw_candidates(flaws: Sequence[CensusFlaw]) -> set[str]:
    """The flaws the draw can reach before any criterion: a census identifier, not withdrawn."""
    return {
        flaw.identifier for flaw in flaws if not flaw.no_census_identifier and not flaw.withdrawn
    }


def load_census(path: Path) -> HoldoutCensus:
    census = HoldoutCensus.model_validate_json(path.read_text())
    coverage = _coverage_problems(census)
    problems = [
        *(problem for flaw in census.flaws for problem in _flaw_problems(flaw, census.bound)),
        *_identity_problems(census.flaws),
        *(
            f"hit {hit.source} {hit.source_id} has no reason"
            for hit in census.hits
            if not hit.reason.strip()
        ),
        *coverage,
        *_consistency_problems(census.classifications),
        *_reader_problems(census),
    ]
    # The grouping and the derived parts pair the two classifiers flaw by flaw, which needs
    # full coverage.
    if not coverage:
        problems += _grouping_problems(census) + _derived_problems(census)
    if census.draw is not None:
        order = draw_order_flaws(census.classifications, draw_candidates(census.flaws))
        place_ids = set(cve_places.load_places(cve_places.HOLDOUT_PLACES))
        disclosure_dates = {flaw.identifier: flaw.disclosure_date for flaw in census.flaws}
        problems += draw_problems(census.draw, order, disclosure_dates, place_ids, census.agents)
    if problems:
        raise ValueError(f"invalid holdout census {path}: {'; '.join(problems)}")
    return census


# Reading 7: a flaw with neither a CVE nor a GHSA ID is recorded under its own record's ID.
def _without_census_identifier(records: Sequence[SourceRecord]) -> str:
    return min(record.id for record in records)


def _flaw_problems(flaw: CensusFlaw, bound: date) -> list[str]:
    problems: list[str] = []
    canonical = census_identifier(set(flaw.ids), flaw.records)
    expected = canonical or _without_census_identifier(flaw.records)
    if flaw.identifier != expected or flaw.no_census_identifier != (canonical is None):
        problems.append(f"flaw {flaw.identifier}: its canonical identifier is {expected}")
    earliest = disclosure_date(flaw.records)
    if earliest is None:
        return [*problems, f"flaw {flaw.identifier} has no published date in any source"]
    if flaw.disclosure_date != earliest:
        problems.append(
            f"flaw {flaw.identifier}: disclosure date {flaw.disclosure_date} is not the "
            f"earliest published, {earliest}"
        )
    if earliest > bound:
        problems.append(
            f"flaw {flaw.identifier} is disclosed on {earliest}, after the bound {bound}"
        )
    return problems


def _identity_problems(flaws: list[CensusFlaw]) -> list[str]:
    counts = Counter(flaw.identifier for flaw in flaws)
    duplicated = [
        f"identifier {identifier} appears {count} times"
        for identifier, count in counts.items()
        if count > 1
    ]
    holders: defaultdict[str, set[str]] = defaultdict(set)
    for flaw in flaws:
        for advisory_id in flaw.ids:
            holders[advisory_id].add(flaw.identifier)
    shared = [
        f"ID {advisory_id} is shared by flaws {', '.join(sorted(identifiers))}"
        for advisory_id, identifiers in holders.items()
        if len(identifiers) > 1
    ]
    return duplicated + shared


def _coverage_problems(census: HoldoutCensus) -> list[str]:
    if tuple(census.classifications) != CLASSIFIERS:
        return [f"classifiers must be {', '.join(CLASSIFIERS)}"]
    in_census = {flaw.identifier for flaw in census.flaws}
    problems: list[str] = []
    for classifier, own in census.classifications.items():
        counts = Counter(classification.flaw for classification in own)
        problems += [
            f"{classifier} does not classify flaw {flaw}"
            for flaw in sorted(in_census - counts.keys())
        ]
        problems += [
            f"{classifier} classifies flaw {flaw} {count} times"
            for flaw, count in counts.items()
            if count > 1
        ]
        problems += [
            f"{classifier} classifies {flaw}, which is not in the census"
            for flaw in sorted(counts.keys() - in_census)
        ]
    return problems


def _consistency_problems(classifications: dict[str, list[Classification]]) -> list[str]:
    return [
        f"{classifier}: the first_failed_criterion of flaw {classification.flaw} is "
        "inconsistent with its fields"
        for classifier, own in classifications.items()
        for classification in own
        if not is_consistent(classification)
    ]


def _reader_problems(census: HoldoutCensus) -> list[str]:
    if tuple(census.groupings) != READERS:
        return [f"readers must be {', '.join(READERS)}"]
    recorded = {agent.scope for agent in census.agents if agent.role == AgentRole.READER}
    problems = [f"{reader} has no agent record" for reader in READERS if reader not in recorded]
    return problems + [
        f"{reader}: the judgment of flaw {judgment.flaw} has no proof or no reason"
        for reader, own in census.groupings.items()
        for judgment in own
        if not judgment.proof.strip() or not judgment.reason.strip()
    ]


def _grouping_problems(census: HoldoutCensus) -> list[str]:
    given = grouped_flaws(census.classifications, draw_candidates(census.flaws))
    problems: list[str] = []
    for reader, own in census.groupings.items():
        counts = Counter(judgment.flaw for judgment in own)
        problems += [
            f"{reader} does not group flaw {flaw}" for flaw in sorted(given - counts.keys())
        ]
        problems += [
            f"{reader} groups flaw {flaw} {count} times"
            for flaw, count in counts.items()
            if count > 1
        ]
        problems += [
            f"{reader} groups {flaw}, which the rule does not give to the readers"
            for flaw in sorted(counts.keys() - given)
        ]
    return problems


def _derived_problems(census: HoldoutCensus) -> list[str]:
    dates = {flaw.identifier: flaw.disclosure_date for flaw in census.flaws}
    withdrawn = {flaw.identifier for flaw in census.flaws if flaw.withdrawn}
    population = gap_population(census.classifications, draw_candidates(census.flaws))
    problems: list[str] = []
    if census.date_mismatches != date_mismatches(census.classifications, dates):
        problems.append("date mismatches differ from their computation")
    if census.figures != compute_figures(census.classifications, dates, withdrawn):
        problems.append("figures differ from their computation")
    if census.known_gap != known_gap(census.groupings, population):
        problems.append("known gap differs from its computation")
    return problems
