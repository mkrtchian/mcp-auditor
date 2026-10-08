"""Where the census collection stands, from the three exports and the work directory.

Flaws are merged over every record of the exports, so a hit is left out before the
collectors see it only when its whole flaw is disclosed after the bound. OSV is read for the
advisories the first two sources do not carry: its hits leave out a flaw that has a GHSA or
NVD hit. The collection is complete when nothing is left: every hit decided, and every flaw
an agent found matched by the pre-filter as last widened.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property

from evals.census_classification import Classification
from evals.census_figures import compute_figures
from evals.census_identity import Flaw, disclosure_date, merge
from evals.census_prefilter import INITIAL_TERMS, PrefilterTerm, matches
from evals.census_sources import AdvisoryRecord, SourceName, SourceProvenance
from evals.census_work import (
    AgentRecord,
    Gap,
    HitDecision,
    RecallFinding,
    VulnerableMcpEntry,
    Widening,
)
from evals.holdout_census import (
    BOUND,
    CensusFlaw,
    Discovery,
    HoldoutCensus,
    census_flaw,
    date_mismatches,
)


@dataclass(frozen=True)
class CollectionWork:
    decisions: list[HitDecision]
    gaps: list[Gap]
    recall: list[RecallFinding]
    vulnerablemcp: list[VulnerableMcpEntry]
    widenings: list[Widening]

    @property
    def terms(self) -> list[PrefilterTerm]:
        return [*INITIAL_TERMS, *(widening.term for widening in self.widenings)]


@dataclass(frozen=True)
class AssemblyInputs:
    sources: SourceProvenance
    agents: list[AgentRecord]
    classifications: dict[str, list[Classification]]


class Collection:
    def __init__(self, records: Iterable[AdvisoryRecord], work: CollectionWork) -> None:
        self._work = work
        flaws = merge(records, recorded={})
        self._flaw_of = {advisory_id: flaw for flaw in flaws for advisory_id in flaw.ids}
        self._in_bound = [flaw for flaw in flaws if _within_bound(flaw)]
        self._decided = {(decision.source, decision.source_id) for decision in work.decisions}

    @cached_property
    def hits(self) -> dict[SourceName, list[AdvisoryRecord]]:
        hits: dict[SourceName, list[AdvisoryRecord]] = {source: [] for source in SourceName}
        for flaw in self._in_bound:
            matched = [record for record in flaw.records if matches(record, self._work.terms)]
            carried = any(record.source != SourceName.OSV for record in matched)
            for record in matched:
                if record.source != SourceName.OSV or not carried:
                    hits[record.source].append(record)
        return hits

    def undecided(self) -> dict[SourceName, list[AdvisoryRecord]]:
        return {
            source: [record for record in records if (source, record.id) not in self._decided]
            for source, records in self.hits.items()
        }

    def remaining(self) -> list[str]:
        undecided = [
            f"{source}: {len(records)} undecided hit(s), run prefilter and decide them"
            for source, records in self.undecided().items()
            if records
        ]
        return undecided + self._finding_problems() + self._absence_problems()

    def census_members(self) -> list[tuple[Flaw, CensusFlaw]]:
        """Each flaw of the census, ordered by identifier, with the advisories' full text."""
        found = self._found_by_agents()
        kept = {
            (decision.source, decision.source_id)
            for decision in self._work.decisions
            if decision.decision == "keep"
        }
        members: list[tuple[Flaw, CensusFlaw]] = []
        for flaw in self._in_bound:
            discoveries = set(found.get(min(flaw.ids), ()))
            if any((record.source, record.id) in kept for record in flaw.records):
                discoveries.add(Discovery.PREFILTER)
            if discoveries:
                found_by = [each for each in Discovery if each in discoveries]
                members.append((flaw, census_flaw(flaw, found_by)))
        return sorted(members, key=lambda member: member[1].identifier)

    def census(self, inputs: AssemblyInputs) -> HoldoutCensus:
        flaws = [flaw for _, flaw in self.census_members()]
        dates = {flaw.identifier: flaw.disclosure_date for flaw in flaws}
        withdrawn = {flaw.identifier for flaw in flaws if flaw.withdrawn}
        return HoldoutCensus(
            sources=inputs.sources,
            agents=inputs.agents,
            prefilter=self._work.terms,
            hits=self._work.decisions,
            flaws=flaws,
            vulnerablemcp=self._work.vulnerablemcp,
            classifications=inputs.classifications,
            date_mismatches=date_mismatches(inputs.classifications, dates),
            figures=compute_figures(inputs.classifications, dates, withdrawn),
        )

    def _found_by_agents(self) -> dict[str, set[Discovery]]:
        """Keyed by the lowest ID of each flaw an agent found in the sources."""
        found: dict[str, set[Discovery]] = {}
        for advisory_id, discovery in self._sightings():
            flaw = self._lookup(advisory_id)
            if flaw is not None:
                found.setdefault(min(flaw.ids), set()).add(discovery)
        return found

    def _finding_problems(self) -> list[str]:
        problems: list[str] = []
        for advisory_id in sorted({advisory_id for advisory_id, _ in self._sightings()}):
            flaw = self._lookup(advisory_id)
            if flaw is None:
                problems.append(f"{advisory_id}, found by an agent, is in none of the sources")
            elif _within_bound(flaw) and not any(
                matches(record, self._work.terms) for record in flaw.records
            ):
                problems.append(f"gap to widen: no record of {advisory_id} matches the pre-filter")
        return problems

    def _absence_problems(self) -> list[str]:
        return [
            f"vulnerablemcp.info {entry.cve_id} is recorded as absent, but the sources carry it"
            for entry in self._work.vulnerablemcp
            if not entry.found and self._lookup(entry.cve_id) is not None
        ]

    def _sightings(self) -> list[tuple[str, Discovery]]:
        work = self._work
        return [
            *((gap.source_id, Discovery.GAP) for gap in work.gaps),
            *(
                (finding.advisory_id, Discovery.RECALL)
                for finding in work.recall
                if finding.advisory_id is not None
            ),
            *(
                (entry.cve_id, Discovery.VULNERABLEMCP)
                for entry in work.vulnerablemcp
                if entry.found
            ),
        ]

    def _lookup(self, advisory_id: str) -> Flaw | None:
        return self._flaw_of.get(advisory_id) or self._flaw_of.get(advisory_id.upper())


def _within_bound(flaw: Flaw) -> bool:
    return disclosure_date(flaw.records) <= BOUND
