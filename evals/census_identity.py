import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date

from evals.census_sources import AdvisoryRecord, SourceRecord


@dataclass(frozen=True)
class Flaw:
    identifier: str | None
    ids: set[str]
    records: list[AdvisoryRecord]


def merge(records: Iterable[AdvisoryRecord], recorded: Mapping[str, set[str]]) -> list[Flaw]:
    return [_flaw(ids, members, recorded) for ids, members in _alias_components(records)]


def census_identifier(ids: set[str], records: Sequence[SourceRecord]) -> str | None:
    rejected = {_canonical(record.id) for record in records if record.rejected}
    cves = sorted(
        (order, each)
        for each in ids
        if each not in rejected and (order := _cve_order(each)) is not None
    )
    if cves:
        return cves[0][1]
    ghsas = [each for each in ids if each.startswith("GHSA-")]
    if ghsas:
        return min(ghsas, key=lambda ghsa: (_earliest_published(ghsa, records), ghsa))
    return None


def disclosure_date(records: Sequence[SourceRecord]) -> date | None:
    return min((record.published for record in records if record.published), default=None)


def _flaw(ids: set[str], records: list[AdvisoryRecord], recorded: Mapping[str, set[str]]) -> Flaw:
    met = sorted(
        identifier for identifier, known in recorded.items() if ids & (known | {identifier})
    )
    if len(met) > 1:
        raise ValueError(f"one flaw meets the recorded identifiers {', '.join(met)}")
    identifier = met[0] if met else census_identifier(ids, records)
    return Flaw(identifier=identifier, ids=ids, records=records)


def _alias_components(
    records: Iterable[AdvisoryRecord],
) -> list[tuple[set[str], list[AdvisoryRecord]]]:
    records = list(records)
    graph = _UnionFind()
    for record in records:
        for alias in record.aliases:
            graph.link(_canonical(record.id), _canonical(alias))
    components: dict[str, tuple[set[str], list[AdvisoryRecord]]] = {}
    for record in records:
        components.setdefault(graph.root(_canonical(record.id)), (set(), []))[1].append(record)
    for node in graph.nodes():
        components[graph.root(node)][0].add(node)
    return list(components.values())


def _canonical(advisory_id: str) -> str:
    return advisory_id.upper() if advisory_id.upper().startswith("CVE-") else advisory_id


class _UnionFind:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def link(self, first: str, second: str) -> None:
        self._parent[self.root(second)] = self.root(first)

    def root(self, node: str) -> str:
        self._parent.setdefault(node, node)
        while self._parent[node] != node:
            self._parent[node] = self._parent[self._parent[node]]
            node = self._parent[node]
        return node

    def nodes(self) -> list[str]:
        return list(self._parent)


def _cve_order(advisory_id: str) -> tuple[int, int] | None:
    match = re.fullmatch(r"CVE-(\d+)-(\d+)", advisory_id)
    return (int(match[1]), int(match[2])) if match else None


def _earliest_published(ghsa: str, records: Sequence[SourceRecord]) -> date:
    return min(
        (record.published for record in records if record.id == ghsa and record.published),
        default=date.max,
    )
