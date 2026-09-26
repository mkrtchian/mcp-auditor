"""The pure parts of a subset run of the probe: debugging only.

See the *Subset runs* section of `evals/probe_method.md`.
"""

from rich.table import Table

from evals.probe import DefectCounts, ProbeObservation, count_defects
from evals.probe_candidates import CANDIDATES, REFERENCE, Candidate
from evals.probe_corpus import ProbeCall, ProbeCorpus

KNOWN_CANDIDATES = [REFERENCE, *CANDIDATES]


class UnknownCandidate(ValueError):
    def __init__(self, name: str) -> None:
        known = ", ".join(repr(candidate.name) for candidate in KNOWN_CANDIDATES)
        super().__init__(f"Unknown candidate {name!r}. Known candidates: {known}")


def select_candidates(names: list[str]) -> list[Candidate]:
    by_name = {candidate.name: candidate for candidate in KNOWN_CANDIDATES}
    for name in names:
        if name not in by_name:
            raise UnknownCandidate(name)
    return [by_name[name] for name in dict.fromkeys(names)]


def select_calls(corpus: ProbeCorpus, schema: str | None) -> list[ProbeCall]:
    return [call for call in corpus.calls if schema is None or call.schema_name == schema]


def defect_counts(
    candidates: list[Candidate], observations: list[ProbeObservation]
) -> list[DefectCounts]:
    return [
        count_defects(c.name, [o for o in observations if o.candidate == c.name])
        for c in candidates
    ]


def defect_table(counts: list[DefectCounts]) -> Table:
    table = Table(title="Probe subset run (debugging only)")
    columns = ("Candidate", "Calls", "Parse failures", "With truncation", "Refusals", "Errors")
    for column in columns:
        table.add_column(column)
    for row in counts:
        table.add_row(
            row.candidate,
            str(row.calls),
            str(row.parse_failures),
            str(row.parse_failures_with_truncation),
            str(row.refusals),
            str(row.errors),
        )
    return table
