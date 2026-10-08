from collections.abc import Iterable, Sequence
from typing import Literal

from pydantic import BaseModel

from evals.census_sources import AdvisoryRecord, SourceName


class PrefilterTerm(BaseModel):
    text: str
    kind: Literal["string", "package"]
    added_for: str | None
    reason: str | None


INITIAL_TERMS = (
    PrefilterTerm(text="mcp", kind="string", added_for=None, reason=None),
    PrefilterTerm(text="model context protocol", kind="string", added_for=None, reason=None),
)


def prefilter(
    records: Iterable[AdvisoryRecord], terms: Sequence[PrefilterTerm]
) -> list[AdvisoryRecord]:
    return [record for record in records if matches(record, terms)]


def matches(record: AdvisoryRecord, terms: Sequence[PrefilterTerm]) -> bool:
    return any(_term_matches(record, term) for term in terms)


def _term_matches(record: AdvisoryRecord, term: PrefilterTerm) -> bool:
    text = term.text.casefold()
    if term.kind == "package":
        return text in {_package_name(record, entry).casefold() for entry in record.packages}
    fields = [record.summary, record.details, *record.packages]
    return any(text in field.casefold() for field in fields)


def _package_name(record: AdvisoryRecord, entry: str) -> str:
    if record.source == SourceName.NVD:
        return entry
    return entry.partition(":")[2]
