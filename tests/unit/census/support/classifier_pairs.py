from datetime import date
from typing import Any, NamedTuple

from evals.cve.census.classification import Classification
from tests.unit.support.censuses import a_classification

FIRST = "classifier_a"
SECOND = "classifier_b"


class CensusParts(NamedTuple):
    classifications: dict[str, list[Classification]]
    disclosure_dates: dict[str, date]
    withdrawn: set[str]


def census_parts(
    *pairs: tuple[Classification, Classification],
    disclosed: dict[str, date] | None = None,
    withdrawn: set[str] | None = None,
) -> CensusParts:
    """Each pair is one flaw as the two classifiers see it, disclosed on 2025-06-10 unless
    `disclosed` says otherwise."""
    flaws = [first.flaw for first, _ in pairs]
    return CensusParts(
        classifications={
            FIRST: [first for first, _ in pairs],
            SECOND: [second for _, second in pairs],
        },
        disclosure_dates={flaw: date(2025, 6, 10) for flaw in flaws} | (disclosed or {}),
        withdrawn=withdrawn or set(),
    )


def agreed(flaw: str, **fields: Any) -> tuple[Classification, Classification]:
    return the_same_flaw_seen_as(flaw, fields, fields)


def the_same_flaw_seen_as(
    flaw: str, first: dict[str, Any], second: dict[str, Any]
) -> tuple[Classification, Classification]:
    return a_classification(flaw=flaw, **first), a_classification(flaw=flaw, **second)
