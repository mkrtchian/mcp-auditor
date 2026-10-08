from datetime import date
from typing import Any, NamedTuple

from evals.census_classification import (
    Classification,
    Primitive,
    SoftwareKind,
    Transport,
)

FIRST = "classifier_a"
SECOND = "classifier_b"


class CensusParts(NamedTuple):
    classifications: dict[str, list[Classification]]
    disclosure_dates: dict[str, date]
    withdrawn: set[str]


def a_classification(**overrides: Any) -> Classification:
    fields: dict[str, Any] = {
        "flaw": "CVE-2025-1234",
        "software_kind": SoftwareKind.SERVER,
        "server_package": "npm:@acme/files",
        "affected_versions": "< 1.2.0",
        "vulnerable_version": "1.1.0",
        "first_patched_version": "1.2.0",
        "pinnable": True,
        "disclosure_date": date(2025, 6, 10),
        "transport": Transport.STDIO,
        "primitive": Primitive.TOOLS,
        "effect_in_tool_response": True,
        "runs_in_container": True,
        "effect_class": "read_outside_scope",
        "first_failed_criterion": None,
        **overrides,
    }
    return Classification(**fields)


def a_census(
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


def the_same_flaw_seen_as(
    flaw: str, first: dict[str, Any], second: dict[str, Any]
) -> tuple[Classification, Classification]:
    return a_classification(flaw=flaw, **first), a_classification(flaw=flaw, **second)


def agreed(flaw: str, **fields: Any) -> tuple[Classification, Classification]:
    return the_same_flaw_seen_as(flaw, fields, fields)
