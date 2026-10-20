"""The deterministic draw order the maintainer walks.

The order is the rule's: ascending order of the lowercase hex SHA-256 of the UTF-8 string
`"mcp-auditor-holdout:" + identifier`. It is the backbone of the walk; the skips and where the
walk stops (20 targets at the draw, more for an addition) depend on draw state the maintainer
tracks as calibration proceeds and live in the draw record, not here.
"""

import hashlib
from dataclasses import dataclass
from datetime import date

from evals.census_grouping import draw_order_flaws
from evals.holdout_census import HoldoutCensus, draw_candidates

DRAW_SALT = "mcp-auditor-holdout:"


def draw_digest(identifier: str) -> str:
    return hashlib.sha256((DRAW_SALT + identifier).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DrawEntry:
    digest: str
    identifier: str
    disclosure_date: date


def draw_order(census: HoldoutCensus) -> list[DrawEntry]:
    identifiers = draw_order_flaws(census.classifications, draw_candidates(census.flaws))
    disclosure_dates = {flaw.identifier: flaw.disclosure_date for flaw in census.flaws}
    entries = [
        DrawEntry(
            digest=draw_digest(identifier),
            identifier=identifier,
            disclosure_date=disclosure_dates[identifier],
        )
        for identifier in identifiers
    ]
    return sorted(entries, key=lambda entry: (entry.digest, entry.identifier))
