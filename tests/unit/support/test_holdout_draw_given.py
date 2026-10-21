from datetime import date
from typing import Any

import tests.unit.support.test_census_figures_given as figures
import tests.unit.support.test_holdout_census_given as census_given
from evals.census_figures import compute_figures
from evals.census_sources import SourceName, SourceRecord
from evals.holdout_census import CensusFlaw, Discovery, HoldoutCensus

AN_EXCLUDED_SERVER = "npm:mcp-fetch-server"
A_BENCHMARK_FLAW = "CVE-2025-65513"


def a_flaw(
    identifier: str,
    disclosure: date = date(2025, 6, 10),
    no_census_identifier: bool = False,
    withdrawn: bool = False,
) -> CensusFlaw:
    record = SourceRecord(
        source=SourceName.NVD,
        id=identifier,
        published=disclosure,
        withdrawn=date(2025, 6, 11) if withdrawn else None,
        rejected=False,
    )
    return CensusFlaw(
        identifier=identifier,
        no_census_identifier=no_census_identifier,
        ids=[identifier],
        records=[record],
        disclosure_date=disclosure,
        found_by=[Discovery.PREFILTER],
    )


def agreed_classifications(specs: dict[str, dict[str, Any]]) -> dict[str, list[Any]]:
    seen = [figures.a_classification(flaw=flaw, **overrides) for flaw, overrides in specs.items()]
    return {"classifier_1": seen, "classifier_2": seen}


def a_census(flaws: list[CensusFlaw], classifications: dict[str, list[Any]]) -> HoldoutCensus:
    dates = {flaw.identifier: flaw.disclosure_date for flaw in flaws}
    withdrawn = {flaw.identifier for flaw in flaws if flaw.withdrawn}
    return HoldoutCensus(
        sources=census_given.a_provenance(),
        agents=[],
        prefilter=[],
        hits=[],
        flaws=flaws,
        vulnerablemcp=[],
        classifications=classifications,
        date_mismatches=[],
        figures=compute_figures(classifications, dates, withdrawn),
        groupings={},
        known_gap={},
    )
