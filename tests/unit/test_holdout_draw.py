from datetime import date
from typing import Any

import tests.unit.support.test_census_figures_given as figures
from evals.census_figures import compute_figures
from evals.census_sources import SourceFile, SourceName, SourceProvenance, SourceRecord
from evals.holdout_census import CensusFlaw, Discovery, HoldoutCensus
from evals.holdout_draw import DRAW_SALT, draw_digest, draw_order

AN_EXCLUDED_SERVER = "npm:mcp-fetch-server"
A_BENCHMARK_FLAW = "CVE-2025-65513"


def test_draw_digest_is_the_known_sha256_of_a_fixed_identifier():
    assert DRAW_SALT == "mcp-auditor-holdout:"
    assert (
        draw_digest("CVE-2026-0001")
        == "67fc3923d5883e0917c22e27d5b5dbb948f25abde818ba7278544b1b356fd514"
    )


def test_draw_order_sorts_entries_by_digest_with_each_disclosure_date():
    flaws = [
        _flaw("CVE-2026-0001", disclosure=date(2025, 6, 10)),
        _flaw("CVE-2026-0002", disclosure=date(2026, 7, 1)),
    ]
    census = _census(flaws, _agreed_classifications({"CVE-2026-0001": {}, "CVE-2026-0002": {}}))

    entries = draw_order(census)

    assert [entry.digest for entry in entries] == sorted(
        draw_digest(flaw.identifier) for flaw in flaws
    )
    by_identifier = {entry.identifier: entry for entry in entries}
    assert by_identifier["CVE-2026-0001"].disclosure_date == date(2025, 6, 10)
    assert by_identifier["CVE-2026-0002"].disclosure_date == date(2026, 7, 1)


def test_draw_order_keeps_only_the_draw_order_candidates():
    flaws = [
        _flaw("CVE-2026-0001"),
        _flaw("CVE-2026-0002"),  # a server that does not run in a container is still drawn
        _flaw("CVE-2026-0003", withdrawn=True),
        _flaw("CVE-2026-0004", no_census_identifier=True),
        _flaw("CVE-2026-0005"),
        _flaw(A_BENCHMARK_FLAW),
        _flaw("CVE-2026-0007"),
    ]
    classifications = _agreed_classifications(
        {
            "CVE-2026-0001": {},
            "CVE-2026-0002": {"runs_in_container": False},
            "CVE-2026-0003": {},
            "CVE-2026-0004": {},
            "CVE-2026-0005": {"server_package": AN_EXCLUDED_SERVER},
            A_BENCHMARK_FLAW: {},
            "CVE-2026-0007": {"pinnable": False, "first_failed_criterion": "pinnable"},
        }
    )
    census = _census(flaws, classifications)

    drawn = {entry.identifier for entry in draw_order(census)}

    assert drawn == {"CVE-2026-0001", "CVE-2026-0002"}


def _flaw(
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


def _agreed_classifications(specs: dict[str, dict[str, Any]]) -> dict[str, list[Any]]:
    seen = [figures.a_classification(flaw=flaw, **overrides) for flaw, overrides in specs.items()]
    return {"classifier_1": seen, "classifier_2": seen}


def _census(flaws: list[CensusFlaw], classifications: dict[str, list[Any]]) -> HoldoutCensus:
    dates = {flaw.identifier: flaw.disclosure_date for flaw in flaws}
    withdrawn = {flaw.identifier for flaw in flaws if flaw.withdrawn}
    return HoldoutCensus(
        sources=_provenance(),
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


def _provenance() -> SourceProvenance:
    a_file = SourceFile(name="all.zip", downloaded=date(2026, 10, 8), sha256="0" * 64)
    return SourceProvenance(
        ghsa_commit="1" * 40,
        nvd_feeds=[a_file.model_copy(update={"name": "nvdcve-2.0-2025.json.gz"})],
        osv_export=a_file,
    )
