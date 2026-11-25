from datetime import date
from typing import Any

from evals.cve.census.census import CLASSIFIERS, Census, CensusFlaw
from evals.cve.census.classification import Classification
from evals.cve.census.grouping import READERS
from tests.unit.support import advisory_sources, censuses

AN_EXCLUDED_SERVER = "npm:mcp-fetch-server"
AN_ACCEPTANCE_TARGET_FLAW = "CVE-2025-65513"
DISCLOSED = date(2025, 6, 10)


def a_flaw(identifier: str, disclosure: date = DISCLOSED) -> CensusFlaw:
    return censuses.a_flaw_with_records(advisory_sources.an_nvd(identifier, published=disclosure))


def a_withdrawn_flaw(identifier: str) -> CensusFlaw:
    record = advisory_sources.an_nvd(identifier, published=DISCLOSED)
    return censuses.a_flaw_with_records(record.model_copy(update={"withdrawn": date(2025, 6, 11)}))


def a_flaw_without_a_census_identifier(osv_id: str) -> CensusFlaw:
    return censuses.a_flaw_with_records(advisory_sources.an_osv(osv_id, published=DISCLOSED))


def agreed_classifications(specs: dict[str, dict[str, Any]]) -> dict[str, list[Classification]]:
    seen = [censuses.a_classification(flaw=flaw, **overrides) for flaw, overrides in specs.items()]
    return {classifier: seen for classifier in CLASSIFIERS}


def a_census(flaws: list[CensusFlaw], classifications: dict[str, list[Classification]]) -> Census:
    return censuses.recomputed(
        censuses.a_census().model_copy(
            update={
                "flaws": flaws,
                "classifications": classifications,
                "groupings": {reader: [] for reader in READERS},
            }
        )
    )
