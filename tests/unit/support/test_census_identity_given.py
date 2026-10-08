from datetime import date

import tests.unit.support.test_census_sources_given as sources
from evals.census_sources import AdvisoryRecord, SourceName


def a_ghsa(ghsa_id: str, *aliases: str, published: date = date(2025, 6, 10)) -> AdvisoryRecord:
    return sources.a_record(
        source=SourceName.GHSA, id=ghsa_id, aliases=list(aliases), published=published
    )


def an_nvd(
    cve_id: str, published: date = date(2025, 7, 2), rejected: bool = False
) -> AdvisoryRecord:
    return sources.a_record(
        source=SourceName.NVD, id=cve_id, published=published, rejected=rejected
    )


def an_osv(
    osv_id: str, *aliases: str, published: date | None = date(2025, 6, 12)
) -> AdvisoryRecord:
    return sources.a_record(
        source=SourceName.OSV, id=osv_id, aliases=list(aliases), published=published
    )
