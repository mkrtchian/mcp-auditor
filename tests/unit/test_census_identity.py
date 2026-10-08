from datetime import date
from pathlib import Path

import pytest

import tests.unit.support.test_census_identity_given as given
import tests.unit.support.test_census_sources_given as sources
from evals.census_identity import census_identifier, disclosure_date, merge
from evals.census_sources import read_osv


def test_a_ghsa_its_nvd_record_and_an_osv_record_are_one_flaw_identified_by_the_cve():
    ghsa = given.a_ghsa("GHSA-aaaa-bbbb-cccc", "CVE-2025-1234")
    nvd = given.an_nvd("CVE-2025-1234")
    osv = given.an_osv("PYSEC-2025-1", "GHSA-aaaa-bbbb-cccc")

    [flaw] = merge([ghsa, nvd, osv], recorded={})

    assert flaw.identifier == "CVE-2025-1234"
    assert flaw.ids == {"GHSA-aaaa-bbbb-cccc", "CVE-2025-1234", "PYSEC-2025-1"}
    assert flaw.records == [ghsa, nvd, osv]


def test_cve_ids_are_ordered_by_year_then_number_as_integers():
    ghsa = given.a_ghsa("GHSA-aaaa-bbbb-cccc", "CVE-2025-10000", "CVE-2025-9999")

    [flaw] = merge([ghsa], recorded={})

    assert flaw.identifier == "CVE-2025-9999"


def test_a_rejected_lower_cve_is_skipped():
    ghsa = given.a_ghsa("GHSA-aaaa-bbbb-cccc", "CVE-2025-1000", "CVE-2025-2000")
    rejected = given.an_nvd("CVE-2025-1000", rejected=True)

    [flaw] = merge([ghsa, rejected], recorded={})

    assert flaw.identifier == "CVE-2025-2000"


def test_without_a_cve_the_earliest_published_ghsa_is_kept():
    later = given.a_ghsa("GHSA-aaaa-aaaa-aaaa", published=date(2025, 6, 2))
    earlier = given.a_ghsa("GHSA-zzzz-zzzz-zzzz", published=date(2025, 6, 1))
    ids = {"GHSA-aaaa-aaaa-aaaa", "GHSA-zzzz-zzzz-zzzz"}

    assert census_identifier(ids, [later, earlier]) == "GHSA-zzzz-zzzz-zzzz"


def test_ghsa_ids_published_the_same_day_are_ordered_by_string():
    first = given.a_ghsa("GHSA-zzzz-zzzz-zzzz", "GHSA-aaaa-aaaa-aaaa")
    second = given.a_ghsa("GHSA-aaaa-aaaa-aaaa")

    [flaw] = merge([first, second], recorded={})

    assert flaw.identifier == "GHSA-aaaa-aaaa-aaaa"


def test_an_osv_only_record_has_no_census_identifier():
    [flaw] = merge([given.an_osv("PYSEC-2025-1")], recorded={})

    assert flaw.identifier is None


def test_a_recorded_identifier_survives_a_newly_seen_lower_cve():
    ghsa = given.a_ghsa("GHSA-aaaa-bbbb-cccc", "CVE-2025-1000", "CVE-2025-2000")
    recorded = {"CVE-2025-2000": {"CVE-2025-2000", "GHSA-aaaa-bbbb-cccc"}}

    [flaw] = merge([ghsa], recorded=recorded)

    assert flaw.identifier == "CVE-2025-2000"


def test_a_flaw_meeting_two_recorded_identifiers_is_refused():
    ghsa = given.a_ghsa("GHSA-aaaa-bbbb-cccc", "CVE-2025-1000", "CVE-2025-2000")
    recorded = {"CVE-2025-1000": {"CVE-2025-1000"}, "CVE-2025-2000": {"CVE-2025-2000"}}

    with pytest.raises(ValueError, match=r"CVE-2025-1000.*CVE-2025-2000"):
        merge([ghsa], recorded=recorded)


def test_related_ids_do_not_link_records(tmp_path: Path):
    ghsa = given.a_ghsa("GHSA-aaaa-bbbb-cccc")
    export = sources.an_osv_export(
        tmp_path, sources.an_osv_advisory("PYSEC-2025-1", related=["GHSA-aaaa-bbbb-cccc"])
    )

    flaws = merge([ghsa, *read_osv(export)], recorded={})

    assert [flaw.identifier for flaw in flaws] == ["GHSA-aaaa-bbbb-cccc", None]


def test_a_ghsa_aliasing_an_nvd_record_takes_the_earlier_nvd_date():
    ghsa = given.a_ghsa("GHSA-aaaa-bbbb-cccc", "CVE-2025-1234", published=date(2025, 7, 9))
    nvd = given.an_nvd("CVE-2025-1234", published=date(2025, 7, 2))

    [flaw] = merge([ghsa, nvd], recorded={})

    assert disclosure_date(flaw.records) == date(2025, 7, 2)


def test_a_record_without_a_date_leaves_the_flaw_its_earliest_known_date():
    ghsa = given.a_ghsa("GHSA-aaaa-bbbb-cccc", published=date(2025, 7, 9))
    undated = given.an_osv("PYSEC-2025-1", "GHSA-aaaa-bbbb-cccc", published=None)

    [flaw] = merge([ghsa, undated], recorded={})

    assert disclosure_date(flaw.records) == date(2025, 7, 9)


def test_a_flaw_whose_records_all_lack_a_date_has_no_disclosure_date():
    undated = given.an_osv("PYSEC-2025-1", published=None)

    assert disclosure_date([undated]) is None
