import hashlib
from datetime import date
from pathlib import Path

import tests.unit.support.test_census_sources_given as given
from evals.census_sources import (
    AdvisoryRecord,
    Download,
    SourceName,
    clone_commit,
    read_ghsa,
    read_nvd,
    read_osv,
    source_provenance,
)


def test_the_ghsa_reader_yields_each_reviewed_advisory(tmp_path: Path):
    advisory = given.an_osv_advisory(
        "GHSA-aaaa-bbbb-cccc",
        aliases=["CVE-2025-1234"],
        withdrawn="2025-08-01T12:00:00Z",
    )
    clone = given.a_ghsa_clone(tmp_path, advisory)

    [record] = read_ghsa(clone)

    assert record == AdvisoryRecord(
        source=SourceName.GHSA,
        id="GHSA-aaaa-bbbb-cccc",
        aliases=["CVE-2025-1234"],
        published=date(2025, 6, 10),
        withdrawn=date(2025, 8, 1),
        rejected=False,
        summary="Path traversal in a file server",
        details="The server reads files outside its root.",
        packages=["npm:@acme/files"],
        references=["https://example.org/GHSA-aaaa-bbbb-cccc"],
    )


def test_an_offset_moves_the_published_day_to_its_utc_day(tmp_path: Path):
    advisory = given.an_osv_advisory("GHSA-aaaa-bbbb-cccc", published="2025-06-10T23:30:00-02:00")
    clone = given.a_ghsa_clone(tmp_path, advisory)

    [record] = read_ghsa(clone)

    assert record.published == date(2025, 6, 11)


def test_the_nvd_reader_marks_a_rejected_cve_and_reads_its_cpe_products(tmp_path: Path):
    cve = given.an_nvd_cve(
        "CVE-2025-53109",
        vulnStatus="Rejected",
        configurations=given.cpe_configurations(
            "cpe:2.3:a:anthropic:filesystem_mcp_server:*:*:*:*:*:node.js:*:*",
            "cpe:2.3:a:anthropic:filesystem_mcp_server:0.6.2:*:*:*:*:node.js:*:*",
        ),
    )
    feed = given.an_nvd_feed(tmp_path, cve)

    [record] = read_nvd([feed])

    assert record == AdvisoryRecord(
        source=SourceName.NVD,
        id="CVE-2025-53109",
        aliases=[],
        published=date(2025, 7, 2),
        withdrawn=None,
        rejected=True,
        summary="",
        details="The server reads files outside its root.",
        packages=["filesystem_mcp_server"],
        references=["https://example.org/CVE-2025-53109"],
    )


def test_an_nvd_record_without_configuration_has_no_packages(tmp_path: Path):
    feed = given.an_nvd_feed(tmp_path, given.an_nvd_cve("CVE-2025-1"))

    [record] = read_nvd([feed])

    assert (record.packages, record.rejected) == ([], False)


def test_an_escaped_colon_does_not_split_a_cpe_field(tmp_path: Path):
    cve = given.an_nvd_cve(
        "CVE-2025-1",
        configurations=given.cpe_configurations(
            r"cpe:2.3:a:acme\:labs:files_mcp:1.0:*:*:*:*:*:*:*"
        ),
    )
    feed = given.an_nvd_feed(tmp_path, cve)

    [record] = read_nvd([feed])

    assert record.packages == ["files_mcp"]


def test_the_nvd_reader_reads_every_feed(tmp_path: Path):
    first = given.an_nvd_feed(tmp_path, given.an_nvd_cve("CVE-2024-1"), year=2024)
    second = given.an_nvd_feed(tmp_path, given.an_nvd_cve("CVE-2025-1"), year=2025)

    records = read_nvd([first, second])

    assert [record.id for record in records] == ["CVE-2024-1", "CVE-2025-1"]


def test_the_osv_reader_reads_the_zip_and_keeps_the_aliases(tmp_path: Path):
    pysec = given.an_osv_advisory(
        "PYSEC-2025-12", aliases=["CVE-2025-1234"], affected=[], references=[]
    )
    del pysec["summary"]
    export = given.an_osv_export(tmp_path, pysec)

    [record] = read_osv(export)

    assert record == AdvisoryRecord(
        source=SourceName.OSV,
        id="PYSEC-2025-12",
        aliases=["CVE-2025-1234"],
        published=date(2025, 6, 10),
        withdrawn=None,
        rejected=False,
        summary="",
        details="The server reads files outside its root.",
        packages=[],
        references=[],
    )


def test_the_provenance_records_the_hash_of_each_download_and_its_date(tmp_path: Path):
    feed = given.an_nvd_feed(tmp_path, given.an_nvd_cve("CVE-2025-1"))
    export = given.an_osv_export(tmp_path, given.an_osv_advisory("PYSEC-2025-12"))

    provenance = source_provenance(
        "0123abcd",
        nvd_feeds=[Download(feed, date(2026, 10, 8))],
        osv_export=Download(export, date(2026, 10, 9)),
    )

    [nvd_feed] = provenance.nvd_feeds
    assert provenance.ghsa_commit == "0123abcd"
    assert (nvd_feed.name, nvd_feed.downloaded) == ("nvdcve-2.0-2025.json.gz", date(2026, 10, 8))
    assert nvd_feed.sha256 == hashlib.sha256(feed.read_bytes()).hexdigest()
    assert (provenance.osv_export.name, provenance.osv_export.downloaded) == (
        "all.zip",
        date(2026, 10, 9),
    )
    assert provenance.osv_export.sha256 == hashlib.sha256(export.read_bytes()).hexdigest()


def test_the_clone_commit_is_its_head(tmp_path: Path):
    repository, head = given.a_committed_repository(tmp_path)

    assert clone_commit(repository) == head
