import gzip
import json
import zipfile
from datetime import date
from pathlib import Path
from typing import Any

from evals.cve.census.sources import AdvisoryRecord, SourceName


def a_ghsa(ghsa_id: str, *aliases: str, published: date = date(2025, 6, 10)) -> AdvisoryRecord:
    return a_record(source=SourceName.GHSA, id=ghsa_id, aliases=list(aliases), published=published)


def an_nvd(
    identifier: str, published: date = date(2025, 7, 2), rejected: bool = False
) -> AdvisoryRecord:
    return a_record(source=SourceName.NVD, id=identifier, published=published, rejected=rejected)


def an_osv(
    osv_id: str, *aliases: str, published: date | None = date(2025, 6, 12)
) -> AdvisoryRecord:
    return a_record(source=SourceName.OSV, id=osv_id, aliases=list(aliases), published=published)


def a_record(**overrides: Any) -> AdvisoryRecord:
    fields: dict[str, Any] = {
        "source": SourceName.GHSA,
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": [],
        "published": date(2025, 6, 10),
        "withdrawn": None,
        "rejected": False,
        "summary": "Path traversal in a file server",
        "details": "The server reads files outside its root.",
        "packages": ["npm:@acme/files"],
        "references": [],
        **overrides,
    }
    return AdvisoryRecord(**fields)


def an_osv_advisory(advisory_id: str, **overrides: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.6.0",
        "id": advisory_id,
        "aliases": [],
        "published": "2025-06-10T23:30:00Z",
        "modified": "2025-06-11T08:00:00Z",
        "summary": "Path traversal in a file server",
        "details": "The server reads files outside its root.",
        "affected": [{"package": {"ecosystem": "npm", "name": "@acme/files"}}],
        "references": [{"type": "ADVISORY", "url": f"https://example.org/{advisory_id}"}],
        **overrides,
    }


def a_ghsa_clone(tmp_path: Path, *advisories: dict[str, Any]) -> Path:
    clone = tmp_path / "advisory-database"
    for advisory in advisories:
        year, month = advisory["published"][:4], advisory["published"][5:7]
        folder = clone / "advisories" / "github-reviewed" / year / month / advisory["id"]
        folder.mkdir(parents=True)
        (folder / f"{advisory['id']}.json").write_text(json.dumps(advisory))
    return clone


def an_nvd_cve(identifier: str, **overrides: Any) -> dict[str, Any]:
    return {
        "id": identifier,
        "published": "2025-07-02T15:15:27.670",
        "lastModified": "2025-07-03T10:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "es", "value": "El servidor lee archivos."},
            {"lang": "en", "value": "The server reads files outside its root."},
        ],
        "references": [{"url": f"https://example.org/{identifier}", "source": "cna@example.org"}],
        **overrides,
    }


def an_nvd_feed(tmp_path: Path, *cves: dict[str, Any], year: int = 2025) -> Path:
    feed = tmp_path / f"nvdcve-2.0-{year}.json.gz"
    vulnerabilities = [{"cve": cve} for cve in cves]
    with gzip.open(feed, "wt") as stream:
        json.dump({"format": "NVD_CVE", "vulnerabilities": vulnerabilities}, stream)
    return feed


def an_osv_export(tmp_path: Path, *records: dict[str, Any]) -> Path:
    export = tmp_path / "all.zip"
    with zipfile.ZipFile(export, "w") as archive:
        for record in records:
            archive.writestr(f"{record['id']}.json", json.dumps(record))
    return export
