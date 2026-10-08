import gzip
import json
import subprocess
import zipfile
from datetime import date
from pathlib import Path
from typing import Any

from evals.census_sources import AdvisoryRecord, SourceName


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


def an_nvd_cve(cve_id: str, **overrides: Any) -> dict[str, Any]:
    return {
        "id": cve_id,
        "published": "2025-07-02T15:15:27.670",
        "lastModified": "2025-07-03T10:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "es", "value": "El servidor lee archivos."},
            {"lang": "en", "value": "The server reads files outside its root."},
        ],
        "references": [{"url": f"https://example.org/{cve_id}", "source": "cna@example.org"}],
        **overrides,
    }


def cpe_configurations(*criteria: str) -> list[dict[str, Any]]:
    matches = [{"vulnerable": True, "criteria": each} for each in criteria]
    return [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}]


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


def a_committed_repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "README").write_text("advisories")
    git = ["git", "-C", str(repository), "-c", "user.name=a", "-c", "user.email=a@example.org"]
    subprocess.run([*git, "init", "--quiet"], check=True)
    subprocess.run([*git, "add", "README"], check=True)
    subprocess.run([*git, "commit", "--quiet", "--message", "init"], check=True)
    head = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    return repository, head.stdout.strip()


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
