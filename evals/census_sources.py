import gzip
import hashlib
import json
import re
import subprocess
import zipfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class SourceName(StrEnum):
    GHSA = "ghsa"
    NVD = "nvd"
    OSV = "osv"


class SourceRecord(BaseModel):
    source: SourceName
    id: str
    published: date
    withdrawn: date | None
    rejected: bool


class AdvisoryRecord(SourceRecord):
    aliases: list[str]
    summary: str
    details: str
    packages: list[str]
    references: list[str]


def read_ghsa(clone: Path) -> Iterator[AdvisoryRecord]:
    reviewed = clone / "advisories" / "github-reviewed"
    for path in sorted(reviewed.rglob("*.json")):
        yield _from_osv_format(SourceName.GHSA, json.loads(path.read_bytes()))


def read_nvd(feeds: Sequence[Path]) -> Iterator[AdvisoryRecord]:
    for feed in feeds:
        with gzip.open(feed, "rb") as stream:
            content = json.load(stream)
        for vulnerability in content["vulnerabilities"]:
            yield _from_nvd(vulnerability["cve"])


def read_osv(export: Path) -> Iterator[AdvisoryRecord]:
    with zipfile.ZipFile(export) as archive:
        for name in archive.namelist():
            if name.endswith(".json"):
                yield _from_osv_format(SourceName.OSV, json.loads(archive.read(name)))


def _from_osv_format(source: SourceName, advisory: dict[str, Any]) -> AdvisoryRecord:
    withdrawn = advisory.get("withdrawn")
    return AdvisoryRecord(
        source=source,
        id=advisory["id"],
        aliases=advisory.get("aliases", []),
        published=_utc_day(advisory["published"]),
        withdrawn=_utc_day(withdrawn) if withdrawn else None,
        rejected=False,
        summary=advisory.get("summary", ""),
        details=advisory.get("details", ""),
        packages=[
            f"{affected['package']['ecosystem']}:{affected['package']['name']}"
            for affected in advisory.get("affected", [])
            if "package" in affected
        ],
        references=[reference["url"] for reference in advisory.get("references", [])],
    )


def _from_nvd(cve: dict[str, Any]) -> AdvisoryRecord:
    # The NVD has no summary field: its English description is the advisory's whole text.
    return AdvisoryRecord(
        source=SourceName.NVD,
        id=cve["id"],
        aliases=[],
        published=_utc_day(cve["published"]),
        withdrawn=None,
        rejected=cve.get("vulnStatus") == "Rejected",
        summary="",
        details=next(
            (each["value"] for each in cve.get("descriptions", []) if each["lang"] == "en"), ""
        ),
        packages=_cpe_products(cve),
        references=[reference["url"] for reference in cve.get("references", [])],
    )


def _cpe_products(cve: dict[str, Any]) -> list[str]:
    products = [
        _UNESCAPED_COLON.split(match["criteria"])[4]
        for configuration in cve.get("configurations", [])
        for node in configuration.get("nodes", [])
        for match in node.get("cpeMatch", [])
    ]
    return list(dict.fromkeys(products))


# CPE 2.3 escapes a colon inside a field as "\:".
_UNESCAPED_COLON = re.compile(r"(?<!\\):")


def _utc_day(timestamp: str) -> date:
    moment = datetime.fromisoformat(timestamp)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).date()


@dataclass(frozen=True)
class Download:
    path: Path
    downloaded: date


class SourceFile(BaseModel):
    name: str
    downloaded: date
    sha256: str


class SourceProvenance(BaseModel):
    ghsa_commit: str
    nvd_feeds: list[SourceFile]
    osv_export: SourceFile


def source_provenance(
    ghsa_commit: str, nvd_feeds: Sequence[Download], osv_export: Download
) -> SourceProvenance:
    return SourceProvenance(
        ghsa_commit=ghsa_commit,
        nvd_feeds=[_source_file(feed) for feed in nvd_feeds],
        osv_export=_source_file(osv_export),
    )


def _source_file(download: Download) -> SourceFile:
    return SourceFile(
        name=download.path.name,
        downloaded=download.downloaded,
        sha256=hashlib.sha256(download.path.read_bytes()).hexdigest(),
    )


def clone_commit(clone: Path) -> str:
    head = subprocess.run(
        ["git", "-C", str(clone), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    return head.stdout.strip()
