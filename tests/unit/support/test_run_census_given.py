import subprocess
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import Any

import tests.unit.support.test_census_figures_given as figures
import tests.unit.support.test_census_sources_given as sources
from evals import run_census
from evals.census_classification import Classification, SoftwareKind
from evals.census_prefilter import PrefilterTerm
from evals.census_sources import AdvisoryRecord, SourceName
from evals.census_work import Downloads, Gap, HitDecision, read_jsonl

DOWNLOADED = date(2026, 10, 8)
MCP_SUMMARY = "Path traversal in an MCP filesystem server"


def a_sources_directory(
    tmp_path: Path,
    ghsa: Sequence[dict[str, Any]] = (),
    nvd: Sequence[dict[str, Any]] = (),
    osv: Sequence[dict[str, Any]] = (),
) -> Path:
    directory = tmp_path / "sources"
    directory.mkdir()
    clone = sources.a_ghsa_clone(directory, *ghsa)
    clone.mkdir(exist_ok=True)
    _commit_all(clone)
    sources.an_nvd_feed(directory, *nvd)
    sources.an_osv_export(directory, *osv)
    return directory


def an_mcp_advisory(advisory_id: str, *aliases: str, **overrides: Any) -> dict[str, Any]:
    return sources.an_osv_advisory(
        advisory_id, aliases=list(aliases), summary=MCP_SUMMARY, **overrides
    )


def an_advisory_without_mcp(advisory_id: str, *aliases: str, **overrides: Any) -> dict[str, Any]:
    return sources.an_osv_advisory(advisory_id, aliases=list(aliases), **overrides)


def a_work_directory(
    tmp_path: Path,
    decisions: Sequence[HitDecision] = (),
    gaps: Sequence[Gap] = (),
    widenings: Sequence[PrefilterTerm] = (),
    classifiers: Sequence[Sequence[Classification]] = (),
) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    _write_jsonl(work / "decisions_ghsa.jsonl", decisions)
    _write_jsonl(work / "gaps_ghsa.jsonl", gaps)
    _write_jsonl(work / "widenings.jsonl", widenings)
    for name, own in zip(("classifier_1", "classifier_2"), classifiers, strict=False):
        _write_jsonl(work / f"{name}.jsonl", own)
    downloads = Downloads(nvd={"nvdcve-2.0-2025.json.gz": DOWNLOADED}, osv=DOWNLOADED)
    (work / "downloads.json").write_text(downloads.model_dump_json())
    return work


def kept(source: SourceName, source_id: str) -> HitDecision:
    return HitDecision(
        source=source,
        source_id=source_id,
        decision="keep",
        software_kind=figures.a_classification().software_kind,
        reason="A filesystem MCP server.",
        agent=f"{source} collector",
    )


def dropped(source: SourceName, source_id: str) -> HitDecision:
    return HitDecision(
        source=source,
        source_id=source_id,
        decision="drop",
        software_kind=SoftwareKind.OTHER,
        reason="Not MCP software.",
        agent=f"{source} collector",
    )


def a_gap(source_id: str) -> Gap:
    return Gap(
        flaw_id=source_id,
        source_id=source_id,
        where_found="the vendor's other advisories",
        agent="ghsa collector",
    )


def a_package_widening(package: str, added_for: str) -> PrefilterTerm:
    return PrefilterTerm(
        text=package, kind="package", added_for=added_for, reason="a missed server"
    )


def both_classifiers_classifying(*flaws: tuple[str, date]) -> list[list[Classification]]:
    own = [
        figures.a_classification(flaw=flaw, disclosure_date=disclosed) for flaw, disclosed in flaws
    ]
    return [own, own]


def run(command: str, sources_directory: Path, work: Path, *options: str) -> int:
    return run_census.main(
        [command, "--sources", str(sources_directory), "--work", str(work), *options]
    )


def hit_ids(work: Path, source: SourceName) -> list[str]:
    return [record.id for record in read_jsonl(work / f"hits_{source}.jsonl", AdvisoryRecord)]


def _write_jsonl(path: Path, records: Sequence[Any]) -> None:
    path.write_text("".join(record.model_dump_json() + "\n" for record in records))


def _commit_all(repository: Path) -> None:
    git = ["git", "-C", str(repository), "-c", "user.name=a", "-c", "user.email=a@example.org"]
    subprocess.run([*git, "init", "--quiet"], check=True)
    subprocess.run([*git, "add", "--all"], check=True)
    subprocess.run([*git, "commit", "--quiet", "--allow-empty", "--message", "init"], check=True)
