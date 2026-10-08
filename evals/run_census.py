"""Build the holdout census from the three source exports and the census agents' work files.

The work directory, the operating procedure and the download commands are in
evals/holdout_census_method.md. This module reads and writes files and does nothing else:
what the collection holds is computed by evals/census_progress.py.
"""

import argparse
import itertools
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from evals import eval_display as display
from evals.census_classification import Classification
from evals.census_identity import Flaw
from evals.census_prefilter import PrefilterTerm
from evals.census_progress import AssemblyInputs, Collection, CollectionWork
from evals.census_sources import (
    AdvisoryRecord,
    Download,
    SourceName,
    SourceProvenance,
    clone_commit,
    read_ghsa,
    read_nvd,
    read_osv,
    source_provenance,
)
from evals.census_work import (
    AgentRecord,
    Downloads,
    Gap,
    HitDecision,
    RecallFinding,
    VulnerableMcpEntry,
    read_jsonl,
)
from evals.eval_session import Refused
from evals.holdout_census import CLASSIFIERS, load_census
from evals.honeypots import REPO_ROOT

SOURCES = REPO_ROOT / "output" / "holdout_census" / "sources"
WORK = REPO_ROOT / "output" / "holdout_census" / "work"
CENSUS_PATH = REPO_ROOT / "evals" / "holdout_census.json"
INCOMPLETE_EXIT = 1
REFUSED_EXIT = 3

# Written from the docstring of evals/cve_grammar.py, which stays untouched.
GRAMMAR_CLASSES = """\
# The effect classes of the grammar

A class names the effect a client of the server can observe in a tool response, not a CWE.
An argument injection is filed under the effect it produces. A flaw whose effect falls in
none of these three classes gets a class name of your own.

- `read_outside_scope`: the server reads data outside the scope it declares, such as a file
  outside the directories it allows, and returns it.
- `command_execution`: the server executes a command of the caller's choice.
- `internal_fetch`: the server fetches an internal address of the caller's choice and returns
  what it got.
"""

_ADVISORY_PAGES = {
    SourceName.GHSA: "https://github.com/advisories/{}",
    SourceName.NVD: "https://nvd.nist.gov/vuln/detail/{}",
    SourceName.OSV: "https://osv.dev/vulnerability/{}",
}


class Dossier(BaseModel):
    identifier: str
    ids: list[str]
    advisory_urls: list[str]
    records: list[AdvisoryRecord]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return args.command(args)
    except Refused as refusal:
        display.print_refusal(refusal.title, refusal.reasons)
        return REFUSED_EXIT
    except ValueError as error:
        # A malformed export or work file, which must not read as an incomplete census (exit 1).
        display.print_refusal("Refused: a file is malformed.", [str(error)])
        return REFUSED_EXIT


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the CVE holdout census.")
    commands = parser.add_subparsers(required=True)
    for name, command, help_text in [
        ("prefilter", _prefilter, "write the undecided pre-filter hits of each source"),
        ("status", _status, "list what is left, exit 0 when the census is complete"),
        ("classify-dossier", _classify_dossier, "write the classifiers' input"),
        ("assemble", _assemble, f"write {CENSUS_PATH.relative_to(REPO_ROOT)}"),
    ]:
        subparser = commands.add_parser(name, help=help_text)
        subparser.set_defaults(command=command)
        subparser.add_argument("--sources", type=Path, default=SOURCES)
        subparser.add_argument("--work", type=Path, default=WORK)
        if name == "classify-dossier":
            subparser.add_argument("--out", type=Path, required=True)
        if name == "assemble":
            subparser.add_argument("--census", type=Path, default=CENSUS_PATH)
    return parser


def _prefilter(args: argparse.Namespace) -> int:
    collection = _collection(args.sources, args.work)
    undecided = collection.undecided()
    for source in SourceName:
        hits, new = collection.hits[source], undecided[source]
        lines = "".join(record.model_dump_json() + "\n" for record in new)
        (args.work / f"hits_{source}.jsonl").write_text(lines)
        print(f"{source}: {len(hits)} hits, {len(hits) - len(new)} already decided, {len(new)} new")
    for entry in collection.term_hits():
        print(f"term {entry.term.text!r} ({entry.term.kind}): {entry.hit_count} hits")
    return 0


def _status(args: argparse.Namespace) -> int:
    remaining = _collection(args.sources, args.work).remaining()
    if not remaining:
        print("The census is complete.")
        return 0
    print("The census is incomplete:")
    print("\n".join(f"- {line}" for line in remaining))
    return INCOMPLETE_EXIT


def _classify_dossier(args: argparse.Namespace) -> int:
    members = _complete_collection(args).census_members()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    for flaw, entry in members:
        dossier = _dossier(flaw, entry.identifier)
        (out / f"{dossier.identifier}.json").write_text(dossier.model_dump_json(indent=2))
    schema = json.dumps(Classification.model_json_schema(), indent=2)
    (out / "classification_schema.json").write_text(schema)
    (out / "grammar_classes.md").write_text(GRAMMAR_CLASSES)
    print(f"{len(members)} dossiers written to {out}")
    return 0


def _assemble(args: argparse.Namespace) -> int:
    collection = _complete_collection(args)
    identifiers = [entry.identifier for _, entry in collection.census_members()]
    inputs = AssemblyInputs(
        sources=_provenance(args.sources, args.work),
        agents=_read_all(args.work, "agents", AgentRecord),
        classifications=_classifications(args.work, identifiers),
    )
    census = collection.census(inputs)
    path: Path = args.census
    draft = path.with_name(f"{path.name}.draft")
    draft.write_text(census.model_dump_json(indent=2) + "\n")
    try:
        load_census(draft)
    except ValueError as error:
        draft.unlink()
        raise Refused("Assembly refused: the census does not load.", [str(error)]) from error
    draft.replace(path)
    print(f"{len(census.flaws)} flaws written to {path}")
    return 0


def _complete_collection(args: argparse.Namespace) -> Collection:
    collection = _collection(args.sources, args.work)
    remaining = collection.remaining()
    if remaining:
        raise Refused("Refused: the census is incomplete.", remaining)
    return collection


def _collection(sources: Path, work: Path) -> Collection:
    missing = [
        str(path)
        for path in (sources / "advisory-database", sources / "all.zip")
        if not path.exists()
    ] + ([] if _nvd_feeds(sources) else [f"{sources}/nvdcve-2.0-*.json.gz"])
    if missing:
        raise Refused("Refused: an export is missing.", missing)
    work.mkdir(parents=True, exist_ok=True)
    records = itertools.chain(
        read_ghsa(sources / "advisory-database"),
        read_nvd(_nvd_feeds(sources)),
        read_osv(sources / "all.zip"),
    )
    return Collection(records, _work(work))


def _work(work: Path) -> CollectionWork:
    return CollectionWork(
        decisions=_read_all(work, "decisions", HitDecision),
        gaps=_read_all(work, "gaps", Gap),
        recall=_read_all(work, "recall", RecallFinding),
        vulnerablemcp=_read_all(work, "vulnerablemcp", VulnerableMcpEntry),
        widenings=_read_all(work, "widenings", PrefilterTerm),
    )


def _read_all[Record: BaseModel](work: Path, stem: str, schema: type[Record]) -> list[Record]:
    paths = sorted(work.glob(f"{stem}*.jsonl"))
    return [record for path in paths for record in read_jsonl(path, schema)]


def _nvd_feeds(sources: Path) -> list[Path]:
    return sorted(sources.glob("nvdcve-2.0-*.json.gz"))


def _dossier(flaw: Flaw, identifier: str) -> Dossier:
    return Dossier(
        identifier=identifier,
        ids=sorted(flaw.ids),
        advisory_urls=[_ADVISORY_PAGES[record.source].format(record.id) for record in flaw.records],
        records=flaw.records,
    )


def _provenance(sources: Path, work: Path) -> SourceProvenance:
    path = work / "downloads.json"
    if not path.exists():
        raise Refused("Assembly refused.", [f"{path} is missing"])
    downloads = Downloads.model_validate_json(path.read_text())
    feeds = _nvd_feeds(sources)
    undated = [feed.name for feed in feeds if feed.name not in downloads.nvd]
    if undated:
        raise Refused("Assembly refused: a feed has no download date.", undated)
    return source_provenance(
        clone_commit(sources / "advisory-database"),
        [Download(feed, downloads.nvd[feed.name]) for feed in feeds],
        Download(sources / "all.zip", downloads.osv),
    )


def _classifications(work: Path, identifiers: list[str]) -> dict[str, list[Classification]]:
    classifications: dict[str, list[Classification]] = {}
    problems: list[str] = []
    for classifier in CLASSIFIERS:
        path = work / f"{classifier}.jsonl"
        if not path.exists():
            problems.append(f"{path} is missing")
            continue
        own = read_jsonl(path, Classification)
        classified = {classification.flaw for classification in own}
        problems += [
            f"{classifier} misses flaw {flaw}" for flaw in identifiers if flaw not in classified
        ]
        classifications[classifier] = own
    if problems:
        raise Refused("Assembly refused: a classifier output is incomplete.", problems)
    return classifications


if __name__ == "__main__":
    sys.exit(main())
