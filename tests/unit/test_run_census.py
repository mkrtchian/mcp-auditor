from datetime import date
from pathlib import Path

import pytest

import tests.unit.support.test_census_sources_given as sources
import tests.unit.support.test_run_census_given as given
from evals import run_census
from evals.census_sources import SourceName
from evals.holdout_census import Discovery, load_census

GHSA = SourceName.GHSA
OSV = SourceName.OSV
A_GHSA = "GHSA-aaaa-bbbb-cccc"
ITS_CVE = "CVE-2025-0001"
OTHER_GHSA = "GHSA-dddd-eeee-ffff"
AN_OSV_ONLY = "PYSEC-2025-2"
AFTER_THE_BOUND = "2026-10-09T10:00:00Z"
COMPLETE, INCOMPLETE, REFUSED = 0, 1, 3


def test_status_is_incomplete_while_a_hit_is_undecided(tmp_path: Path):
    sources_directory = given.a_sources_directory(tmp_path, ghsa=[given.an_mcp_advisory(A_GHSA)])
    work = given.a_work_directory(tmp_path)

    assert given.run("status", sources_directory, work) == INCOMPLETE


def test_status_is_incomplete_while_a_gap_is_not_matched_by_the_prefilter(tmp_path: Path):
    sources_directory = given.a_sources_directory(
        tmp_path,
        ghsa=[given.an_mcp_advisory(A_GHSA), given.an_advisory_without_mcp(OTHER_GHSA)],
    )
    work = given.a_work_directory(
        tmp_path, decisions=[given.kept(GHSA, A_GHSA)], gaps=[given.a_gap(OTHER_GHSA)]
    )

    assert given.run("status", sources_directory, work) == INCOMPLETE


def test_status_is_complete_once_every_hit_of_the_widened_prefilter_is_decided(tmp_path: Path):
    sources_directory = given.a_sources_directory(
        tmp_path,
        ghsa=[given.an_mcp_advisory(A_GHSA), given.an_advisory_without_mcp(OTHER_GHSA)],
    )
    work = given.a_work_directory(
        tmp_path,
        decisions=[given.kept(GHSA, A_GHSA), given.kept(GHSA, OTHER_GHSA)],
        gaps=[given.a_gap(OTHER_GHSA)],
        widenings=[given.a_package_widening("@acme/files", added_for=OTHER_GHSA)],
    )

    assert given.run("status", sources_directory, work) == COMPLETE


def test_status_refuses_a_malformed_work_line_rather_than_reading_it_as_incomplete(
    tmp_path: Path,
):
    sources_directory = given.a_sources_directory(tmp_path, ghsa=[given.an_mcp_advisory(A_GHSA)])
    work = given.a_work_directory(tmp_path)
    (work / "decisions_ghsa.jsonl").write_text('{"source": "ghsa"}\n')

    assert given.run("status", sources_directory, work) == REFUSED


def test_prefilter_leaves_out_of_the_osv_hits_a_record_whose_ghsa_advisory_is_a_hit(
    tmp_path: Path,
):
    sources_directory = given.a_sources_directory(
        tmp_path,
        ghsa=[given.an_mcp_advisory(A_GHSA, ITS_CVE)],
        osv=[given.an_mcp_advisory("PYSEC-2025-1", ITS_CVE), given.an_mcp_advisory(AN_OSV_ONLY)],
    )
    work = given.a_work_directory(tmp_path)

    given.run("prefilter", sources_directory, work)

    assert given.hit_ids(work, OSV) == [AN_OSV_ONLY]


def test_prefilter_keeps_a_hit_published_after_the_bound_when_its_flaw_is_disclosed_within(
    tmp_path: Path,
):
    sources_directory = given.a_sources_directory(
        tmp_path,
        ghsa=[
            given.an_mcp_advisory(A_GHSA, ITS_CVE, published=AFTER_THE_BOUND),
            given.an_mcp_advisory(OTHER_GHSA, published=AFTER_THE_BOUND),
        ],
        nvd=[sources.an_nvd_cve(ITS_CVE)],
    )
    work = given.a_work_directory(tmp_path)

    given.run("prefilter", sources_directory, work)

    assert given.hit_ids(work, GHSA) == [A_GHSA]


def test_prefilter_lists_only_the_undecided_hits(tmp_path: Path):
    sources_directory = given.a_sources_directory(
        tmp_path, ghsa=[given.an_mcp_advisory(A_GHSA), given.an_mcp_advisory(OTHER_GHSA)]
    )
    work = given.a_work_directory(tmp_path, decisions=[given.kept(GHSA, A_GHSA)])

    given.run("prefilter", sources_directory, work)

    assert given.hit_ids(work, GHSA) == [OTHER_GHSA]


def test_assemble_refuses_while_the_census_is_incomplete(tmp_path: Path):
    sources_directory = given.a_sources_directory(tmp_path, ghsa=[given.an_mcp_advisory(A_GHSA)])
    work = given.a_work_directory(tmp_path)
    census = tmp_path / "holdout_census.json"

    exit_code = given.run("assemble", sources_directory, work, "--census", str(census))

    assert exit_code == REFUSED
    assert not census.exists()


def test_assemble_refuses_when_a_classifier_misses_a_flaw(tmp_path: Path):
    sources_directory = given.a_sources_directory(
        tmp_path, ghsa=[given.an_mcp_advisory(A_GHSA), given.an_mcp_advisory(OTHER_GHSA)]
    )
    work = given.a_work_directory(
        tmp_path,
        decisions=[given.kept(GHSA, A_GHSA), given.kept(GHSA, OTHER_GHSA)],
        classifiers=given.both_classifiers_classifying((A_GHSA, date(2025, 6, 10))),
    )
    census = tmp_path / "holdout_census.json"

    exit_code = given.run("assemble", sources_directory, work, "--census", str(census))

    assert exit_code == REFUSED
    assert not census.exists()


def test_assemble_writes_a_census_that_loads(tmp_path: Path):
    sources_directory, work = _a_complete_census_collection(tmp_path)
    census = tmp_path / "holdout_census.json"

    exit_code = given.run("assemble", sources_directory, work, "--census", str(census))

    assert exit_code == COMPLETE
    loaded = load_census(census)
    assert {flaw.identifier: flaw.found_by for flaw in loaded.flaws} == {
        ITS_CVE: [Discovery.PREFILTER],
        AN_OSV_ONLY: [Discovery.PREFILTER],
    }
    assert [mismatch.flaw for mismatch in loaded.date_mismatches] == [ITS_CVE, ITS_CVE]


def test_classify_dossier_writes_one_file_per_flaw_the_schema_and_the_grammar_classes(
    tmp_path: Path,
):
    sources_directory, work = _a_complete_census_collection(tmp_path)
    dossier = tmp_path / "dossier"

    given.run("classify-dossier", sources_directory, work, "--out", str(dossier))

    assert sorted(path.name for path in dossier.iterdir()) == [
        f"{ITS_CVE}.json",
        f"{AN_OSV_ONLY}.json",
        "classification_schema.json",
        "grammar_classes.md",
    ]


def test_the_help_lists_the_four_subcommands(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit):
        run_census.main(["--help"])

    usage = capsys.readouterr().out
    assert all(
        command in usage for command in ("prefilter", "status", "classify-dossier", "assemble")
    )


def _a_complete_census_collection(tmp_path: Path) -> tuple[Path, Path]:
    """A GHSA hit with its NVD record, disclosed on 2025-06-10, and an OSV-only hit. Both
    classifiers read the CVE's date as its NVD date, 2025-07-02."""
    sources_directory = given.a_sources_directory(
        tmp_path,
        ghsa=[given.an_mcp_advisory(A_GHSA, ITS_CVE)],
        nvd=[sources.an_nvd_cve(ITS_CVE)],
        osv=[given.an_mcp_advisory(AN_OSV_ONLY)],
    )
    work = given.a_work_directory(
        tmp_path,
        decisions=[given.kept(GHSA, A_GHSA), given.kept(OSV, AN_OSV_ONLY)],
        classifiers=given.both_classifiers_classifying(
            (ITS_CVE, date(2025, 7, 2)), (AN_OSV_ONLY, date(2025, 6, 10))
        ),
    )
    return sources_directory, work
