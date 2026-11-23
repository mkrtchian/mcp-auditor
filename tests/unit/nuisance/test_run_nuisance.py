from pathlib import Path

import pytest

import tests.unit.nuisance.support.nuisance_queue_walks as queue_walks
import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_admissions as admissions
import tests.unit.support.nuisance_walks as walks
from evals import run_nuisance
from evals.cve.nuisance.admission.admission import NuisanceAdmission
from tests.unit.support import census_draws, censuses


def test_walk_prints_the_population_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = census_draws.a_census_with_draw(census_draws.a_draw())
    path = censuses.written(tmp_path, census)
    missing = tmp_path / "absent.json"

    exit_code = run_nuisance.main(
        [
            "walk",
            *walks.committed_census_arguments(tmp_path, path),
            "--admission",
            str(missing),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "servers reached by the walk" in out
    assert "npm:@acme/files" in out
    assert "reached by CVE-2025-0001 (drawn)" in out


def test_walk_marks_a_queue_server_and_counts_the_admitted_ones(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(["walk", *arguments])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert f"{queue_walks.QUEUE_SERVER}  reached by {queue_walks.QUEUE_FLAW} (addition)" in out
    assert "1 of 1 servers of the addition admitted and in the nuisance holdout layer" in out


def test_walk_without_an_admission_prints_no_count_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    arguments = queue_walks.a_walk_with_a_queue_server(tmp_path, admitted=False)

    exit_code = run_nuisance.main(["walk", *arguments])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "(addition)" in out
    assert "servers of the addition" not in out


def test_a_malformed_census_exits_three(tmp_path: Path):
    path = tmp_path / "census.json"
    path.write_text("{ not valid json")

    missing = tmp_path / "absent.json"

    exit_code = run_nuisance.main(
        [
            "walk",
            *walks.committed_census_arguments(tmp_path, path),
            "--admission",
            str(missing),
        ]
    )

    assert exit_code == 3


def test_a_missing_walk_record_is_refused_as_not_committed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = censuses.written(tmp_path, census_draws.a_census_with_draw(census_draws.a_draw()))
    missing = tmp_path / "absent.json"

    exit_code = run_nuisance.main(
        [
            "walk",
            "--census",
            str(census),
            "--walk-record",
            str(missing),
            "--admission",
            str(missing),
        ]
    )

    assert exit_code == run_nuisance.REFUSED_EXIT
    assert "the nuisance walk record is not committed" in capsys.readouterr().out


@pytest.mark.parametrize(
    "admitted",
    [None, mutations.admitting()],
    ids=["absent", "no servers"],
)
def test_run_with_no_admitted_server_exits_zero_and_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], admitted: NuisanceAdmission | None
):
    census = censuses.written(tmp_path, admissions.a_census())
    path = tmp_path / "absent.json" if admitted is None else admissions.written(tmp_path, admitted)

    exit_code = run_nuisance.main(
        ["run", *walks.committed_census_arguments(tmp_path, census), "--admission", str(path)]
    )

    assert exit_code == 0
    assert "no server is admitted" in capsys.readouterr().out


def test_run_refuses_tracing_before_reading_the_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    census = censuses.written(tmp_path, admissions.a_census())
    malformed = tmp_path / "nuisance_admission.json"
    malformed.write_text("{ not json")

    exit_code = run_nuisance.main(
        [
            "run",
            *walks.committed_census_arguments(tmp_path, census),
            "--admission",
            str(malformed),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == run_nuisance.REFUSED_EXIT
    assert "nuisance holdout run refused" in out
    assert "malformed" not in out


def test_run_on_a_stale_admission_exits_three_naming_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = censuses.written(tmp_path, admissions.a_census())
    stale = mutations.with_a_stale_grammar_fingerprint(admissions.an_admission())
    path = admissions.written(tmp_path, stale)

    exit_code = run_nuisance.main(
        ["run", *walks.committed_census_arguments(tmp_path, census), "--admission", str(path)]
    )

    out = capsys.readouterr().out
    assert exit_code == run_nuisance.REFUSED_EXIT
    assert "the census, the walk record or the admission is malformed" in out
    assert f"grammar fingerprint {stale.grammar_fingerprint} is not the current" in out
