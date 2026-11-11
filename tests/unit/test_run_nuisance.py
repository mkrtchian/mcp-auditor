from pathlib import Path

import pytest

import tests.unit.support.test_census_given as given
import tests.unit.support.test_detection_draw_record_given as draw_given
import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_re_admission_dossier_given as re_admission
import tests.unit.support.test_nuisance_walk_given as walk_given
import tests.unit.support.test_run_nuisance_given as run_given
from evals import run_nuisance


def test_walk_prints_the_population_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = draw_given.a_census_with_draw(draw_given.a_draw())
    path = given.written(tmp_path, census)
    missing = tmp_path / "absent.json"

    exit_code = run_nuisance.main(
        [
            "walk",
            *walk_given.committed_census_arguments(tmp_path, path),
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
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=True)

    exit_code = run_nuisance.main(["walk", *arguments])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert f"{run_given.QUEUE_SERVER}  reached by {run_given.QUEUE_FLAW} (addition)" in out
    assert "1 of 1 servers of the addition admitted and in the nuisance holdout layer" in out


def test_walk_without_an_admission_prints_no_count_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    arguments = run_given.a_walk_with_a_queue_server(tmp_path, admitted=False)

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
            *walk_given.committed_census_arguments(tmp_path, path),
            "--admission",
            str(missing),
        ]
    )

    assert exit_code == 3


def test_a_missing_walk_record_is_refused_as_not_committed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, draw_given.a_census_with_draw(draw_given.a_draw()))
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


def test_nuisance_dossier_writes_and_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    census = given.written(tmp_path, admission.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            *walk_given.committed_census_arguments(tmp_path, census),
            "--server",
            "npm:@acme/files",
            "--out",
            str(out),
        ]
    )

    assert exit_code == 0
    assert out.exists()
    assert "Admission dossier for npm:@acme/files written to" in capsys.readouterr().out


def test_nuisance_dossier_with_a_backend_writes_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, admission.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            *walk_given.committed_census_arguments(tmp_path, census),
            "--server",
            "npm:@acme/files",
            "--out",
            str(out),
            "--backend",
            "doris",
        ]
    )

    assert exit_code == 0
    assert (out / "evals" / "cve" / "kit" / "backends.py").exists()


def test_nuisance_dossier_with_an_unknown_backend_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, admission.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            *walk_given.committed_census_arguments(tmp_path, census),
            "--server",
            "npm:@acme/files",
            "--out",
            str(out),
            "--backend",
            "ghost",
        ]
    )

    assert exit_code == 3
    assert not out.exists()
    assert "no backend named 'ghost'" in capsys.readouterr().out


def test_nuisance_dossier_on_an_unknown_server_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, admission.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            *walk_given.committed_census_arguments(tmp_path, census),
            "--server",
            "npm:ghost",
            "--out",
            str(out),
        ]
    )

    assert exit_code == 3
    assert not out.exists()
    assert "no census flaw names the server npm:ghost" in capsys.readouterr().out


def test_a_re_admission_dossier_with_a_backend_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    out = tmp_path / "dossier"
    server = re_admission.a_committed_server_with_fix_checks().server_package

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            "--server",
            server,
            "--re-admission",
            "--backend",
            "doris",
            "--out",
            str(out),
        ]
    )

    assert exit_code == 3
    assert not out.exists()
    assert "--backend is for a first admission" in capsys.readouterr().out


def test_a_re_admission_dossier_of_an_admitted_server_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    out = tmp_path / "dossier"
    server = re_admission.a_committed_server_with_fix_checks().server_package

    exit_code = run_nuisance.main(
        ["nuisance-dossier", "--server", server, "--re-admission", "--out", str(out)]
    )

    assert exit_code == 0
    assert (out / "admission_record.json").exists()
    assert f"Re-admission dossier for {server} written to {out}" in capsys.readouterr().out


def test_a_re_admission_dossier_without_an_admission_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    out = tmp_path / "dossier"
    missing = tmp_path / "absent.json"
    server = re_admission.a_committed_server_with_fix_checks().server_package

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            "--server",
            server,
            "--re-admission",
            "--admission",
            str(missing),
            "--out",
            str(out),
        ]
    )

    assert exit_code == 3
    assert not out.exists()


@pytest.mark.parametrize(
    "old_command",
    [
        ["calibrate"],
        ["fix-check", "--cve", "CVE-2099-9999"],
        ["nuisance-dossier", "--server", "npm:x", "--out", "out", "--readmission"],
    ],
    ids=["calibrate", "--cve", "--readmission"],
)
def test_an_old_command_or_flag_is_refused_by_the_parser(old_command: list[str]):
    with pytest.raises(SystemExit) as refused:
        run_nuisance.main(old_command)

    assert refused.value.code == 2


def test_run_without_an_admission_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, admission.a_census())
    missing = tmp_path / "absent.json"

    exit_code = run_nuisance.main(
        [
            "run",
            *walk_given.committed_census_arguments(tmp_path, census),
            "--admission",
            str(missing),
        ]
    )

    assert exit_code == 0
    assert "no server is admitted" in capsys.readouterr().out


def test_run_on_an_admission_with_no_server_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, admission.a_census())
    empty = admission.an_admission().model_copy(update={"servers": []})
    path = admission.written(tmp_path, empty)

    exit_code = run_nuisance.main(
        ["run", *walk_given.committed_census_arguments(tmp_path, census), "--admission", str(path)]
    )

    assert exit_code == 0
    assert "no server is admitted" in capsys.readouterr().out


def test_run_refuses_tracing_before_reading_the_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    census = given.written(tmp_path, admission.a_census())
    malformed = tmp_path / "nuisance_admission.json"
    malformed.write_text("{ not json")

    exit_code = run_nuisance.main(
        [
            "run",
            *walk_given.committed_census_arguments(tmp_path, census),
            "--admission",
            str(malformed),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == run_nuisance.REFUSED_EXIT
    assert "nuisance run refused" in out
    assert "malformed" not in out


def test_run_on_a_stale_admission_exits_three_naming_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    census = given.written(tmp_path, admission.a_census())
    stale = admission.with_a_stale_grammar_fingerprint(admission.an_admission())
    path = admission.written(tmp_path, stale)

    exit_code = run_nuisance.main(
        ["run", *walk_given.committed_census_arguments(tmp_path, census), "--admission", str(path)]
    )

    out = capsys.readouterr().out
    assert exit_code == run_nuisance.REFUSED_EXIT
    assert "the census, the walk record or the admission is malformed" in out
    assert f"grammar fingerprint {stale.grammar_fingerprint} is not the current" in out
