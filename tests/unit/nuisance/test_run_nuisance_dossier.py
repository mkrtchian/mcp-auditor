"""The nuisance-dossier subcommand of the nuisance suite, first admission and re-admission."""

from pathlib import Path

import pytest

import tests.unit.support.nuisance_admissions as admissions
import tests.unit.support.nuisance_walks as walks
from evals import run_nuisance
from tests.unit.support import censuses
from tests.unit.support.committed_nuisance_admission import a_committed_server_with_fix_checks


def test_nuisance_dossier_writes_and_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    census = censuses.written(tmp_path, admissions.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            *walks.committed_census_arguments(tmp_path, census),
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
    census = censuses.written(tmp_path, admissions.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            *walks.committed_census_arguments(tmp_path, census),
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
    census = censuses.written(tmp_path, admissions.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            *walks.committed_census_arguments(tmp_path, census),
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
    census = censuses.written(tmp_path, admissions.a_census())
    out = tmp_path / "dossier"

    exit_code = run_nuisance.main(
        [
            "nuisance-dossier",
            *walks.committed_census_arguments(tmp_path, census),
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
    server = a_committed_server_with_fix_checks().server_package

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
    server = a_committed_server_with_fix_checks().server_package

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
    server = a_committed_server_with_fix_checks().server_package

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
