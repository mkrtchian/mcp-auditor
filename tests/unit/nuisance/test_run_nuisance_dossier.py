"""The nuisance-dossier subcommand of the nuisance suite, first admission and re-admission."""

from pathlib import Path

import pytest

import tests.unit.census.support.test_census_given as given
import tests.unit.nuisance.admission.support.test_nuisance_admission_given as admission
import tests.unit.nuisance.admission.support.test_nuisance_walk_given as walk_given
from evals import run_nuisance
from tests.unit.nuisance.admission.support import (
    test_nuisance_re_admission_dossier_given as re_admission,
)


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
