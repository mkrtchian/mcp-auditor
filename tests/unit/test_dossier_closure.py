from pathlib import Path

import pytest

from evals.dossier_closure import copy_closure, import_closure


def test_a_fix_check_closure_contains_the_sibling_it_imports():
    closure = import_closure(["evals.nuisance_fix_checks.ghsa_8g7g_hmwm_6rv2_n8n"])

    assert "evals.nuisance_fix_checks.cve_2026_44694_n8n" in closure
    assert "evals.nuisance_fix_checks" in closure
    assert "evals" in closure


def test_a_backend_closure_contains_every_module_its_lifecycle_needs():
    closure = import_closure(["evals.ckan_backend"])

    for module in (
        "evals.ckan_backend",
        "evals.responder_backend",
        "evals.closed_network",
        "evals.docker_paths",
        "evals.nuisance_confinement",
        "evals.backend_lifecycle",
    ):
        assert module in closure, module
    assert closure == sorted(closure)


def test_a_module_importing_mcp_auditor_is_refused_with_its_importer(tmp_path: Path):
    _write(tmp_path / "pkg" / "__init__.py", "")
    _write(tmp_path / "pkg" / "entry.py", "import pkg.coupled\n")
    _write(tmp_path / "pkg" / "coupled.py", "from mcp_auditor.domain import models\n")

    with pytest.raises(ValueError, match=r"pkg\.coupled.*mcp_auditor\.domain"):
        import_closure(["pkg.entry"], root=tmp_path)


def test_a_from_package_import_reads_as_the_submodule(tmp_path: Path):
    _write(tmp_path / "pkg" / "__init__.py", "")
    _write(tmp_path / "pkg" / "entry.py", "from pkg import helper\n")
    _write(tmp_path / "pkg" / "helper.py", "import json\n")

    assert import_closure(["pkg.entry"], root=tmp_path) == ["pkg", "pkg.entry", "pkg.helper"]


def test_the_closure_is_copied_at_its_relative_paths(tmp_path: Path):
    out = tmp_path / "out"

    copy_closure(out, ["evals.ckan_backend"])

    assert (out / "evals" / "__init__.py").exists()
    assert (out / "evals" / "responder_backend.py").exists()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
