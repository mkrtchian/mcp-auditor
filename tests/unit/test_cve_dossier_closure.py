from pathlib import Path

import pytest

from evals.cve.dossier_closure import copy_closure, import_closure


def test_the_closure_follows_imports_transitively_and_skips_imported_attributes(tmp_path: Path):
    _a_planted_package(tmp_path)

    assert import_closure(["pkg.entry"], root=tmp_path) == ["pkg", "pkg.a", "pkg.b", "pkg.entry"]


def test_a_module_importing_mcp_auditor_is_refused_with_its_import_chain(tmp_path: Path):
    _write(tmp_path / "pkg" / "__init__.py", "")
    _write(tmp_path / "pkg" / "entry.py", "import pkg.coupled\n")
    _write(tmp_path / "pkg" / "coupled.py", "from mcp_auditor.domain import models\n")

    with pytest.raises(ValueError, match=r"pkg\.entry -> pkg\.coupled -> mcp_auditor\.domain\b"):
        import_closure(["pkg.entry"], root=tmp_path)


def test_a_from_package_import_reads_as_the_submodule(tmp_path: Path):
    _write(tmp_path / "pkg" / "__init__.py", "")
    _write(tmp_path / "pkg" / "entry.py", "from pkg import helper\n")
    _write(tmp_path / "pkg" / "helper.py", "import json\n")

    assert import_closure(["pkg.entry"], root=tmp_path) == ["pkg", "pkg.entry", "pkg.helper"]


def test_the_closure_is_copied_at_its_relative_paths(tmp_path: Path):
    root = tmp_path / "repo"
    _a_planted_package(root)
    out = tmp_path / "out"

    copy_closure(out, ["pkg.entry"], root=root)

    assert (out / "pkg" / "__init__.py").read_text() == ""
    assert (out / "pkg" / "b.py").read_text() == "some_name = 1\n"


def test_the_closure_of_a_kit_root_holds_its_packages_and_the_shared_modules(tmp_path: Path):
    copy_closure(tmp_path, ["evals.cve.kit.driver"])

    for relative in ("evals/cve/__init__.py", "evals/cve/kit/__init__.py", "evals/cve_places.py"):
        assert (tmp_path / relative).is_file(), relative


def _a_planted_package(root: Path) -> None:
    _write(root / "pkg" / "__init__.py", "")
    _write(root / "pkg" / "entry.py", "import pkg.a\nfrom pkg.a import some_name\n")
    _write(root / "pkg" / "a.py", "import pkg.b\nsome_name = pkg.b.some_name\n")
    _write(root / "pkg" / "b.py", "some_name = 1\n")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
