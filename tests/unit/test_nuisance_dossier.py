"""The nuisance admission dossier mirrors the holdout calibration kit: a self-contained tree,
free of any mcp_auditor import, but with the fix-check driver instead of the holdout list and
layout. These pins are the twin of test_calibration_dossier_writes_an_isolated_kit."""

from pathlib import Path

import pytest

import tests.unit.support.holdout_kit_isolation as iso
import tests.unit.support.test_holdout_census_given as given
from evals.calibration_dossier import CLEAN_MODULES, acceptance_services
from evals.eval_session import Refused
from evals.nuisance_dossier import write_dossier

_SERVER = "npm:@acme/files"


def test_writes_the_isolated_admission_dossier(tmp_path: Path):
    out = tmp_path / "dossier"
    write_dossier(given.a_census(), _SERVER, out)

    for relative in (
        f"advisories/{given.FLAW_WITH_A_CVE}.json",
        "evals/__init__.py",
        *(f"evals/{module}.py" for module in CLEAN_MODULES),
        "evals/holdout_kit/fix_check.py",
        "evals/holdout_kit/kit_driver.py",
        "docker/Dockerfile.sentinel",
        "README.md",
        "fixture_format.md",
        "grammar_classes.md",
    ):
        assert (out / relative).exists(), relative
    assert not (out / "evals" / "holdout_places.json").exists()
    assert not (out / "layout.md").exists()


def test_the_written_dossier_imports_nothing_from_mcp_auditor(tmp_path: Path):
    out = tmp_path / "dossier"
    write_dossier(given.a_census(), _SERVER, out)

    assert iso.scan_tree(out) == {}
    assert iso.import_closure_offenders(iso.kit_modules(out), root=out) == []


def test_the_readme_names_the_kit_tag_and_the_acceptance_services(tmp_path: Path):
    out = tmp_path / "dossier"
    write_dossier(given.a_census(), _SERVER, out)

    readme = (out / "README.md").read_text()
    assert "mcp-auditor-kit-<service>:local" in readme
    for service in acceptance_services():
        assert f"`{service}`" in readme, service


def test_an_unknown_server_is_refused(tmp_path: Path):
    out = tmp_path / "dossier"
    with pytest.raises(Refused):
        write_dossier(given.a_census(), "npm:nonexistent", out)
    assert not out.exists()
