"""The nuisance admission dossier mirrors the holdout calibration kit: a self-contained tree,
free of any mcp_auditor import, but with the fix-check driver instead of the holdout list and
layout. These pins are the twin of test_calibration_dossier_writes_an_isolated_kit."""

import re
import tomllib
from dataclasses import fields
from pathlib import Path

import pytest

import tests.unit.support.holdout_kit_isolation as iso
import tests.unit.support.test_holdout_census_given as census_given
import tests.unit.support.test_nuisance_dossier_given as given
import tests.unit.support.test_nuisance_dossier_then as then
import tests.unit.support.test_nuisance_unrecorded_given as unrecorded_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals.calibration_dossier import CLEAN_MODULES, acceptance_services, write_kit
from evals.eval_session import Refused
from evals.holdout_kit.fix_check import FixCheckTarget
from evals.nuisance_dossier import write_dossier


def test_writes_the_isolated_admission_dossier(tmp_path: Path):
    out = given.a_written_dossier(tmp_path)

    for relative in (
        f"advisories/{census_given.FLAW_WITH_A_CVE}.json",
        "evals/__init__.py",
        *(f"evals/{module}.py" for module in CLEAN_MODULES),
        "evals/holdout_kit/fix_check.py",
        "evals/holdout_kit/kit_driver.py",
        "docker/Dockerfile.sentinel",
        "docker/Dockerfile.stand-in",
        "evals/stand_ins/example.com.json",
        "evals/stand_ins/tls/fixture-authority.pem",
        "README.md",
        "fixture_format.md",
        "grammar_classes.md",
    ):
        assert (out / relative).exists(), relative
    assert not (out / "evals" / "holdout_places.json").exists()
    assert not (out / "layout.md").exists()
    assert not (out / "evals" / "holdout_kit" / "kit_backends.py").exists()
    assert not (out / "evals" / "doris_backend.py").exists()
    assert "doris" not in (out / "fixture_format.md").read_text()


def test_a_backend_dossier_imports_closed(tmp_path: Path):
    out = given.a_written_dossier(tmp_path, backend="doris")

    assert (out / "evals" / "holdout_kit" / "kit_backends.py").exists()
    assert (out / "evals" / "doris_backend.py").exists()
    assert (out / "evals" / "nuisance_confinement.py").exists()
    fixture_format = (out / "fixture_format.md").read_text()
    assert "kit_backends.doris_backend_env" in fixture_format
    assert "169.254.0.0/16" in fixture_format
    assert "DORIS_SERVER_LAUNCH" in fixture_format
    assert iso.import_closure_offenders(iso.kit_modules(out), root=out) == []


def test_an_unknown_backend_is_refused(tmp_path: Path):
    out = tmp_path / "dossier"
    with pytest.raises(Refused):
        write_dossier(
            walk_given.a_nuisance_census(census_given.a_census()),
            given.SERVER,
            out,
            backend="ghost",
        )
    assert not out.exists()


def test_the_shared_kit_carries_no_worked_exploit(tmp_path: Path):
    # A worked exploit named by its CVE in the shared launch module would reach the admitting
    # agent through the copied kit and pre-answer the flaw it is meant to re-derive. Such a
    # builder belongs with its fixture (evals/nuisance_fix_checks), which the dossier never copies.
    out = given.a_written_dossier(tmp_path)

    kit = (out / "evals" / "holdout_kit" / "kit_launch.py").read_text()
    assert "CVE-" not in kit
    names = (
        "redirect_ssrf_env",
        "ipv6_loopback_env",
        "contextforge_env",
        "_gw_tools",
        "_GW_PUBLIC_IP",
    )
    for name in names:
        assert name not in kit, name


def test_the_written_dossier_imports_nothing_from_mcp_auditor(tmp_path: Path):
    out = given.a_written_dossier(tmp_path)

    assert iso.scan_tree(out) == {}
    assert iso.import_closure_offenders(iso.kit_modules(out), root=out) == []


def test_the_readme_names_the_kit_tag_and_the_acceptance_services(tmp_path: Path):
    out = given.a_written_dossier(tmp_path)

    readme = (out / "README.md").read_text()
    assert "mcp-auditor-kit-<service>:local" in readme
    for service in acceptance_services():
        assert f"`{service}`" in readme, service


def test_both_readmes_state_the_mcp_specifier_of_the_project(tmp_path: Path):
    dossier = given.a_written_dossier(tmp_path)
    write_kit(census_given.a_census(), census_given.FLAW_WITH_A_CVE, tmp_path / "kit")

    specifier = _mcp_specifier()
    assert f"`{specifier}`" in (dossier / "README.md").read_text()
    assert f"`{specifier}`" in (tmp_path / "kit" / "README.md").read_text()


def _mcp_specifier() -> str:
    pyproject = tomllib.loads((iso.REPO_ROOT / "pyproject.toml").read_text())
    dependencies: list[str] = pyproject["project"]["dependencies"]
    return next(each for each in dependencies if re.split(r"[<>=!~\[; ]", each)[0] == "mcp")


def test_both_readmes_build_the_stand_in_image_beside_the_sentinel(tmp_path: Path):
    dossier = given.a_written_dossier(tmp_path)
    write_kit(census_given.a_census(), census_given.FLAW_WITH_A_CVE, tmp_path / "kit")

    build = "docker build -t mcp-auditor-cve-stand-in:local -f docker/Dockerfile.stand-in docker"
    assert build in (dossier / "README.md").read_text()
    kit_readme = (tmp_path / "kit" / "README.md").read_text()
    assert build in kit_readme
    assert "`evals/stand_ins/`" in kit_readme


def test_an_unknown_server_is_refused(tmp_path: Path):
    out = tmp_path / "dossier"
    with pytest.raises(Refused):
        write_dossier(walk_given.a_nuisance_census(census_given.a_census()), "npm:nonexistent", out)
    assert not out.exists()


def test_the_fixture_format_names_every_field_the_run_refuses_unrecorded(tmp_path: Path):
    server = unrecorded_given.a_server_with_every_field_unrecorded()

    fixture_format = (given.a_written_dossier(tmp_path) / "fixture_format.md").read_text()

    for name in [*then.unrecorded_field_names(server), "holdout_fingerprint"]:
        assert re.search(rf"`\w+\.{name}`", fixture_format), name


def test_the_fixture_format_names_every_fix_check_target_field(tmp_path: Path):
    fixture_format = (given.a_written_dossier(tmp_path) / "fixture_format.md").read_text()

    section = fixture_format.split("## FixCheckTarget fields")[1].split("\n## ")[0]
    for field in fields(FixCheckTarget):
        assert f"`{field.name}`" in section, field.name
