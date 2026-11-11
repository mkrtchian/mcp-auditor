"""The nuisance admission dossier mirrors the calibration kit of a holdout target: a self-contained
tree, free of any mcp_auditor import, but with the fix-check driver instead of the holdout list and
layout. These pins are the counterpart of test_calibration_dossier_writes_an_isolated_kit."""

import re
import tomllib
from dataclasses import fields
from pathlib import Path

import pytest

import tests.unit.support.kit_isolation as iso
import tests.unit.support.test_census_given as census_given
import tests.unit.support.test_nuisance_dossier_given as given
import tests.unit.support.test_nuisance_dossier_then as then
import tests.unit.support.test_nuisance_unrecorded_given as unrecorded_given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals.cve.detection.calibration_dossier import acceptance_services, write_kit
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.nuisance.dossier import NUISANCE_RULE, write_dossier
from evals.cve.nuisance.re_admission_docs import admission_confinement_text
from evals.eval_session import Refused


def test_writes_the_isolated_admission_dossier(tmp_path: Path):
    out = given.a_written_dossier(tmp_path)

    for relative in (
        f"advisories/{census_given.FLAW_WITH_A_CVE}.json",
        "evals/__init__.py",
        "evals/cve/__init__.py",
        "evals/cve/kit/__init__.py",
        "evals/cve_grammar.py",
        "evals/cve_places.py",
        "evals/cve_planting.py",
        "evals/cve/kit/fix_check.py",
        "evals/cve/kit/driver.py",
        "docker/Dockerfile.sentinel",
        "docker/Dockerfile.stand-in",
        "evals/stand_ins/example.com.json",
        "evals/stand_ins/tls/fixture-authority.pem",
        "README.md",
        "fixture_format.md",
        "grammar_classes.md",
        "nuisance-rule.md",
        "confinement.md",
        "evals/cve/kit/benign_probe.py",
        "evals/capture_stand_in.py",
    ):
        assert (out / relative).exists(), relative
    assert (out / "nuisance-rule.md").read_text() == NUISANCE_RULE.read_text()
    assert (out / "confinement.md").read_text() == admission_confinement_text()
    assert not (out / "reference").exists()
    assert not (out / "evals" / "holdout_places.json").exists()
    assert not (out / "layout.md").exists()
    assert not (out / "evals" / "cve" / "kit" / "backends.py").exists()
    assert not (out / "evals" / "doris_backend.py").exists()
    assert "doris" not in (out / "fixture_format.md").read_text()


def test_the_grammar_classes_send_a_flaw_outside_them_to_null(tmp_path: Path):
    out = given.a_written_dossier(tmp_path)

    then.grammar_classes_send_an_unclassed_flaw_to_null(out)


def test_a_backend_dossier_imports_closed(tmp_path: Path):
    out = given.a_written_dossier(tmp_path, backend="doris")

    assert (out / "evals" / "cve" / "kit" / "backends.py").exists()
    assert (out / "evals" / "doris_backend.py").exists()
    assert (out / "evals" / "nuisance_confinement.py").exists()
    fixture_format = (out / "fixture_format.md").read_text()
    assert "backends.doris_backend_env" in fixture_format
    assert "169.254.0.0/16" in fixture_format
    assert "DORIS_SERVER_LAUNCH" in fixture_format
    assert iso.import_closure_offenders(iso.kit_modules(out), root=out) == []


def test_an_unknown_backend_is_refused(tmp_path: Path):
    out = tmp_path / "dossier"
    with pytest.raises(Refused):
        write_dossier(
            walk_given.walk_inputs_of(census_given.a_census()),
            given.SERVER,
            out,
            backend="ghost",
        )
    assert not out.exists()


def test_the_shared_kit_carries_no_worked_exploit(tmp_path: Path):
    # A worked exploit named by its CVE in the shared launch module would reach the admitting agent
    # through the copied kit and pre-answer the flaw it is meant to re-derive. Such a builder
    # belongs with its fixture (evals/cve/nuisance/fix_checks), which the dossier never copies.
    out = given.a_written_dossier(tmp_path)

    kit = (out / "evals" / "cve" / "kit" / "launch.py").read_text()
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


def test_a_detection_holdout_server_dossier_carries_the_holdout_reference_of_each_target(
    tmp_path: Path,
):
    server = given.a_detection_holdout_server_with_its_own_fix_check()

    out = given.a_written_dossier_of(tmp_path, server)

    for target in given.its_holdout_targets(server):
        then.it_carries_the_holdout_reference_of(out, target)
    assert iso.scan_tree(out) == {}
    assert iso.import_closure_offenders(iso.kit_modules(out), root=out) == []


def test_the_readme_lists_the_rule_confinement_probe_capture_tool_and_reference(
    tmp_path: Path,
):
    readme = (given.a_written_dossier(tmp_path) / "README.md").read_text()

    for named in (
        "`nuisance-rule.md`",
        "`confinement.md`",
        "evals.cve.kit.benign_probe",
        "evals.capture_stand_in",
        "`reference/cards/<id>.json`",
        "`reference/holdout_fixtures/`",
        "`reference/docker/`",
    ):
        assert named in readme, named


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
        write_dossier(walk_given.walk_inputs_of(census_given.a_census()), "npm:nonexistent", out)
    assert not out.exists()


def test_the_fixture_format_names_every_field_the_run_refuses_unrecorded(tmp_path: Path):
    server = unrecorded_given.a_server_with_every_field_unrecorded()

    fixture_format = (given.a_written_dossier(tmp_path) / "fixture_format.md").read_text()

    for name in [*then.unrecorded_field_names(server), "holdout_fingerprint"]:
        assert re.search(rf"`\w+\.{name}`", fixture_format), name


def test_the_fixture_format_names_every_fix_check_target_field(tmp_path: Path):
    fixture_format = (given.a_written_dossier(tmp_path) / "fixture_format.md").read_text()

    section = fixture_format.split("## FixCheckFixture fields")[1].split("\n## ")[0]
    for field in fields(FixCheckFixture):
        assert f"`{field.name}`" in section, field.name
