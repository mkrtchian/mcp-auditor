"""The re-admission dossier carries what the two blind agents need to fill rule v3's fields for
one admitted server: its record, the rule, the run's Dockerfiles and confinement, its fix-check
modules and backend lifecycle, and the benign probe, all free of any mcp_auditor import."""

from pathlib import Path

import pytest

import tests.unit.support.holdout_kit_isolation as iso
import tests.unit.support.test_nuisance_readmission_dossier_given as given
from evals.dossier_closure import import_closure
from evals.eval_session import Refused
from evals.nuisance_admission import AdmittedServer
from evals.nuisance_confinement import nuisance_confinement_args, user_args
from evals.nuisance_fixtures import FIX_CHECK_TARGETS
from evals.nuisance_readmission_dossier import (
    closure_roots,
    holdout_fixture_file,
    holdout_references,
    write_readmission_dossier,
)


@pytest.mark.parametrize("server_package", [given.PRAISONAI, given.APIFY, given.NEO4J, given.MYSQL])
def test_the_dossier_imports_nothing_from_the_auditor(tmp_path: Path, server_package: str):
    out = given.a_written_dossier(tmp_path, server_package)

    assert iso.scan_tree(out) == {}
    assert iso.import_closure_offenders(iso.kit_modules(out), root=out) == []
    assert given.copies_of_auditor_sources(out) == []


def test_every_admitted_server_has_a_clean_closure():
    for server in given.the_committed_admission().servers:
        import_closure(closure_roots(server))


def test_the_praisonai_dossier_carries_its_record_rule_dockerfiles_and_fix_checks(
    tmp_path: Path,
):
    out = given.a_written_dossier(tmp_path, given.PRAISONAI)
    server = given.the_committed_server(given.PRAISONAI)

    record = AdmittedServer.model_validate_json((out / "admission_record.json").read_text())
    assert record == server
    rule = (given.REPO_ROOT / "docs" / "nuisance-rule.md").read_text()
    assert (out / "nuisance-rule.md").read_text() == rule
    for service in _fix_check_services(server):
        assert (out / "evals" / "docker" / f"Dockerfile.{service}").exists(), service
    for relative in (
        "evals/docker/Dockerfile.praisonai",
        "evals/docker/Dockerfile.sentinel",
        "evals/docker/Dockerfile.stand-in",
        "evals/nuisance_fix_checks/cve_2026_44336_praisonai.py",
        "evals/nuisance_fix_checks/cve_2026_47394_praisonai.py",
        "evals/holdout_kit/benign_probe.py",
        "evals/holdout_kit/kit_backend_launch.py",
        "confinement.md",
    ):
        assert (out / relative).exists(), relative


def test_the_apify_dossier_carries_its_backend_alone(tmp_path: Path):
    out = given.a_written_dossier(tmp_path, given.APIFY)

    for relative in (
        "evals/docker/Dockerfile.apify-responder",
        "evals/docker/Dockerfile.stand-in",
        "evals/stand_ins/api.apify.com.json",
        "evals/stand_ins/tls/api.apify.com-key.pem",
        "evals/apify_backend.py",
    ):
        assert (out / relative).exists(), relative
    assert not (out / "evals" / "ckan_backend.py").exists()


def test_the_mysql_dossier_carries_its_holdout_reference_as_text(tmp_path: Path):
    out = given.a_written_dossier(tmp_path, given.MYSQL)

    reference = out / "reference" / "holdout_fixtures" / "cve_2026_85788_mysql.py.txt"
    text = reference.read_text()
    fixture = (given.REPO_ROOT / "evals/holdout_fixtures/cve_2026_85788_mysql.py").read_text()
    assert text.startswith(fixture)
    assert "def mysql_db_env(" in text
    for service in ("holdout-2026-85788-mysql", "holdout-2026-85788-mysql-patched"):
        assert (out / "evals" / "docker" / f"Dockerfile.{service}").exists(), service
    assert list((out / "reference").rglob("*.py")) == []


@pytest.mark.parametrize("server_package", [given.PRAISONAI, given.MYSQL])
def test_the_confinement_names_every_option_the_run_sets(tmp_path: Path, server_package: str):
    out = given.a_written_dossier(tmp_path, server_package)
    server = given.the_committed_server(server_package)

    confinement = (out / "confinement.md").read_text()
    for option in (*nuisance_confinement_args(), *user_args(server.host.user)):
        assert option in confinement, option
    if server.backend is not None:
        assert server.backend.network in confinement


def test_the_readme_says_how_to_build_probe_and_leave_the_shared_backends(tmp_path: Path):
    out = given.a_written_dossier(tmp_path, given.MYSQL)

    readme = (out / "README.md").read_text()
    assert "## Re-admission" in readme
    assert "mcp>=1.18.0,<2" in readme
    assert 'kit_launch.build_images(Path("docker"), ["<prefix>-mysql"])' in readme
    assert "python -m evals.holdout_kit.benign_probe --record admission_record.json" in readme
    assert "asyncio.run(check_fix(" in readme
    assert "mcp-auditor-cve-*" in readme
    assert "never removed or stopped" in readme


def test_every_holdout_calibration_flaw_resolves_to_one_target_and_one_fixture():
    for server in given.the_committed_admission().servers:
        calibrated = {
            flaw.flaw for flaw in server.flaws if flaw.fix_check.source == "holdout_calibration"
        }
        targets = holdout_references(server)
        assert {target.cve_id for target in targets} == calibrated, server.server_package
        for target in targets:
            assert holdout_fixture_file(target.cve_id).is_file()


def test_a_holdout_calibration_flaw_no_target_carries_is_refused():
    server = given.the_committed_server(given.MYSQL)
    flaw = server.flaws[0].model_copy(update={"flaw": "CVE-2099-0001"})

    with pytest.raises(Refused):
        holdout_references(server.model_copy(update={"flaws": [flaw]}))


def test_a_server_the_admission_does_not_hold_is_refused_before_writing(tmp_path: Path):
    out = tmp_path / "dossier"

    with pytest.raises(Refused):
        write_readmission_dossier(
            given.the_committed_census(), given.the_committed_admission(), "npm:ghost", out
        )
    assert not out.exists()


def _fix_check_services(server: AdmittedServer) -> list[str]:
    flaws = {flaw.flaw for flaw in server.flaws}
    return [
        service
        for target in FIX_CHECK_TARGETS
        if target.flaw in flaws
        for service in (
            target.vulnerable_service,
            target.patched_service,
            target.server_patched_service,
        )
        if service is not None
    ]
