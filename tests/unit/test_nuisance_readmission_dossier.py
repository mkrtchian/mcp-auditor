"""The re-admission dossier carries what the two blind agents need to fill rule v3's fields for
one admitted server: its record, the rule, the run's Dockerfiles and confinement, its fix-check
modules and backend lifecycle, and the benign probe, all free of any mcp_auditor import."""

import functools
from collections.abc import Callable
from fnmatch import fnmatch
from pathlib import Path

import pytest

import evals.nuisance_readmission_dossier as readmission
import tests.unit.support.holdout_kit_isolation as iso
import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_dossier_given as dossier_given
import tests.unit.support.test_nuisance_dossier_then as dossier_then
import tests.unit.support.test_nuisance_readmission_dossier_given as given
from evals.cve_planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE
from evals.docker_paths import image_dockerfile
from evals.dossier_closure import import_closure
from evals.eval_session import Refused
from evals.holdout_kit import benign_probe
from evals.holdout_kit.fix_check import check_fix
from evals.nuisance_admission import AdmittedServer, FlawRecord
from evals.nuisance_backends import BACKENDS
from evals.nuisance_confinement import nuisance_confinement_args, user_args
from evals.nuisance_dossier import NUISANCE_RULE
from evals.nuisance_holdout_reference import holdout_fixture_file
from evals.nuisance_readmission_docs import confinement_text, readmission_readme
from evals.nuisance_readmission_dossier import (
    closure_roots,
    fix_check_modules,
    holdout_references,
    readmission_dockerfiles,
    write_readmission_dossier,
)
from tests.unit.support.test_nuisance_committed_admission_given import (
    the_committed_admission,
    the_committed_census,
)

type DossierOf = Callable[[AdmittedServer], Path]

SHAPES = [
    given.a_committed_server_with_fix_checks,
    given.a_committed_server_with_a_backend,
    given.a_committed_server_with_a_holdout_copy,
    given.a_committed_twin_with_its_own_fix_check,
]


@pytest.fixture(scope="module")
def dossier_of(tmp_path_factory: pytest.TempPathFactory) -> DossierOf:
    """One written dossier per server, shared by the tests of the module: they only read it."""

    @functools.cache
    def written(server_package: str) -> Path:
        return given.a_written_dossier(tmp_path_factory.mktemp("readmission"), server_package)

    return lambda server: written(server.server_package)


@pytest.mark.parametrize("a_server", SHAPES, ids=lambda shape: shape.__name__)
def test_the_dossier_imports_nothing_from_the_auditor(
    dossier_of: DossierOf, a_server: Callable[[], AdmittedServer]
):
    out = dossier_of(a_server())

    assert iso.scan_tree(out) == {}
    assert iso.import_closure_offenders(iso.kit_modules(out), root=out) == []
    assert given.copies_of_auditor_sources(out) == []


def test_every_admitted_server_has_a_clean_closure():
    for server in the_committed_admission().servers:
        import_closure(closure_roots(server))


def test_a_fix_check_dossier_carries_its_record_rule_dockerfiles_and_fix_checks(
    dossier_of: DossierOf,
):
    server = given.a_committed_server_with_fix_checks()

    out = dossier_of(server)

    record = AdmittedServer.model_validate_json((out / "admission_record.json").read_text())
    assert record == server
    assert (out / "nuisance-rule.md").read_text() == NUISANCE_RULE.read_text()
    for service in (*readmission_dockerfiles(server), SENTINEL_SERVICE, STAND_IN_SERVICE):
        assert (out / "evals" / "docker" / image_dockerfile(service).name).exists(), service
    for module in (
        *fix_check_modules(server),
        "evals.holdout_kit.benign_probe",
        "evals.holdout_kit.kit_backend_launch",
    ):
        relative = f"{module.replace('.', '/')}.py"
        assert (out / relative).exists(), relative
    assert (out / "confinement.md").read_text() == confinement_text(server)
    readme = (out / "README.md").read_text()
    assert readme.endswith(readmission_readme(server, fix_check_modules(server)))


def test_a_backend_dossier_carries_its_backend_alone(dossier_of: DossierOf):
    server = given.a_committed_server_with_a_backend()
    assert server.backend is not None
    provisioner = server.backend.provisioner
    another = next(key for key in BACKENDS if key != provisioner)

    out = dossier_of(server)

    assert (out / "evals" / f"{provisioner}_backend.py").exists()
    for service in BACKENDS[provisioner].built_services:
        assert (out / "evals" / "docker" / image_dockerfile(service).name).exists(), service
    assert not (out / "evals" / f"{another}_backend.py").exists()


def test_a_holdout_copy_dossier_carries_its_holdout_reference_as_text(dossier_of: DossierOf):
    server = given.a_committed_server_with_a_holdout_copy()

    out = dossier_of(server)

    for target in holdout_references(server):
        fixture = holdout_fixture_file(target.cve_id)
        reference = out / "reference" / "holdout_fixtures" / f"{fixture.name}.txt"
        text = reference.read_text()
        assert text.startswith(fixture.read_text())
        assert f"def {target.builder.__name__}(" in text
        for service in (*target.images, target.patched_image):
            assert (out / "evals" / "docker" / image_dockerfile(service).name).exists(), service
    assert list((out / "reference").rglob("*.py")) == []


def test_a_twin_with_its_own_fix_check_carries_its_holdout_reference_and_card(
    dossier_of: DossierOf,
):
    server = given.a_committed_twin_with_its_own_fix_check()

    out = dossier_of(server)

    for target in dossier_given.its_holdout_targets(server):
        dossier_then.it_carries_the_holdout_reference_of(out, target)


@pytest.mark.parametrize(
    "server",
    [
        admission_given.an_admitted_server(),
        edits.with_the_registered_backend(admission_given.an_admitted_server(), "doris"),
    ],
    ids=["without a backend", "on the doris backend"],
)
def test_the_confinement_names_every_option_the_run_sets(server: AdmittedServer):
    confinement = confinement_text(server)

    for option in (*nuisance_confinement_args(), *user_args(server.host.user)):
        assert option in confinement, option
    if server.backend is not None:
        assert server.backend.network in confinement


def test_the_readme_builds_the_run_image_and_names_the_fix_check_modules():
    server = admission_given.an_admitted_server()
    modules = ["evals.nuisance_fix_checks.first", "evals.nuisance_fix_checks.second"]

    readme = readmission_readme(server, modules)

    assert f'["<prefix>-{server.service}"]' in readme
    for module in modules:
        assert f"`{module}`" in readme, module


def test_the_readme_names_the_backend_lifecycle_of_a_server_with_a_backend():
    server = edits.with_the_registered_backend(admission_given.an_admitted_server(), "doris")

    readme = readmission_readme(server, [])

    assert "`evals/doris_backend.py`" in readme


def test_the_readme_says_a_server_without_a_backend_has_none():
    readme = readmission_readme(admission_given.an_admitted_server(), [])

    assert "has no backend" in readme


def test_the_readme_commands_name_the_probe_and_fix_check_entry_points_the_kit_ships():
    readme = readmission_readme(admission_given.an_admitted_server(), [])

    assert f"python -m {benign_probe.__name__} --record" in readme
    assert f"from {check_fix.__module__} import {check_fix.__name__}" in readme


def test_the_readme_keeps_the_agent_off_every_shared_backend():
    readme = readmission_readme(admission_given.an_admitted_server(), [])

    assert "(`mcp-auditor-cve-*`)" in readme
    assert "never removed or stopped by the agent" in readme
    for key, backend in BACKENDS.items():
        assert fnmatch(backend.network, "mcp-auditor-cve-*"), key


def test_every_holdout_calibration_flaw_resolves_to_one_target_and_one_fixture():
    for server in the_committed_admission().servers:
        calibrated = {
            flaw.flaw for flaw in server.flaws if flaw.fix_check.source == "holdout_calibration"
        }
        targets = holdout_references(server)
        assert {target.cve_id for target in targets} == calibrated, server.server_package
        for target in targets:
            assert holdout_fixture_file(target.cve_id).is_file()


def test_a_holdout_calibration_flaw_no_target_carries_is_refused():
    def calibrated_on_an_unknown_target(flaw: FlawRecord) -> FlawRecord:
        fix_check = flaw.fix_check.model_copy(update={"source": "holdout_calibration"})
        return flaw.model_copy(update={"flaw": "CVE-2099-0001", "fix_check": fix_check})

    server = edits.with_the_first_flaw(
        admission_given.an_admitted_server(), calibrated_on_an_unknown_target
    )

    with pytest.raises(Refused):
        holdout_references(server)


def test_a_server_the_admission_does_not_hold_is_refused_before_writing(tmp_path: Path):
    out = tmp_path / "dossier"

    with pytest.raises(Refused):
        write_readmission_dossier(
            admission_given.a_nuisance_census(), admission_given.an_admission(), "npm:ghost", out
        )
    assert not out.exists()


def test_a_closure_reaching_the_auditor_is_refused_before_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    out = tmp_path / "dossier"
    server = the_committed_admission().servers[0]

    def roots_reaching_the_auditor(_: AdmittedServer) -> list[str]:
        return ["evals.cve_baseline"]

    monkeypatch.setattr(readmission, "closure_roots", roots_reaching_the_auditor)

    with pytest.raises(ValueError, match="mcp_auditor"):
        write_readmission_dossier(
            the_committed_census(), the_committed_admission(), server.server_package, out
        )
    assert not out.exists()
