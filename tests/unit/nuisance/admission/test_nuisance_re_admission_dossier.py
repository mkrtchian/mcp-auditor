"""The re-admission dossier carries what the two blind agents need to fill nuisance suite rule
v3's fields for one admitted server: its record, the rule, the run's Dockerfiles and confinement,
its fix-check modules and backend lifecycle, and the benign probe, all free of any mcp_auditor
import."""

import functools
from collections.abc import Callable
from fnmatch import fnmatch
from pathlib import Path

import pytest

import tests.unit.nuisance.admission.support.test_nuisance_re_admission_dossier_given as given
import tests.unit.support.admission_mutations as mutations
import tests.unit.support.kit_isolation as iso
import tests.unit.support.nuisance_admissions as admissions
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.docker_paths import image_dockerfile
from evals.cve.dossier_closure import import_closure
from evals.cve.kit import benign_probe
from evals.cve.kit.fix_check import check_fix
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.dossier import NUISANCE_SUITE_RULE
from evals.cve.nuisance.admission.re_admission_docs import confinement_text, re_admission_readme
from evals.cve.nuisance.admission.re_admission_dossier import (
    closure_roots,
    copied_holdout_targets,
    fix_check_modules,
    re_admission_dockerfiles,
    re_admission_plan,
)
from evals.cve.nuisance.backend_registry import BACKENDS
from evals.cve.nuisance.confinement import user_args
from evals.cve.planting_base import SENTINEL_SERVICE, STAND_IN_SERVICE, confinement_args
from evals.eval_session import Refused
from tests.unit.nuisance.admission.support.holdout_target_reference_checks import (
    it_carries_the_holdout_target_reference_of,
)
from tests.unit.support.committed_nuisance_admission import (
    a_committed_server_with_fix_checks,
    a_detection_holdout_server_with_its_own_fix_check,
    its_holdout_targets,
    the_committed_admission,
)

type DossierOf = Callable[[AdmittedServer], Path]

SHAPES = [
    a_committed_server_with_fix_checks,
    given.a_committed_server_with_a_backend,
    given.a_committed_server_with_a_holdout_calibration_copy,
    a_detection_holdout_server_with_its_own_fix_check,
]


@pytest.fixture(scope="module")
def dossier_of(tmp_path_factory: pytest.TempPathFactory) -> DossierOf:
    """One written dossier per server, shared by the tests of the module: they only read it."""

    @functools.cache
    def written(server_package: str) -> Path:
        return given.a_written_dossier(tmp_path_factory.mktemp("re_admission"), server_package)

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
    server = a_committed_server_with_fix_checks()

    out = dossier_of(server)

    record = AdmittedServer.model_validate_json((out / "admission_record.json").read_text())
    assert record == server
    assert (out / "nuisance-suite-rule.md").read_text() == NUISANCE_SUITE_RULE.read_text()
    services = re_admission_dockerfiles(server, given.the_copy_resolution())
    for service in (*services, SENTINEL_SERVICE, STAND_IN_SERVICE):
        assert (out / "evals" / "docker" / image_dockerfile(service).name).exists(), service
    for module in (
        *fix_check_modules(server),
        "evals.cve.kit.benign_probe",
        "evals.cve.kit.backend_launch",
    ):
        relative = f"{module.replace('.', '/')}.py"
        assert (out / relative).exists(), relative
    assert (out / "confinement.md").read_text() == confinement_text(server)
    readme = (out / "README.md").read_text()
    assert readme.endswith(re_admission_readme(server, fix_check_modules(server)))


def test_a_backend_dossier_carries_its_backend_alone(dossier_of: DossierOf):
    server = given.a_committed_server_with_a_backend()
    assert server.backend is not None
    provisioner = server.backend.provisioner
    another = next(key for key in BACKENDS if key != provisioner)

    out = dossier_of(server)

    assert (out / "evals" / "cve" / "backends" / f"{provisioner}.py").exists()
    for service in BACKENDS[provisioner].built_services:
        assert (out / "evals" / "docker" / image_dockerfile(service).name).exists(), service
    assert not (out / "evals" / "cve" / "backends" / f"{another}.py").exists()


def test_a_holdout_calibration_copy_dossier_carries_its_holdout_target_reference_as_text(
    dossier_of: DossierOf,
):
    server = given.a_committed_server_with_a_holdout_calibration_copy()

    out = dossier_of(server)

    for target in copied_holdout_targets(server, given.the_copy_resolution()):
        it_carries_the_holdout_target_reference_of(out, target)
        for service in (*target.images, target.patched_image):
            assert (out / "evals" / "docker" / image_dockerfile(service).name).exists(), service


def test_a_detection_holdout_server_with_its_own_fix_check_carries_its_reference_and_card(
    dossier_of: DossierOf,
):
    server = a_detection_holdout_server_with_its_own_fix_check()

    out = dossier_of(server)

    for target in its_holdout_targets(server):
        it_carries_the_holdout_target_reference_of(out, target)


@pytest.mark.parametrize(
    "server",
    [
        admissions.an_admitted_server(),
        mutations.with_the_registered_backend(admissions.an_admitted_server(), "doris"),
    ],
    ids=["without a backend", "on the doris backend"],
)
def test_the_confinement_names_every_option_the_run_sets(server: AdmittedServer):
    confinement = confinement_text(server)

    for option in (*confinement_args(), *user_args(server.host.user)):
        assert option in confinement, option
    if server.backend is not None:
        assert server.backend.network in confinement


def test_the_readme_builds_the_run_image_and_names_the_fix_check_modules():
    server = admissions.an_admitted_server()
    modules = ["evals.cve.nuisance.fix_checks.first", "evals.cve.nuisance.fix_checks.second"]

    readme = re_admission_readme(server, modules)

    assert f'["<prefix>-{server.service}"]' in readme
    for module in modules:
        assert f"`{module}`" in readme, module


def test_the_readme_names_the_backend_lifecycle_of_a_server_with_a_backend():
    server = mutations.with_the_registered_backend(admissions.an_admitted_server(), "doris")

    readme = re_admission_readme(server, [])

    assert "`evals/cve/backends/doris.py`" in readme


def test_the_readme_says_a_server_without_a_backend_has_none():
    readme = re_admission_readme(admissions.an_admitted_server(), [])

    assert "has no backend" in readme


def test_the_readme_commands_name_the_probe_and_fix_check_entry_points_the_kit_ships():
    readme = re_admission_readme(admissions.an_admitted_server(), [])

    assert f"python -m {benign_probe.__name__} --record" in readme
    assert f"from {check_fix.__module__} import {check_fix.__name__}" in readme


def test_the_readme_keeps_the_agent_off_every_shared_backend():
    readme = re_admission_readme(admissions.an_admitted_server(), [])

    assert "(`mcp-auditor-cve-*`)" in readme
    assert "never removed or stopped by the agent" in readme
    for key, backend in given.shared_backends().items():
        assert fnmatch(backend.network, "mcp-auditor-cve-*"), key


def test_the_confinement_of_a_server_on_a_per_launch_backend_points_at_its_launch():
    server = given.a_server_on_a_per_launch_backend()

    confinement = confinement_text(server, given.a_per_launch_registry())

    assert "`evals/cve/backends/fake_per_launch.py`" in confinement
    assert "stood for each launch" in confinement
    assert f"`{given.PER_LAUNCH_NETWORK_PREFIX}`" in confinement
    for option in confinement_args():
        assert option in confinement, option


def test_a_copy_on_a_drawn_target_and_its_sibling_resolve_to_one_target():
    drawn = HOLDOUT_TARGETS[0].flaw_id
    sibling = "CVE-2099-0002"
    server = given.a_server_copying(drawn, sibling)

    targets = copied_holdout_targets(server, {drawn: drawn, sibling: drawn})

    assert [target.flaw_id for target in targets] == [drawn]


def test_a_copied_flaw_no_target_carries_is_refused():
    server = mutations.a_server_with_a_holdout_calibration_copy_at(None)

    with pytest.raises(Refused):
        copied_holdout_targets(server, {})


def test_a_server_the_admission_does_not_hold_is_refused():
    with pytest.raises(Refused):
        re_admission_plan(admissions.walk_inputs_of(), admissions.an_admission(), "npm:ghost")
