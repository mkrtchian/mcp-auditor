import ast
from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_fix_checks_given as given
from evals.cve_planting import SymbolicUser
from evals.cve_proofs import is_aimed
from evals.docker_paths import image_dockerfile
from evals.holdout_kit.fix_check import FixCheckTarget
from evals.holdout_kit.kit_driver import unit_of
from evals.nuisance_counting import counted_flaws
from evals.nuisance_fixtures import FIX_CHECK_TARGETS
from tests.unit.support.holdout_kit_isolation import scan_tree
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission

_FIX_CHECK_DIR = Path(__file__).resolve().parents[2] / "evals" / "nuisance_fix_checks"


def _cve_environments_imports(source: str, filename: str) -> list[str]:
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        if isinstance(node, ast.Import):
            offenders += [alias.name for alias in node.names if _is_cve_environments(alias.name)]
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and _is_cve_environments(node.module)
        ):
            offenders.append(node.module)
    return offenders


def _is_cve_environments(name: str) -> bool:
    return name == "evals.cve_environments" or name.startswith("evals.cve_environments.")


def test_no_fix_check_module_imports_mcp_auditor():
    assert scan_tree(_FIX_CHECK_DIR) == {}


def test_no_fix_check_module_imports_cve_environments():
    offenders = {
        str(path): names
        for path in sorted(_FIX_CHECK_DIR.rglob("*.py"))
        if (names := _cve_environments_imports(path.read_text(), str(path)))
    }
    assert offenders == {}


def test_no_fix_check_runs_as_the_host_user():
    assert [t.flaw for t in FIX_CHECK_TARGETS if t.planting_host.user is SymbolicUser.HOST] == []


def test_every_counted_flaw_has_a_fix_check_target_unless_holdout_calibrated():
    target_flaws = {target.flaw for target in FIX_CHECK_TARGETS}
    for server in the_committed_admission().servers:
        for flaw in counted_flaws(server):
            if flaw.fix_check.source == "holdout_calibration":
                continue
            assert flaw.flaw in target_flaws, (
                f"{server.server_package}: counted flaw {flaw.flaw} has no FixCheckTarget"
            )


@pytest.mark.parametrize("target", FIX_CHECK_TARGETS, ids=lambda t: t.flaw)
async def test_every_exploit_reads_as_aimed_and_no_benign_call_does(target: FixCheckTarget):
    for exploit in target.exploits:
        assert is_aimed(unit_of(await given.recorded(target, exploit)), target.aim)
    assert not is_aimed(unit_of(await given.recorded(target, *target.benign_calls)), target.aim)


@pytest.mark.parametrize("target", FIX_CHECK_TARGETS, ids=lambda t: t.flaw)
async def test_the_exploits_call_exactly_the_flaws_tools(target: FixCheckTarget):
    exchanges = await given.recorded(target, *target.exploits)

    assert {name for name, _, _ in exchanges} == given.reached_tools(target)


@pytest.mark.parametrize("target", FIX_CHECK_TARGETS, ids=lambda t: t.flaw)
def test_the_target_mechanism_is_the_flaws_effect_class(target: FixCheckTarget):
    assert target.mechanism == given.flaw_record(target).effect_class


@pytest.mark.parametrize(
    "target", [t for t in FIX_CHECK_TARGETS if t.benign_calls], ids=lambda t: t.flaw
)
async def test_every_counted_tool_has_a_benign_call(target: FixCheckTarget):
    exchanges = await given.recorded(target, *target.benign_calls)

    assert given.counted_tools(target) <= {name for name, _, _ in exchanges}


@pytest.mark.parametrize("target", FIX_CHECK_TARGETS, ids=lambda t: t.flaw)
def test_every_version_of_a_fix_check_has_its_dockerfile(target: FixCheckTarget):
    services = (target.vulnerable_service, target.patched_service, target.server_patched_service)

    assert [s for s in services if s is not None and not image_dockerfile(s).is_file()] == []


@pytest.mark.parametrize("target", FIX_CHECK_TARGETS, ids=lambda t: t.flaw)
def test_the_last_patched_version_is_the_image_the_run_audits_or_its_release(
    target: FixCheckTarget,
):
    # A `<service>-patched` image carries what only the fix check reads, which the run image may
    # not, on the run's release: every build argument it pins is one the run Dockerfile pins.
    last_patched = target.server_patched_service or target.patched_service
    service = given.admitted_server(target).service

    assert last_patched in (service, f"{service}-patched")
    assert given.build_arguments(last_patched) <= given.build_arguments(service)
