import ast
import importlib.util
from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_fix_checks_given as given
from evals.cve.docker_paths import image_dockerfile
from evals.cve.kit.driver import unit_of
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.nuisance.counting import counted_flaws
from evals.cve.nuisance.fixtures import FIX_CHECK_FIXTURES
from evals.cve.proofs import is_aimed
from tests.unit.support.kit_isolation import scan_tree
from tests.unit.support.test_nuisance_committed_admission_given import the_committed_admission

_FIX_CHECK_DIR = Path(__file__).resolve().parents[2] / "evals" / "cve" / "nuisance" / "fix_checks"


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


_ENVIRONMENTS = "evals.cve.environments"


def _is_cve_environments(name: str) -> bool:
    return name == _ENVIRONMENTS or name.startswith(f"{_ENVIRONMENTS}.")


def test_the_scans_read_the_fix_check_modules():
    # Both scans pass on an empty tree, so a stale directory would check nothing.
    assert any(path.name != "__init__.py" for path in _FIX_CHECK_DIR.rglob("*.py"))


def test_the_environments_scan_names_an_importable_module():
    # A stale name would match no import, so the scan below would check nothing.
    assert importlib.util.find_spec(_ENVIRONMENTS) is not None


def test_no_fix_check_module_imports_mcp_auditor():
    assert scan_tree(_FIX_CHECK_DIR) == {}


def test_no_fix_check_module_imports_cve_environments():
    offenders = {
        str(path): names
        for path in sorted(_FIX_CHECK_DIR.rglob("*.py"))
        if (names := _cve_environments_imports(path.read_text(), str(path)))
    }
    assert offenders == {}


def test_every_counted_flaw_has_a_fix_check_fixture_unless_its_fix_check_is_a_copy():
    fixture_flaws = {fixture.flaw for fixture in FIX_CHECK_FIXTURES}
    for server in the_committed_admission().servers:
        for flaw in counted_flaws(server):
            if flaw.fix_check.source == "detection_holdout_calibration":
                continue
            assert flaw.flaw in fixture_flaws, (
                f"{server.server_package}: counted flaw {flaw.flaw} has no FixCheckFixture"
            )


@pytest.mark.parametrize("fixture", FIX_CHECK_FIXTURES, ids=lambda t: t.flaw)
async def test_every_exploit_reads_as_aimed_and_no_benign_call_does(fixture: FixCheckFixture):
    for exploit in fixture.exploits:
        assert is_aimed(unit_of(await given.recorded(fixture, exploit)), fixture.aim)
    assert not is_aimed(unit_of(await given.recorded(fixture, *fixture.benign_calls)), fixture.aim)


@pytest.mark.parametrize("fixture", FIX_CHECK_FIXTURES, ids=lambda t: t.flaw)
async def test_the_exploits_call_exactly_the_flaws_tools(fixture: FixCheckFixture):
    exchanges = await given.recorded(fixture, *fixture.exploits)

    assert {name for name, _, _ in exchanges} == given.reached_tools(fixture)


@pytest.mark.parametrize("fixture", FIX_CHECK_FIXTURES, ids=lambda t: t.flaw)
def test_the_fixture_effect_class_is_the_flaws(fixture: FixCheckFixture):
    assert fixture.effect_class == given.flaw_record(fixture).effect_class


@pytest.mark.parametrize(
    "fixture", [t for t in FIX_CHECK_FIXTURES if t.benign_calls], ids=lambda t: t.flaw
)
async def test_every_counted_tool_has_a_benign_call(fixture: FixCheckFixture):
    exchanges = await given.recorded(fixture, *fixture.benign_calls)

    assert given.counted_tools(fixture) <= {name for name, _, _ in exchanges}


@pytest.mark.parametrize("fixture", FIX_CHECK_FIXTURES, ids=lambda t: t.flaw)
def test_every_version_of_a_fix_check_has_its_dockerfile(fixture: FixCheckFixture):
    services = (fixture.vulnerable_service, fixture.patched_service, fixture.server_patched_service)

    assert [s for s in services if s is not None and not image_dockerfile(s).is_file()] == []


@pytest.mark.parametrize("fixture", FIX_CHECK_FIXTURES, ids=lambda t: t.flaw)
def test_the_last_patched_version_is_the_image_the_run_audits_or_its_release(
    fixture: FixCheckFixture,
):
    # A `<service>-patched` image carries what only the fix check reads, which the run image may
    # not, on the run's release: every build argument it pins is one the run Dockerfile pins.
    last_patched = fixture.server_patched_service or fixture.patched_service
    service = given.admitted_server(fixture).service

    assert last_patched in (service, f"{service}-patched")
    assert given.build_arguments(last_patched) <= given.build_arguments(service)
