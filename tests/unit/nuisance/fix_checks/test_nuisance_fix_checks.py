import importlib.util
from pathlib import Path

from tests.unit.support.kit_isolation import scan_tree

_FIX_CHECK_DIR = Path(__file__).resolve().parents[4] / "evals" / "cve" / "nuisance" / "fix_checks"


_ENVIRONMENTS = "evals.cve.environments"


def test_the_scans_read_the_fix_check_modules():
    # Both scans pass on an empty tree, so a stale directory would check nothing.
    assert any(path.name != "__init__.py" for path in _FIX_CHECK_DIR.rglob("*.py"))


def test_the_environments_scan_names_an_importable_module():
    # A stale name would match no import, so the scan below would check nothing.
    assert importlib.util.find_spec(_ENVIRONMENTS) is not None


def test_no_fix_check_module_imports_mcp_auditor():
    assert scan_tree(_FIX_CHECK_DIR) == {}


def test_no_fix_check_module_imports_cve_environments():
    assert scan_tree(_FIX_CHECK_DIR, package=_ENVIRONMENTS) == {}
