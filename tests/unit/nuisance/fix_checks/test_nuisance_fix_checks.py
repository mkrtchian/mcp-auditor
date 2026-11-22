import ast
import importlib.util
from pathlib import Path

from tests.unit.support.kit_isolation import scan_tree

_FIX_CHECK_DIR = Path(__file__).resolve().parents[4] / "evals" / "cve" / "nuisance" / "fix_checks"


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
