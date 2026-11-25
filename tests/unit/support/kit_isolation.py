"""Isolation checks for the kit, static and at runtime.

Reused by test_kit_isolation.py, test_detection_calibration_dossier.py and the nuisance dossier
tests on the written `--out` tree, and by the fix-check import scan: the one place that knows what
importing a package means for these isolation checks.
"""

import ast
import json
import subprocess
import sys
from pathlib import Path


def scan_tree(root: Path, package: str = "mcp_auditor") -> dict[str, list[str]]:
    """Each .py file under root that imports `package`, mapped to the offending names."""
    found: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*.py")):
        offenders = _package_imports(path.read_text(), str(path), package)
        if offenders:
            found[str(path)] = offenders
    return found


def _package_imports(source: str, filename: str, package: str) -> list[str]:
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        if isinstance(node, ast.Import):
            offenders += [alias.name for alias in node.names if _is_in(alias.name, package)]
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            # `from X import y` imports the package when X is in it, or when X.y is.
            if _is_in(node.module, package):
                offenders.append(node.module)
            else:
                submodules = (f"{node.module}.{alias.name}" for alias in node.names)
                offenders += [name for name in submodules if _is_in(name, package)]
    return offenders


def _is_in(name: str, package: str) -> bool:
    return name == package or name.startswith(f"{package}.")


def kit_modules(out: Path) -> list[str]:
    """Every module of the written kit's `evals` package, by dotted name."""
    return [_dotted_name(path.relative_to(out)) for path in sorted((out / "evals").rglob("*.py"))]


def _dotted_name(relative: Path) -> str:
    parts = relative.with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def import_closure_offenders(modules: list[str], root: Path) -> list[str]:
    """The mcp_auditor modules importing `modules` from `root` pulls into sys.modules, measured
    in a fresh interpreter so the test suite's own mcp_auditor imports cannot pollute the
    result."""
    script = (
        "import importlib, sys, json\n"
        f"for name in {modules!r}:\n"
        "    importlib.import_module(name)\n"
        "bad = [k for k in sys.modules if k == 'mcp_auditor' or k.startswith('mcp_auditor.')]\n"
        "print(json.dumps(sorted(bad)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=root, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise AssertionError(f"could not import the kit in isolation:\n{result.stderr}")
    return json.loads(result.stdout.strip().splitlines()[-1])
