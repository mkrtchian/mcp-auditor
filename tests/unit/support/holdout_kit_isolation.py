"""Isolation checks for the holdout calibration kit, static and at runtime.

Reused by test_holdout_kit_isolation.py and (Step 5) by test_run_holdout.py on the written
`--out` tree: the one place that knows what "free of mcp_auditor" means for the kit.
"""

import ast
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def mcp_auditor_imports(source: str, filename: str = "<string>") -> list[str]:
    """Every mcp_auditor import (the package or a submodule) in one Python source, by name."""
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        if isinstance(node, ast.Import):
            offenders += [alias.name for alias in node.names if _is_mcp_auditor(alias.name)]
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and _is_mcp_auditor(node.module)
        ):
            offenders.append(node.module)
    return offenders


def scan_tree(root: Path) -> dict[str, list[str]]:
    """Each .py file under root that imports mcp_auditor, mapped to the offending names."""
    found: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*.py")):
        offenders = mcp_auditor_imports(path.read_text(), str(path))
        if offenders:
            found[str(path)] = offenders
    return found


def import_closure_offenders(modules: list[str]) -> list[str]:
    """The mcp_auditor modules importing `modules` pulls into sys.modules, measured in a fresh
    interpreter so the test suite's own mcp_auditor imports cannot pollute the result."""
    script = (
        "import importlib, sys, json\n"
        f"for name in {modules!r}:\n"
        "    importlib.import_module(name)\n"
        "bad = [k for k in sys.modules if k == 'mcp_auditor' or k.startswith('mcp_auditor.')]\n"
        "print(json.dumps(sorted(bad)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=REPO_ROOT, capture_output=True, text=True
    )
    if result.returncode != 0:
        raise AssertionError(f"could not import the kit in isolation:\n{result.stderr}")
    return json.loads(result.stdout.strip().splitlines()[-1])


def _is_mcp_auditor(name: str) -> bool:
    return name == "mcp_auditor" or name.startswith("mcp_auditor.")
