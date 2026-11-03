"""The repository modules a dossier module needs, found by reading its imports.

A dossier copies a module together with every repository module it imports, transitively, so
the exported tree runs with no repository on the path. The walk reads the source (no import is
executed) and refuses a closure that reaches `mcp_auditor`, which a dossier must never carry.
"""

import ast
import shutil
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def import_closure(modules: Iterable[str], root: Path = REPO_ROOT) -> list[str]:
    found: set[str] = set()
    pending = list(modules)
    while pending:
        module = pending.pop()
        if module in found:
            continue
        found.add(module)
        pending += _packages_of(module, root)
        pending += _imported_modules(module, root)
    return sorted(found)


def copy_closure(out: Path, modules: Iterable[str]) -> None:
    for module in import_closure(modules):
        source = _source_file(module, REPO_ROOT)
        target = out / source.relative_to(REPO_ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _source_file(module: str, root: Path) -> Path:
    source = _module_file(module, root)
    if source is None:
        raise ValueError(f"{module} has no source file under {root}")
    return source


def _module_file(module: str, root: Path) -> Path | None:
    base = root.joinpath(*module.split("."))
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _packages_of(module: str, root: Path) -> list[str]:
    parts = module.split(".")
    prefixes = (".".join(parts[:end]) for end in range(1, len(parts)))
    return [prefix for prefix in prefixes if _module_file(prefix, root) is not None]


def _imported_modules(module: str, root: Path) -> list[str]:
    source = _source_file(module, root)
    names: list[str] = []
    for node in ast.walk(ast.parse(source.read_text(), filename=str(source))):
        if isinstance(node, ast.Import):
            names += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            names.append(node.module)
            names += [f"{node.module}.{alias.name}" for alias in node.names]
    for name in names:
        if name == "mcp_auditor" or name.startswith("mcp_auditor."):
            raise ValueError(f"{module} imports {name}, which a dossier must never carry")
    return [name for name in names if _module_file(name, root) is not None]
