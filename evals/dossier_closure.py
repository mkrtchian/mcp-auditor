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
    importers: dict[str, str | None] = {}
    pending: list[tuple[str, str | None]] = [(module, None) for module in modules]
    while pending:
        module, importer = pending.pop()
        if module in importers:
            continue
        importers[module] = importer
        if _is_auditor(module):
            chain = " -> ".join(_import_chain(module, importers))
            raise ValueError(f"{chain}: a dossier must never carry mcp_auditor")
        pending += [(package, module) for package in _packages_of(module, root)]
        pending += [(imported, module) for imported in _imported_modules(module, root)]
    return sorted(importers)


def _is_auditor(module: str) -> bool:
    return module == "mcp_auditor" or module.startswith("mcp_auditor.")


def _import_chain(module: str, importers: dict[str, str | None]) -> list[str]:
    chain = [module]
    while (importer := importers[chain[0]]) is not None:
        chain.insert(0, importer)
    return chain


def copy_closure(out: Path, modules: Iterable[str], root: Path = REPO_ROOT) -> None:
    for module in import_closure(modules, root):
        source = _source_file(module, root)
        target = out / source.relative_to(root)
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
    return [name for name in names if _is_auditor(name) or _module_file(name, root) is not None]
