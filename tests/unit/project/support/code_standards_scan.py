"""The code standards scan: the standards of CLAUDE.md that no Ruff rule reads.

Three standards, each read on the AST of one module. Newspaper order: a top-level function every
user of which sits below it, and no code Python runs at import time uses, is out of order. One
given/then pair per test file: under `tests/`, only `test_x.py` and the `test_x_given.py` and
`test_x_then.py` of its directory's `support/` (or beside it) import that `test_x_given` or
`test_x_then`. Fakes, not mocks: no `monkeypatch.setattr`. A violation's line is reported,
never compared: the debt list keys a violation by path, standard and symbol, so an unrelated edit
never moves it.
"""

import ast
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TypeGuard


class CodeStandard(StrEnum):
    NEWSPAPER_ORDER = "newspaper-order"
    FOREIGN_GIVEN_THEN = "foreign-given-then"
    MONKEYPATCH_SETATTR = "monkeypatch-setattr"


@dataclass(frozen=True)
class Violation:
    path: str  # relative to the repository root, POSIX separators
    standard: CodeStandard
    symbol: str
    line: int


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str


def violations(source: SourceFile) -> list[Violation]:
    module = ast.parse(source.text, filename=source.path)
    return [
        *_newspaper_violations(source, module),
        *_foreign_given_then_imports(source, module),
        *_monkeypatch_setattrs(source, module),
    ]


def _newspaper_violations(source: SourceFile, module: ast.Module) -> list[Violation]:
    eager = _eager_loads(module)
    deferred = [_deferred_loads(statement) for statement in module.body]
    found: list[Violation] = []
    for index, statement in enumerate(module.body):
        if (
            not isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef)
            or statement.name in eager
        ):
            continue
        users = [
            position
            for position, loads in enumerate(deferred)
            if position != index and statement.name in loads
        ]
        if users and min(users) > index:
            found.append(
                Violation(
                    source.path, CodeStandard.NEWSPAPER_ORDER, statement.name, statement.lineno
                )
            )
    return found


# Everything Python runs at import time: module-level statements, and the parts of a definition
# that are evaluated when it is defined (decorators, defaults, annotations, bases, class bodies).
def _eager_loads(module: ast.Module) -> set[str]:
    return {name for statement in module.body for name in _eager_loads_of(statement)}


def _eager_loads_of(statement: ast.stmt) -> set[str]:
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
        return _loads(_definition_time_parts(statement))
    if isinstance(statement, ast.ClassDef):
        header = _loads([*statement.decorator_list, *statement.bases, *statement.keywords])
        return header.union(*(_eager_loads_of(member) for member in statement.body))
    return _loads([statement])


def _definition_time_parts(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    arguments = function.args
    annotations = [
        argument.annotation for argument in _every_argument(arguments) if argument.annotation
    ]
    return [
        *function.decorator_list,
        *arguments.defaults,
        *(default for default in arguments.kw_defaults if default is not None),
        *annotations,
        *([function.returns] if function.returns else []),
    ]


def _every_argument(arguments: ast.arguments) -> list[ast.arg]:
    return [
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
        *([arguments.vararg] if arguments.vararg else []),
        *([arguments.kwarg] if arguments.kwarg else []),
    ]


# What a definition loads only once it runs: a function's body, the bodies of a class's methods.
# A name a function binds itself (an argument, an assignment, an import) is its own, not a use.
def _deferred_loads(statement: ast.stmt) -> set[str]:
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
        return _loads(statement.body) - _locals(statement)
    if isinstance(statement, ast.ClassDef):
        return set().union(*(_deferred_loads(member) for member in statement.body))
    return set()


def _locals(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    bound = {argument.arg for argument in _every_argument(function.args)}
    for node in (inner for statement in function.body for inner in ast.walk(statement)):
        bound |= _names_bound_by(node)
    return bound


def _names_bound_by(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
        return {node.id}
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return {node.name}
    if isinstance(node, ast.Import | ast.ImportFrom):
        return {(alias.asname or alias.name).split(".")[0] for alias in node.names}
    return set()


def _loads(nodes: list[ast.AST] | list[ast.stmt]) -> set[str]:
    return {
        node.id
        for root in nodes
        for node in ast.walk(root)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }


_GIVEN_OR_THEN = re.compile(r"(test_\w+)_(?:given|then)")


def _foreign_given_then_imports(source: SourceFile, module: ast.Module) -> list[Violation]:
    if not source.path.startswith("tests/"):
        return []
    owned = _owners(source.path)
    return [
        Violation(source.path, CodeStandard.FOREIGN_GIVEN_THEN, last, line)
        for imported, line in sorted(_imported_modules(module), key=lambda pair: pair[1])
        if _GIVEN_OR_THEN.fullmatch(last := imported.split(".")[-1]) and imported not in owned
    ]


# The full dotted name of every module an import may name: `import a.b`, `from a import b` (b may
# be a module) and `from a.b import name`. A relative import is not resolved against its package.
def _imported_modules(module: ast.Module) -> list[tuple[str, int]]:
    imported: list[tuple[str, int]] = []
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imported += [(alias.name, node.lineno) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.append((node.module, node.lineno))
            package = f"{node.module}." if node.module else ""
            imported += [(f"{package}{alias.name}", node.lineno) for alias in node.names]
    return imported


# A test's given and then sit in its directory's `support/`, or beside it. A given or then maps
# back to the test it serves, so it owns the same modules.
def _owners(path: str) -> set[str]:
    importer = PurePosixPath(path).with_suffix("")
    directory, test = importer.parent, importer.name
    if match := _GIVEN_OR_THEN.fullmatch(test):
        test = match.group(1)
        if directory.name == "support":
            directory = directory.parent
    package = ".".join(directory.parts)
    return {
        f"{package}.{test}",
        f"{package}.support.{test}_given",
        f"{package}.support.{test}_then",
        f"{package}.{test}_given",
        f"{package}.{test}_then",
    }


def _monkeypatch_setattrs(source: SourceFile, module: ast.Module) -> list[Violation]:
    if "monkeypatch.setattr" not in source.text:  # spares the walk of nearly every module
        return []
    found: list[Violation] = []
    for statement in module.body:
        owner = (
            statement.name
            if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            else "<module>"
        )
        calls = [node for node in ast.walk(statement) if _is_monkeypatch_setattr(node)]
        found += [
            Violation(
                source.path,
                CodeStandard.MONKEYPATCH_SETATTR,
                f"{owner}:{_patched(call)}",
                call.lineno,
            )
            for call in sorted(calls, key=lambda call: call.lineno)
        ]
    return found


def _is_monkeypatch_setattr(node: ast.AST) -> TypeGuard[ast.Call]:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "setattr"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "monkeypatch"
    )


def _patched(call: ast.Call) -> str:
    if not call.args:
        return ""
    target = ast.unparse(call.args[0])
    if len(call.args) > 1:
        name = call.args[1]
        if isinstance(name, ast.Constant) and isinstance(name.value, str):
            target += f".{name.value}"
    return target
