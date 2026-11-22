import subprocess
import tomllib

from tests.unit.project.support.code_standards_debt import DEBTS, Debt
from tests.unit.project.support.code_standards_scan import SourceFile, Violation, violations
from tests.unit.project.support.fingerprinted_sources import REPOSITORY_ROOT

PACKAGE = REPOSITORY_ROOT / "src" / "mcp_auditor"
HEXAGON = ("domain", "graph")


def tree_violations() -> list[Violation]:
    return [violation for path in _swept_paths() for violation in violations(_source(path))]


def unlisted(found: list[Violation]) -> list[str]:
    listed = {_key(debt) for debt in DEBTS}
    return [
        f"{violation.path}:{violation.line}: {violation.standard} {violation.symbol}"
        for violation in found
        if _key(violation) not in listed
    ]


def stale(found: list[Violation]) -> list[Debt]:
    keys = {_key(violation) for violation in found}
    return [debt for debt in DEBTS if _key(debt) not in keys]


def composition_root_modules() -> set[str]:
    modules = {path.stem for path in PACKAGE.glob("*.py")}
    packages = {path.parent.name for path in PACKAGE.glob("*/__init__.py")}
    return (modules | packages) - {"__init__", *HEXAGON}


def banned_modules(layer: str) -> set[str]:
    configuration = tomllib.loads((PACKAGE / layer / "ruff.toml").read_text())
    return set(configuration["lint"]["flake8-tidy-imports"]["banned-api"])


# Every Python file git knows of, not yet staged included, so a module created during a change is
# swept before it is committed. A path deleted from the working tree but still in the index is
# listed by `--cached`, hence the existence check.
def _swept_paths() -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.py"],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return sorted(path for path in set(listed) if (REPOSITORY_ROOT / path).is_file())


def _source(path: str) -> SourceFile:
    return SourceFile(path, (REPOSITORY_ROOT / path).read_text())


def _key(entry: Violation | Debt) -> tuple[str, str, str]:
    return (entry.path, entry.standard, entry.symbol)
