import textwrap

from tests.unit.project.support.code_standards_scan import CodeStandard, SourceFile, violations

A_MODULE_PATH = "evals/cve/module.py"


def a_source(text: str, path: str = A_MODULE_PATH) -> SourceFile:
    return SourceFile(path, textwrap.dedent(text))


def found(source: SourceFile) -> list[tuple[CodeStandard, str]]:
    return [(violation.standard, violation.symbol) for violation in violations(source)]
