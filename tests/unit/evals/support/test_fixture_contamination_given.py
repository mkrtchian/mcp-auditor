import ast
from pathlib import Path

from evals.cve.census.census import CENSUS_PATH, load_census
from evals.honeypots import HONEYPOTS
from evals.judge.fixture import CaseLabel, CaseSource, JudgeCase, JudgeInputs, load_fixture
from evals.repository import REPO_ROOT
from evals.run_judge_eval import FIXTURES_PATH
from mcp_auditor.domain.models import AuditCategory
from tests.unit.evals.support import contamination


def discriminating_literals() -> set[str]:
    candidates = {
        text.strip() for honeypot in HONEYPOTS for text in _literals_and_names_of(honeypot.server)
    }
    return {text for text in candidates if contamination.is_discriminating(text)}


def layout_literals() -> set[str]:
    # The deployment layout's instantiation literals (ADR 031). `/srv/` carries the trailing
    # slash so the FHS refused root `/srv` (ADR 017, confinement.py) is not a false positive:
    # only a layout path (`/srv/app`, `/srv/.env`, `/srv/app.git`) matches.
    return {"/srv/", "app.git"}


def shipped_constants() -> list[tuple[Path, str]]:
    return [
        (path, text)
        for path in sorted((REPO_ROOT / "src").rglob("*.py"))
        for text in _string_constants_of(_parse(path))
    ]


def excluded_server_corpus() -> set[str]:
    return contamination.server_corpus_of(detection_cases(), servers_by_flaw())


def detection_cases() -> list[JudgeCase]:
    fixture = load_fixture(FIXTURES_PATH)
    return [case for case in fixture.cases if case.source == CaseSource.DETECTION_SUITE]


def servers_by_flaw() -> dict[str, str]:
    census = load_census(CENSUS_PATH)
    return {
        classification.flaw: classification.server_package
        for own in census.classifications.values()
        for classification in own
    }


def a_detection_case(
    flaw_id: str,
    *,
    tool_description: str = "",
    response: str | None = None,
    error: str | None = None,
    arguments: dict[str, object] | None = None,
) -> JudgeCase:
    return JudgeCase(
        id="crafted",
        source=CaseSource.DETECTION_SUITE,
        origin=f"cve {flaw_id}",
        inputs=JudgeInputs(
            tool_name="tool",
            tool_description=tool_description,
            category=AuditCategory.INPUT_VALIDATION,
            description="",
            arguments=arguments or {},
            response=response,
            error=error,
        ),
        label=CaseLabel.PASS,
        clause=None,
    )


def _literals_and_names_of(path: Path) -> list[str]:
    tree = _parse(path)
    function_names = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    return _string_constants_of(tree) + function_names


def _string_constants_of(tree: ast.AST) -> list[str]:
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))
