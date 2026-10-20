import ast
import re
from pathlib import Path

from evals import holdout_census, holdout_exclusions
from evals.judge_fixture import CaseLabel, CaseSource, JudgeCase, JudgeInputs, load_fixture
from mcp_auditor.domain.models import AuditCategory

_TESTS_DIR = Path(__file__).resolve().parents[2]
_REPO_ROOT = Path(__file__).resolve().parents[3]

HONEYPOT_SERVERS = (
    _TESTS_DIR / "honeypot_server.py",
    _TESTS_DIR / "subtle_server.py",
    _TESTS_DIR / "chain_honeypot_server.py",
)

_JUDGE_CASES = _REPO_ROOT / "evals" / "fixtures" / "judge_cases.json"
_HOLDOUT_CENSUS = _REPO_ROOT / "evals" / "holdout_census.json"

# The auditor's own tool name heads every payload marker it plants (`mcp-auditor-probe`, the
# `mcp-auditor-no-such-…` probe paths). A server never emits that name except by echoing our
# payload back, so a run matching it is dropped: the corpus holds the server's text, not ours.
_AUDITOR_MARKER = re.compile(r"mcp-auditor[\w-]*")

_MARKER_CHARACTERS = set("_@./-")


def discriminating_literals() -> set[str]:
    candidates = {
        text.strip() for server in HONEYPOT_SERVERS for text in _literals_and_names_of(server)
    }
    return {text for text in candidates if _is_discriminating(text)}


def layout_literals() -> set[str]:
    # The deployment layout's instantiation literals (ADR 031). `/srv/` carries the trailing
    # slash so the FHS refused root `/srv` (ADR 017, confinement.py) is not a false positive:
    # only a layout path (`/srv/app`, `/srv/.env`, `/srv/app.git`) matches.
    return {"/srv/", "app.git"}


def shipped_constants() -> list[tuple[Path, str]]:
    return [
        (path, text)
        for path in sorted((_REPO_ROOT / "src").rglob("*.py"))
        for text in _string_constants_of(_parse(path))
    ]


def excluded_server_corpus() -> set[str]:
    return server_corpus_of(cve_cases(), servers_by_cve())


def cve_cases() -> list[JudgeCase]:
    fixture = load_fixture(_JUDGE_CASES)
    return [case for case in fixture.cases if case.source == CaseSource.CVE]


def servers_by_cve() -> dict[str, str]:
    census = holdout_census.load_census(_HOLDOUT_CENSUS)
    return {
        classification.flaw: classification.server_package
        for own in census.classifications.values()
        for classification in own
    }


def server_corpus_of(cases: list[JudgeCase], servers: dict[str, str]) -> set[str]:
    corpus: set[str] = set()
    for case in cases:
        cve_id = _cve_id_of(case)
        if cve_id not in servers:
            raise LookupError(f"the census does not classify {cve_id} of case {case.id}")
        if servers[cve_id] not in holdout_exclusions.EXCLUDED_SERVERS:
            continue
        corpus |= _server_texts_of(case)
    return corpus


def a_cve_case(
    cve_id: str,
    *,
    tool_description: str = "",
    response: str | None = None,
    error: str | None = None,
    arguments: dict[str, object] | None = None,
) -> JudgeCase:
    return JudgeCase(
        id="crafted",
        source=CaseSource.CVE,
        origin=f"cve {cve_id}",
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


def _cve_id_of(case: JudgeCase) -> str:
    return case.origin.split()[1]


def _server_texts_of(case: JudgeCase) -> set[str]:
    inputs = case.inputs
    payload = [value for value in inputs.arguments.values() if isinstance(value, str)]
    pieces = (inputs.tool_description, inputs.response, inputs.error)
    texts = {
        _without_payload(piece, payload)
        for piece in pieces
        if isinstance(piece, str) and piece != "None"
    }
    return {text for text in texts if _is_discriminating(text)}


def _without_payload(text: str, payload: list[str]) -> str:
    for value in payload:
        text = text.replace(value, "")
    return _AUDITOR_MARKER.sub("", text).strip()


def _literals_and_names_of(path: Path) -> list[str]:
    tree = _parse(path)
    function_names = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    return _string_constants_of(tree) + function_names


def _is_discriminating(text: str) -> bool:
    if len(text) < 3:
        return False
    return (
        len(text.split()) >= 2
        or any(character.isupper() or character.isdigit() for character in text)
        or any(character in _MARKER_CHARACTERS for character in text)
    )


def _string_constants_of(tree: ast.AST) -> list[str]:
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))
