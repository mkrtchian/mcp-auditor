import ast
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parents[2]
_REPO_ROOT = Path(__file__).resolve().parents[3]

HONEYPOT_SERVERS = (
    _TESTS_DIR / "honeypot_server.py",
    _TESTS_DIR / "subtle_server.py",
    _TESTS_DIR / "chain_honeypot_server.py",
)

_MARKER_CHARACTERS = set("_@./-")


def discriminating_literals() -> set[str]:
    candidates = {
        text.strip() for server in HONEYPOT_SERVERS for text in _literals_and_names_of(server)
    }
    return {text for text in candidates if _is_discriminating(text)}


def shipped_constants() -> list[tuple[Path, str]]:
    return [
        (path, text)
        for path in sorted((_REPO_ROOT / "src").rglob("*.py"))
        for text in _string_constants_of(_parse(path))
    ]


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
