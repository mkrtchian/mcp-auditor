from pathlib import Path

README = Path(__file__).resolve().parents[2] / "README.md"


def test_the_payload_safety_bullet_carries_its_limit_beside_its_promise():
    scope = _section(README.read_text(), "## Scope and limitations")
    promise = [bullet for bullet in _bullets(scope) if "ADR 013" in bullet]

    assert len(promise) == 1
    assert "ADR 011" in promise[0]


def _section(markdown: str, heading: str) -> str:
    lines = markdown.splitlines()
    start = lines.index(heading) + 1
    end = next(
        (i for i, line in enumerate(lines[start:], start) if line.startswith("## ")),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _bullets(markdown: str) -> list[str]:
    bullets: list[str] = []
    for line in markdown.splitlines():
        if line.startswith("- "):
            bullets.append(line)
        elif bullets and line.startswith("  "):
            bullets[-1] += " " + line.strip()
    return bullets
