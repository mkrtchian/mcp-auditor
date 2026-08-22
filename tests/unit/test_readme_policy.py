from pathlib import Path

README = Path(__file__).resolve().parents[2] / "README.md"

OVERCLAIMS = (
    "read-only",
    "no side effects",
    "safe against production",
    "will not modify your server",
    "sandbox",
    "security boundary",
)


def test_the_payload_safety_bullet_links_adr_011_beside_adr_013():
    assert "ADR 011" in _safety_bullet()


def test_the_payload_safety_bullet_promises_no_property_the_guard_cannot_deliver():
    bullet = _safety_bullet().lower()

    for overclaim in OVERCLAIMS:
        assert overclaim not in bullet


def _safety_bullet() -> str:
    scope = _section(README.read_text(), "## Scope and limitations")
    bullets = [bullet for bullet in _bullets(scope) if "ADR 013" in bullet]

    assert len(bullets) == 1, "the promise and its limit must live in one bullet"
    return bullets[0]


def _section(markdown: str, heading: str) -> str:
    lines = markdown.splitlines()
    assert heading in lines, f"{heading} is gone from README.md"
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
