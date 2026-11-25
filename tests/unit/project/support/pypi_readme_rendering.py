import re
import subprocess
import sys
from pathlib import Path

_LINK_TARGET = re.compile(r"\]\(([^)]*)\)")


def rendered(project_dir: Path) -> str:
    """The README as the hook renders it for PyPI, with the version 42.0."""
    return subprocess.run(
        [sys.executable, "-m", "hatch_fancy_pypi_readme", str(project_dir / "pyproject.toml")],
        check=True,
        capture_output=True,
        text=True,
        cwd=project_dir,
    ).stdout


def link_targets(markdown: str) -> list[str]:
    return _LINK_TARGET.findall(markdown)


def without_link_targets(markdown: str) -> str:
    return _LINK_TARGET.sub("]()", markdown)
