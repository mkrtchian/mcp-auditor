import re
import shutil
import subprocess
import sys
from pathlib import Path

from evals.honeypots import REPO_ROOT

LINK_KINDS_README = """\
# Fixture

[![PyPI version](https://img.shields.io/pypi/v/mcp-auditor)](https://pypi.org/project/mcp-auditor/)

![demo](docs/demo/demo.gif)

The numbers are in [Measurement](#measurement), as of now.

Every run is kept in [runs](evals/cve/holdout_runs/), committed.

The default is described in [confinement](docs/usage.md#confinement) for each regime.

The decision is in an [ADR](https://github.com/mkrtchian/mcp-auditor) on GitHub.

## Measurement
"""

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


def a_project_with_readme(directory: Path, readme: str) -> Path:
    shutil.copy(REPO_ROOT / "pyproject.toml", directory / "pyproject.toml")
    (directory / "README.md").write_text(readme)
    return directory


def link_targets(markdown: str) -> list[str]:
    return _LINK_TARGET.findall(markdown)


def without_link_targets(markdown: str) -> str:
    return _LINK_TARGET.sub("]()", markdown)
