import shutil
from pathlib import Path

from evals.repository import REPO_ROOT

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


def a_project_with_readme(directory: Path, readme: str) -> Path:
    shutil.copy(REPO_ROOT / "pyproject.toml", directory / "pyproject.toml")
    (directory / "README.md").write_text(readme)
    return directory
