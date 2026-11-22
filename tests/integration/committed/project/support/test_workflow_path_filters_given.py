import re
import subprocess
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from evals.honeypots import REPO_ROOT

WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))


def path_filters(workflow: Path) -> list[tuple[str, str]]:
    """Each (event, path filter) of the workflow's push and pull_request triggers."""
    loaded: dict[Any, Any] = yaml.safe_load(workflow.read_text())
    # YAML 1.1 reads the bare key `on` as the boolean True.
    triggers: dict[str, Any] = loaded.get("on", loaded.get(True)) or {}
    filters: list[tuple[str, str]] = []
    for event in ("push", "pull_request"):
        trigger: dict[str, list[str]] = triggers.get(event) or {}
        filters += [(event, pattern) for pattern in trigger.get("paths", [])]
    return filters


def every_path_filter() -> list[tuple[str, str, str]]:
    return [
        (workflow.name, event, pattern)
        for workflow in WORKFLOWS
        for event, pattern in path_filters(workflow)
    ]


def matches_a_tracked_file(pattern: str) -> bool:
    expression = _github_glob(pattern)
    return any(expression.fullmatch(path) for path in _tracked_files())


def _github_glob(pattern: str) -> re.Pattern[str]:
    # GitHub's filter syntax: `**` crosses directories, `*` does not.
    parts = re.split(r"(\*\*|\*)", pattern)
    translated = {"**": ".*", "*": "[^/]*"}
    return re.compile("".join(translated.get(part, re.escape(part)) for part in parts))


@cache
def _tracked_files() -> tuple[str, ...]:
    listed = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return tuple(listed.stdout.splitlines())
