"""What the draw checks of its sources and of its cases before it writes anything."""

import hashlib
import re
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel

from evals.judge_fixture import JudgeCase, SourceRun

SCALAR_CONDITIONS = (
    "runs",
    "budget",
    "provider",
    "model",
    "judge_model",
    "reasoning",
    "judge_reasoning",
)

_KEY_PATTERNS = {
    "sk- key pattern": re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    "sk-ant- key pattern": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "AIza key pattern": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
}


class SourceReport(BaseModel):
    """The slice of `eval_report.json` or `cve_report.json` the draw reads."""

    commit: str
    dirty: bool
    conditions: dict[str, Any]


def leaked_secrets(cases: Iterable[JudgeCase], home: str, user: str) -> list[str]:
    """Names the case and the kind of match only: the matched text would leak again."""
    user_word = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(user)}(?![A-Za-z0-9_])", re.IGNORECASE)
    leaks: list[str] = []
    for case in cases:
        text = case.inputs.model_dump_json()
        found = {
            "home path": home in text,
            "user name": user_word.search(text) is not None,
            **{kind: pattern.search(text) is not None for kind, pattern in _KEY_PATTERNS.items()},
        }
        kinds = [kind for kind, matched in found.items() if matched]
        leaks.extend(f"case {case.id}: {kind}" for kind in kinds)
    return leaks


def source_run(path: str, export: bytes, report: SourceReport) -> SourceRun:
    return SourceRun(
        path=path,
        sha256=hashlib.sha256(export).hexdigest(),
        commit=report.commit,
        conditions={name: report.conditions.get(name) for name in SCALAR_CONDITIONS},
    )


def source_refusals(reports: dict[str, SourceReport]) -> list[str]:
    refusals = [
        f"{path} ran on a tree with tracked modifications"
        for path, report in reports.items()
        if report.dirty
    ]
    commits = sorted({report.commit for report in reports.values()})
    if len(commits) > 1:
        refusals.append(f"the sources ran at different commits: {', '.join(commits)}")
    return refusals
