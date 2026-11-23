import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from evals.baseline import Baseline
from evals.declared_flips import (
    DECLARED_FLIPS_PATH,
    DeclaredFlip,
    Instrument,
    entries_of_commit,
    load_declared_flips,
)
from evals.repository import REPO_ROOT

RECORDING_REFUSED = "Recording refused."
REFUSED_BEFORE_ANY_LLM_CALL = "Refused before any LLM call."


class Refused(Exception):
    def __init__(self, title: str, reasons: list[str]) -> None:
        super().__init__(title, reasons)
        self.title = title
        self.reasons = reasons


@dataclass(frozen=True)
class TreeState:
    commit: str
    dirty: bool


@dataclass(frozen=True)
class WorkingTree:
    """What an instrument's session reads from the repository it runs in."""

    declared_flips_path: Path
    parent_commit: Callable[[], str | None]
    is_dirty: Callable[[], bool]
    read_tree: Callable[[], TreeState]


def declarations_of_head(
    instrument: Instrument, working_tree: WorkingTree
) -> tuple[list[DeclaredFlip], bool]:
    """The entries declared by the commit at HEAD, and whether the tree has tracked changes."""
    try:
        entries = load_declared_flips(working_tree.declared_flips_path)
    except ValidationError as error:
        reason = f"{working_tree.declared_flips_path} is not a valid declaration file: {error}"
        raise Refused(REFUSED_BEFORE_ANY_LLM_CALL, [reason]) from error
    if not entries:
        return [], False
    of_head = entries_of_commit(entries, instrument, working_tree.parent_commit())
    return of_head, bool(of_head) and working_tree.is_dirty()


def _parent_commit() -> str | None:
    """None on a root commit, a one-commit shallow clone or outside a git checkout."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", "HEAD~"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return completed.stdout.strip()


def tree_drift(before: TreeState, after: TreeState) -> list[str]:
    """What changed in the checkout while the runs of a recording went on."""
    reasons: list[str] = []
    if after.dirty:
        reasons.append("tracked files changed during the runs: record again from a clean tree")
    if after.commit != before.commit:
        reasons.append(
            f"HEAD moved from {before.commit} to {after.commit} during the runs: record again"
        )
    return reasons


def baseline_changed(loaded: Baseline | None, current: Baseline | None) -> list[str]:
    if loaded == current:
        return []
    return ["the baseline file changed during the runs: record again"]


def read_tree() -> TreeState:
    return TreeState(
        commit=_git("rev-parse", "HEAD"),
        dirty=_tree_is_dirty(),
    )


def last_commit(path: Path) -> str:
    """The most recent commit that touched `path`, recorded as a run's census provenance."""
    return _git("log", "-n", "1", "--format=%H", "--", str(path))


def _tree_is_dirty() -> bool:
    return bool(_git("status", "--porcelain", "--untracked-files=no"))


def _git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        reason = f"git {' '.join(args)} failed: run from a git checkout"
        raise Refused("Git unavailable.", [reason]) from error
    return completed.stdout.strip()


REPOSITORY_TREE = WorkingTree(
    declared_flips_path=DECLARED_FLIPS_PATH,
    parent_commit=_parent_commit,
    is_dirty=_tree_is_dirty,
    read_tree=read_tree,
)
