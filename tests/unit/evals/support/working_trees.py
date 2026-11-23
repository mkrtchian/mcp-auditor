import json
from pathlib import Path
from typing import NoReturn

from evals.declared_flips import DeclaredFlip, DeclaredFlipsFile, Instrument
from evals.eval_session import TreeState, WorkingTree
from tests.unit.evals.support.honeypot_baselines import RECORDED_COMMIT

HEAD = RECORDED_COMMIT
PARENT = "0123456789abcdef0123456789abcdef01234567"


def a_clean_tree(commit: str = HEAD) -> TreeState:
    return TreeState(commit=commit, dirty=False)


def a_declaration_file(tmp_path: Path, *keys: str) -> Path:
    """Entries declared by a commit whose parent is `PARENT`."""
    entries = [
        DeclaredFlip(
            instrument=Instrument.HONEYPOT,
            key=key,
            mechanism="the generator no longer probes this category",
            base=PARENT,
            runs_seen=[],
        )
        for key in keys
    ]
    path = tmp_path / "declared_flips.json"
    path.write_text(json.dumps(DeclaredFlipsFile(entries=entries).model_dump(mode="json")))
    return path


def a_working_tree_that_must_not_read_git(declared_flips_path: Path) -> WorkingTree:
    return WorkingTree(
        declared_flips_path=declared_flips_path,
        parent_commit=a_git_that_must_not_run,
        is_dirty=a_git_that_must_not_run,
        read_tree=a_git_that_must_not_run,
    )


def a_git_that_must_not_run(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError("git was read")
