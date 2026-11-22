import json
from pathlib import Path
from typing import NoReturn

from evals.declared_flips import DeclaredFlip, DeclaredFlipsFile, Instrument
from evals.eval_session import (
    DEFAULT_BUDGET,
    DEFAULT_CONCURRENCY,
    DEFAULT_RUNS,
    HoneypotOptions,
    TreeState,
    WorkingTree,
)
from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import EvalVerdict
from tests.unit.evals.support import honeypot_gate_inputs
from tests.unit.evals.support.honeypot_baselines import RECORDED_COMMIT

HEAD = RECORDED_COMMIT
PARENT = "0123456789abcdef0123456789abcdef01234567"
A_GATED_CELL = "delete_record/injection"

LABELS: GroundTruth = honeypot_gate_inputs.a_ground_truth()
LABELS_WITH_THE_FLAW_RELABELED_PASS: GroundTruth = {
    **LABELS,
    honeypot_gate_inputs.VULNERABLE_CELL: EvalVerdict.PASS,
}
LABELS_WITH_THE_SAFE_CELL_RELABELED_FAIL: GroundTruth = {
    **LABELS,
    honeypot_gate_inputs.SAFE_CELL: EvalVerdict.FAIL,
}


def options() -> HoneypotOptions:
    return HoneypotOptions(
        runs=DEFAULT_RUNS,
        budget=DEFAULT_BUDGET,
        report="",
        record_baseline=False,
        no_baseline=False,
        concurrency=DEFAULT_CONCURRENCY,
    )


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


def a_working_tree(declared_flips_path: Path, dirty: bool = False) -> WorkingTree:
    """A tree whose parent is `PARENT`, with no committed baseline beside the declarations."""
    return WorkingTree(
        baseline_path=declared_flips_path.parent / "no_baseline.json",
        declared_flips_path=declared_flips_path,
        parent_commit=lambda: PARENT,
        is_dirty=lambda: dirty,
        read_tree=a_git_that_must_not_run,
    )


def a_git_that_must_not_run(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError("git was read")


def a_working_tree_that_must_not_read_git(declared_flips_path: Path) -> WorkingTree:
    return WorkingTree(
        baseline_path=declared_flips_path.parent / "no_baseline.json",
        declared_flips_path=declared_flips_path,
        parent_commit=a_git_that_must_not_run,
        is_dirty=a_git_that_must_not_run,
        read_tree=a_git_that_must_not_run,
    )
