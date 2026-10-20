import json
from pathlib import Path
from typing import NoReturn

import tests.unit.support.test_eval_baseline_given as baseline_given
from evals.baseline import Baseline, BaselineConditions, BaselineStatus
from evals.declared_flips import ActiveDeclarations, DeclaredFlip, DeclaredFlipsFile, Suite
from evals.eval_session import (
    DEFAULT_BUDGET,
    DEFAULT_CONCURRENCY,
    DEFAULT_RUNS,
    EvalOptions,
    EvalSession,
    TreeState,
    WorkingTree,
    select_mode,
)
from evals.ground_truth import GroundTruth
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import EvalVerdict

HEAD = baseline_given.RECORDED_COMMIT
PARENT = "0123456789abcdef0123456789abcdef01234567"
A_GATED_CELL = "delete_record/injection"

LABELS: GroundTruth = baseline_given.a_ground_truth()
LABELS_WITH_THE_FLAW_RELABELED_PASS: GroundTruth = {
    **LABELS,
    baseline_given.VULNERABLE_CELL: EvalVerdict.PASS,
}
LABELS_WITH_THE_SAFE_CELL_RELABELED_FAIL: GroundTruth = {
    **LABELS,
    baseline_given.SAFE_CELL: EvalVerdict.FAIL,
}


def ci_conditions(budget: int = DEFAULT_BUDGET) -> BaselineConditions:
    defaults = Settings.model_construct()
    return baseline_given.conditions().model_copy(
        update={
            "runs": DEFAULT_RUNS,
            "budget": budget,
            "provider": defaults.provider,
            "model": defaults.resolve_model(),
            "judge_model": defaults.resolve_judge_model(),
            "reasoning": defaults.resolve_reasoning(defaults.resolve_model()),
            "judge_reasoning": defaults.resolve_reasoning(defaults.resolve_judge_model()),
        }
    )


def options() -> EvalOptions:
    return EvalOptions(
        runs=DEFAULT_RUNS,
        budget=DEFAULT_BUDGET,
        report="",
        record_baseline=False,
        ungated=False,
        concurrency=DEFAULT_CONCURRENCY,
    )


def a_baseline_at_ci_conditions(status: BaselineStatus = BaselineStatus.EXPLORATORY) -> Baseline:
    """Each side of `LABELS` has its one cell stable and correct."""
    return baseline_given.a_baseline(
        status=status, runs=baseline_given.all_correct_runs()
    ).model_copy(update={"conditions": ci_conditions()})


def a_session(
    baseline: Baseline | None = None,
    tree: TreeState | None = None,
    conditions: BaselineConditions | None = None,
    declarations: ActiveDeclarations | None = None,
) -> EvalSession:
    """A session recording whenever it holds a tree, as open_session builds it."""
    return EvalSession(
        settings=Settings.model_construct(),
        conditions=conditions or ci_conditions(),
        baseline=baseline,
        mode=select_mode(baseline, ungated=False),
        tree=tree,
        declarations=declarations or ActiveDeclarations(),
    )


def a_clean_tree(commit: str = HEAD) -> TreeState:
    return TreeState(commit=commit, dirty=False)


def a_git_that_must_not_run(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError("git was read")


def a_declaration_file(tmp_path: Path, *keys: str) -> Path:
    """Entries declared by a commit whose parent is `PARENT`."""
    entries = [
        DeclaredFlip(
            suite=Suite.HONEYPOT,
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


def a_working_tree_that_must_not_read_git(declared_flips_path: Path) -> WorkingTree:
    return WorkingTree(
        baseline_path=declared_flips_path.parent / "no_baseline.json",
        declared_flips_path=declared_flips_path,
        parent_commit=a_git_that_must_not_run,
        is_dirty=a_git_that_must_not_run,
        read_tree=a_git_that_must_not_run,
    )
