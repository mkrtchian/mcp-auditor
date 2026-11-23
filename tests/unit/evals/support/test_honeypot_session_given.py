from pathlib import Path

from evals.eval_session import WorkingTree
from evals.ground_truth import GroundTruth
from evals.honeypot.session import (
    DEFAULT_CONCURRENCY,
    DEFAULT_RUNS,
    DEFAULT_TEST_BUDGET,
    HoneypotOptions,
)
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import EvalVerdict
from tests.unit.evals.support import honeypot_gate_inputs
from tests.unit.evals.support.working_trees import PARENT, a_git_that_must_not_run

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


def options(settings: Settings | None = None) -> HoneypotOptions:
    """Settings built with model_construct, so neither the environment nor `.env` is read."""
    return HoneypotOptions(
        settings=settings or Settings.model_construct(),
        runs=DEFAULT_RUNS,
        test_budget=DEFAULT_TEST_BUDGET,
        report="",
        record_baseline=False,
        no_baseline=False,
        concurrency=DEFAULT_CONCURRENCY,
    )


def a_working_tree(declared_flips_path: Path, dirty: bool = False) -> WorkingTree:
    """A tree whose parent is `PARENT`."""
    return WorkingTree(
        declared_flips_path=declared_flips_path,
        parent_commit=lambda: PARENT,
        is_dirty=lambda: dirty,
        read_tree=a_git_that_must_not_run,
    )
