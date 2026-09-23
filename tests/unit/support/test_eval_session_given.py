import tests.unit.support.test_eval_baseline_given as baseline_given
from evals.baseline import Baseline, BaselineConditions, BaselineStatus
from evals.eval_session import (
    DEFAULT_BUDGET,
    DEFAULT_RUNS,
    EvalSession,
    TreeState,
    select_mode,
)
from mcp_auditor.config import Settings

HEAD = baseline_given.RECORDED_COMMIT


def ci_conditions(budget: int = DEFAULT_BUDGET) -> BaselineConditions:
    defaults = Settings.model_construct()
    return baseline_given.conditions().model_copy(
        update={
            "runs": DEFAULT_RUNS,
            "budget": budget,
            "provider": defaults.provider,
            "model": defaults.resolve_model(),
            "judge_model": defaults.resolve_judge_model(),
        }
    )


def a_baseline_at_ci_conditions(status: BaselineStatus = BaselineStatus.EXPLORATORY) -> Baseline:
    return baseline_given.a_baseline(status=status).model_copy(
        update={"conditions": ci_conditions()}
    )


def a_session(
    baseline: Baseline | None = None,
    tree: TreeState | None = None,
    conditions: BaselineConditions | None = None,
) -> EvalSession:
    """A session recording whenever it holds a tree, as open_session builds it."""
    return EvalSession(
        settings=Settings.model_construct(),
        conditions=conditions or ci_conditions(),
        baseline=baseline,
        mode=select_mode(baseline, ungated=False),
        record=tree is not None,
        tree=tree,
    )


def a_clean_tree(commit: str = HEAD) -> TreeState:
    return TreeState(commit=commit, dirty=False)
