from evals.baseline import Baseline, BaselineConditions, BaselineStatus
from evals.declared_flips import ActiveDeclarations
from evals.eval_session import TreeState
from evals.honeypot.session import DEFAULT_RUNS, DEFAULT_TEST_BUDGET, HoneypotSession, select_mode
from evals.model_conditions import ModelConditions
from mcp_auditor.config import Settings
from tests.unit.evals.support import honeypot_baselines


def a_baseline_at_ci_conditions(status: BaselineStatus = BaselineStatus.UNCONFIRMED) -> Baseline:
    """Each side of `honeypot_gate_inputs.a_ground_truth` has its one cell stable and correct."""
    return honeypot_baselines.a_baseline(
        status=status, runs=honeypot_baselines.all_correct_runs()
    ).model_copy(update={"conditions": ci_conditions()})


def ci_conditions(test_budget: int = DEFAULT_TEST_BUDGET) -> BaselineConditions:
    return honeypot_baselines.conditions().model_copy(
        update={
            "runs": DEFAULT_RUNS,
            "budget": test_budget,
            **ModelConditions.of(Settings.model_construct()).model_dump(),
        }
    )


def a_session(
    baseline: Baseline | None = None,
    tree: TreeState | None = None,
    conditions: BaselineConditions | None = None,
    declarations: ActiveDeclarations | None = None,
) -> HoneypotSession:
    """A session recording whenever it holds a tree, as open_session builds it."""
    return HoneypotSession(
        settings=Settings.model_construct(),
        conditions=conditions or ci_conditions(),
        baseline=baseline,
        mode=select_mode(baseline, no_baseline=False),
        tree=tree,
        declarations=declarations or ActiveDeclarations(),
    )
