from evals.baseline import Baseline, BaselineConditions, BaselineStatus
from evals.declared_flips import ActiveDeclarations
from evals.eval_session import DEFAULT_BUDGET, DEFAULT_RUNS, HoneypotSession, TreeState, select_mode
from mcp_auditor.config import Settings
from tests.unit.evals.support import honeypot_baselines


def a_baseline_at_ci_conditions(status: BaselineStatus = BaselineStatus.UNCONFIRMED) -> Baseline:
    """Each side of `honeypot_gate_inputs.a_ground_truth` has its one cell stable and correct."""
    return honeypot_baselines.a_baseline(
        status=status, runs=honeypot_baselines.all_correct_runs()
    ).model_copy(update={"conditions": ci_conditions()})


def ci_conditions(budget: int = DEFAULT_BUDGET) -> BaselineConditions:
    defaults = Settings.model_construct()
    return honeypot_baselines.conditions().model_copy(
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
