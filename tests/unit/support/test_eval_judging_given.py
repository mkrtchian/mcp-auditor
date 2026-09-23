from evals.baseline import Baseline, BaselineStatus
from evals.gate import Cell, cell_key, observe
from evals.honeypots import HONEYPOTS, MERGED_GROUND_TRUTH
from evals.judging import RunsOutcome
from evals.metrics import VerdictMap, build_run_detail
from evals.replay import Replayer
from mcp_auditor.domain.models import AuditReport, EvalVerdict, TokenUsage
from tests.unit.support.test_eval_replay_given import FakeAudit, a_replay
from tests.unit.support.test_eval_session_given import a_baseline_at_ci_conditions, a_session

__all__ = ["a_session"]

FLIPPED_HONEYPOT = HONEYPOTS[0]
FLIPPED_CELL: Cell = next(
    cell for cell, verdict in FLIPPED_HONEYPOT.ground_truth.items() if verdict == EvalVerdict.FAIL
)


def correct_runs(completed: int = 3) -> RunsOutcome:
    return an_outcome([dict(MERGED_GROUND_TRUTH) for _ in range(completed)])


def runs_missing_the_flipped_cell(completed: int = 3) -> RunsOutcome:
    missing: VerdictMap = {**MERGED_GROUND_TRUTH, FLIPPED_CELL: EvalVerdict.PASS}
    return an_outcome([dict(missing) for _ in range(completed)])


def an_outcome(verdict_maps: list[VerdictMap]) -> RunsOutcome:
    report = AuditReport(target="evals", tool_reports=[], token_usage=TokenUsage())
    return RunsOutcome(
        details=[
            build_run_detail(index, verdicts, report, MERGED_GROUND_TRUTH)
            for index, verdicts in enumerate(verdict_maps)
        ],
        verdict_maps=verdict_maps,
        audits=[(index, report) for index in range(len(verdict_maps))],
    )


def a_baseline_all_correct(status: BaselineStatus) -> Baseline:
    """Every merged ground truth cell observed correct in each run: all stable correct."""
    observed = observe(dict(MERGED_GROUND_TRUTH), MERGED_GROUND_TRUTH)
    run = {cell_key(cell): observation for cell, observation in observed.items()}
    return a_baseline_at_ci_conditions(status=status).model_copy(
        update={"runs": [dict(run) for _ in range(3)]}
    )


def an_audit_reproducing_the_flip() -> FakeAudit:
    replay = a_replay(reproducing=(FLIPPED_CELL,))
    return FakeAudit({FLIPPED_HONEYPOT.name: [replay] * 5}, honeypots=HONEYPOTS)


def a_crashing_audit() -> FakeAudit:
    return FakeAudit({}, failing=frozenset({FLIPPED_HONEYPOT.name}), honeypots=HONEYPOTS)


def a_replayer(audit: FakeAudit) -> Replayer:
    return Replayer(audit=audit, honeypots=HONEYPOTS, announce=lambda _: None)


def no_audit_ran(audit: FakeAudit) -> bool:
    return all(count == 0 for count in audit.calls.values())
