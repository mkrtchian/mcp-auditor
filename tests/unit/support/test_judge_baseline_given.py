from evals.baseline import BaselineStatus, RecordingRef
from evals.gate import Observation, ProtectedCells, ReplayRule, protected_cells
from evals.judge_baseline import JudgeBaseline, JudgeConditions
from evals.judge_fixture import CaseLabel, JudgeFixture, ground_truth_of, inputs_fingerprint
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import EvalVerdict
from tests.unit.support.test_judge_fixture_given import a_case, a_fixture

RECORDED_COMMIT = "0123abc"

FAIL_CASE = a_case(label=CaseLabel.FAIL, description="Path traversal leaks /etc/passwd")
PASS_CASE = a_case(label=CaseLabel.PASS, description="Negative user_id")
OTHER_PASS_CASE = a_case(label=CaseLabel.PASS, description="Empty user_id")
UNSPECIFIED_CASE = a_case(label=CaseLabel.UNSPECIFIED, description="Oversized user_id")

FAIL_ID, PASS_ID, OTHER_PASS_ID, UNSPECIFIED_ID = (
    FAIL_CASE.id,
    PASS_CASE.id,
    OTHER_PASS_CASE.id,
    UNSPECIFIED_CASE.id,
)

ObservationRuns = list[dict[str, Observation]]

_CORRECT = {
    FAIL_ID: Observation.FAIL,
    PASS_ID: Observation.PASS,
    OTHER_PASS_ID: Observation.PASS,
    UNSPECIFIED_ID: Observation.PASS,
}


def a_judge_fixture() -> JudgeFixture:
    """One FAIL case, two PASS cases and one unspecified: FAIL cases are a minority."""
    return a_fixture(FAIL_CASE, PASS_CASE, OTHER_PASS_CASE, UNSPECIFIED_CASE)


def a_ground_truth() -> dict[str, EvalVerdict]:
    return ground_truth_of(a_judge_fixture())


def correct_runs(count: int = 3) -> ObservationRuns:
    return [dict(_CORRECT) for _ in range(count)]


def runs_where(case_id: str, *observations: Observation) -> ObservationRuns:
    """One run per observation, `case_id` observed as given, every other case correct."""
    return [{**_CORRECT, case_id: observation} for observation in observations]


def runs_failing_every_case(count: int = 3) -> ObservationRuns:
    return [dict.fromkeys(_CORRECT, Observation.FAIL) for _ in range(count)]


def conditions(runs: int = 3, fixture: JudgeFixture | None = None) -> JudgeConditions:
    defaults = Settings.model_construct()
    judge_model = defaults.resolve_judge_model()
    return JudgeConditions(
        runs=runs,
        provider=defaults.provider,
        judge_model=judge_model,
        judge_reasoning=defaults.resolve_reasoning(judge_model),
        inputs_fingerprint=inputs_fingerprint(fixture or a_judge_fixture()),
    )


def a_baseline(
    status: BaselineStatus = BaselineStatus.CONFIRMED,
    runs: ObservationRuns | None = None,
    confirms: RecordingRef | None = None,
    commit: str = RECORDED_COMMIT,
) -> JudgeBaseline:
    runs = correct_runs() if runs is None else runs
    return JudgeBaseline(
        status=status,
        conditions=conditions(),
        replay_rule=ReplayRule(),
        commit=commit,
        recorded_at="2026-09-28T12:00:00+00:00",
        runs=runs,
        confirms=confirms,
        protected=_protected_of(runs),
    )


def _protected_of(runs: ObservationRuns) -> ProtectedCells:
    if not runs:
        return ProtectedCells(
            fail_stable_correct=0, fail_total=0, pass_stable_correct=0, pass_total=0, unstable=0
        )
    return protected_cells(runs, a_ground_truth())
