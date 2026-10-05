from evals.declared_flips import ActiveDeclarations
from evals.gate import CellComparison, Observation
from evals.gate_verdict import GateMode, GateVerdict
from evals.judge_fixture import CaseLabel, JudgeFixture
from evals.judge_gate import JudgeGateResult
from evals.judge_session import JudgeSessionResult
from mcp_auditor.domain.models import AuditCategory
from tests.unit.support.test_judge_baseline_given import a_baseline, conditions
from tests.unit.support.test_judge_fixture_given import a_case, a_fixture

FLIPPED_CASE = a_case(
    label=CaseLabel.PASS,
    tool_name="delete_record",
    category=AuditCategory.INPUT_VALIDATION,
    description="Negative record id",
).model_copy(update={"origin": "cell delete_record/input_validation"})
NEW_CASE = a_case(
    label=CaseLabel.FAIL,
    tool_name="read_file",
    category=AuditCategory.INFO_LEAKAGE,
    description="Path traversal leaks /etc/passwd",
).model_copy(update={"origin": "cve CVE-2025-53355"})
STEADY_CASE = a_case(label=CaseLabel.PASS, description="Empty user_id")
PARTIAL_CASE = a_case(
    label=CaseLabel.FAIL,
    tool_name="update_record",
    category=AuditCategory.INPUT_VALIDATION,
    description="SQL fragment in record id accepted",
).model_copy(update={"origin": "cell update_record/input_validation"})
UNSPECIFIED_CASE = a_case(
    label=CaseLabel.UNSPECIFIED,
    tool_name="update_record",
    category=AuditCategory.ERROR_HANDLING,
    description="Stack trace on unknown field",
).model_copy(update={"origin": "cell update_record/error_handling"})

FLIPPED_ID, NEW_ID, STEADY_ID = FLIPPED_CASE.id, NEW_CASE.id, STEADY_CASE.id
PARTIAL_ID, UNSPECIFIED_ID = PARTIAL_CASE.id, UNSPECIFIED_CASE.id

P, F, U = Observation.PASS, Observation.FAIL, Observation.UNCOVERED


def a_judge_fixture() -> JudgeFixture:
    return a_fixture(FLIPPED_CASE, NEW_CASE, STEADY_CASE, PARTIAL_CASE, UNSPECIFIED_CASE)


def a_result(
    cases: dict[str, CellComparison],
    replay_observations: dict[str, list[Observation]] | None = None,
    with_baseline: bool = True,
) -> JudgeSessionResult:
    """Baseline on an older draw that lacks NEW_CASE, run 2 judging FLIPPED_CASE FAIL, runs 1
    and 3 judging PARTIAL_CASE and UNSPECIFIED_CASE FAIL after a baseline judging them PASS."""
    baseline_runs = [
        {FLIPPED_ID: P, STEADY_ID: P, PARTIAL_ID: P, UNSPECIFIED_ID: P} for _ in range(3)
    ]
    runs = [
        {FLIPPED_ID: flipped, NEW_ID: F, STEADY_ID: P, PARTIAL_ID: other, UNSPECIFIED_ID: other}
        for flipped, other in ((P, F), (F, P), (P, F))
    ]
    return JudgeSessionResult(
        conditions=conditions(),
        runs=runs,
        gate=_a_gate(cases),
        baseline=a_baseline(runs=baseline_runs) if with_baseline else None,
        replay_observations=replay_observations or {},
        declarations=ActiveDeclarations(),
        written=None,
        recording_refused=[],
        exit_code=0,
    )


def _a_gate(cases: dict[str, CellComparison]) -> JudgeGateResult:
    return JudgeGateResult(
        mode=GateMode.PAIRED,
        verdict=GateVerdict.GREEN,
        reasons=[],
        baseline_status=None,
        cases=cases,
        floor_breaches=[],
    )
