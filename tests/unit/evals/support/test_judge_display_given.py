import tests.unit.evals.support.judge_session_results as judge_session_results
from evals.gate import CellComparison, CellOutcome, FlipCause
from evals.judge.outcomes import CaseOutcomes, case_outcomes
from evals.judge.report import JudgeReport, JudgeRunFacts, build_judge_report
from evals.judge.session_model import JudgeSessionResult

FLIPPED_ID = judge_session_results.FLIPPED_ID


def a_report(throttled_requests: int = 0, concurrency: int = 30) -> JudgeReport:
    facts = JudgeRunFacts("2026-11-23T10:00:00+00:00", throttled_requests, concurrency)
    return build_judge_report(
        a_result_with_a_flip_not_reproduced(), judge_session_results.a_judge_fixture(), facts
    )


def a_result_with_a_flip_not_reproduced() -> JudgeSessionResult:
    return judge_session_results.a_result(
        {
            FLIPPED_ID: CellComparison(
                outcome=CellOutcome.FLIP_NOT_REPRODUCED,
                cause=FlipCause.WRONG_VERDICT,
                retests=[True, False, False],
            ),
            judge_session_results.STEADY_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
        },
        retest_observations={
            FLIPPED_ID: [judge_session_results.F, judge_session_results.P, judge_session_results.P]
        },
    )


def a_result_with_a_partial_case() -> JudgeSessionResult:
    return judge_session_results.a_result(
        {judge_session_results.PARTIAL_ID: CellComparison(outcome=CellOutcome.UNCHANGED)}
    )


def the_outcomes_of(result: JudgeSessionResult) -> CaseOutcomes:
    return case_outcomes(result, judge_session_results.a_judge_fixture())
