import dataclasses

import tests.unit.evals.support.judge_session_results as judge_session_results
from evals.gate import CellComparison, CellOutcome
from evals.judge.report import JudgeReport, JudgeRunFacts, build_judge_report
from evals.judge.session_model import JudgeSessionResult

_FACTS = JudgeRunFacts(timestamp="2026-11-23T10:00:00+00:00", throttled_requests=4, concurrency=30)


def a_report() -> JudgeReport:
    return _report_of(_a_result())


def a_report_with_a_case_uncovered_in_the_first_run() -> JudgeReport:
    """The first run judges FLIPPED_CASE and STEADY_CASE PASS and PARTIAL_CASE FAIL, as
    labeled, and gives no verdict on NEW_CASE."""
    result = _a_result()
    first_run = result.runs[0] | {judge_session_results.NEW_ID: judge_session_results.U}
    return _report_of(dataclasses.replace(result, runs=[first_run, *result.runs[1:]]))


def _a_result() -> JudgeSessionResult:
    return judge_session_results.a_result(
        {judge_session_results.STEADY_ID: CellComparison(outcome=CellOutcome.UNCHANGED)}
    )


def _report_of(result: JudgeSessionResult) -> JudgeReport:
    return build_judge_report(result, judge_session_results.a_judge_fixture(), _FACTS)
