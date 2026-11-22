import tests.unit.evals.support.judge_session_results as judge_session_results
from evals.gate import CellComparison, CellOutcome, FlipCause
from evals.judge.fixture import CaseLabel
from evals.judge.outcomes import JudgeOutcomeRow, case_outcomes, judge_outcome_rows

F, P, U = judge_session_results.F, judge_session_results.P, judge_session_results.U


def test_rows_list_only_the_cases_that_left_unchanged():
    result = judge_session_results.a_result(
        {
            judge_session_results.FLIPPED_ID: CellComparison(
                outcome=CellOutcome.FLIP_NOT_REPRODUCED,
                cause=FlipCause.WRONG_VERDICT,
                retests=[True, False, False],
            ),
            judge_session_results.STEADY_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
        },
        retest_observations={judge_session_results.FLIPPED_ID: [F, P, U]},
    )

    rows = judge_outcome_rows(result, judge_session_results.a_judge_fixture())

    assert rows == [
        JudgeOutcomeRow(
            outcome=CellOutcome.FLIP_NOT_REPRODUCED,
            case=judge_session_results.FLIPPED_ID,
            origin="cell delete_record/input_validation",
            tool_category="delete_record/input_validation",
            label=CaseLabel.PASS,
            baseline="PPP",
            run="PFP",
            retests="FP-",
            cause="wrong_verdict",
        )
    ]


def test_a_case_with_no_retest_and_no_cause_shows_dashes():
    result = judge_session_results.a_result(
        {judge_session_results.FLIPPED_ID: CellComparison(outcome=CellOutcome.FLIP)}
    )

    [row] = judge_outcome_rows(result, judge_session_results.a_judge_fixture())

    assert (row.retests, row.cause) == ("-", "-")


def test_a_case_the_baseline_lacks_reads_as_no_verdict():
    result = judge_session_results.a_result(
        {judge_session_results.NEW_ID: CellComparison(outcome=CellOutcome.NOT_RECORDED)}
    )

    [row] = judge_outcome_rows(result, judge_session_results.a_judge_fixture())

    assert (row.tool_category, row.label, row.baseline, row.run) == (
        "read_file/info_leakage",
        CaseLabel.FAIL,
        "---",
        "FFF",
    )


def test_rows_are_sorted_by_outcome_then_case():
    result = judge_session_results.a_result(
        {
            judge_session_results.STEADY_ID: CellComparison(outcome=CellOutcome.FLIP),
            judge_session_results.NEW_ID: CellComparison(outcome=CellOutcome.NOT_RECORDED),
            judge_session_results.FLIPPED_ID: CellComparison(outcome=CellOutcome.FLIP),
        }
    )

    rows = judge_outcome_rows(result, judge_session_results.a_judge_fixture())

    assert [(row.outcome, row.case) for row in rows] == [
        *sorted(
            [
                (CellOutcome.FLIP, judge_session_results.FLIPPED_ID),
                (CellOutcome.FLIP, judge_session_results.STEADY_ID),
            ]
        ),
        (CellOutcome.NOT_RECORDED, judge_session_results.NEW_ID),
    ]


def test_no_baseline_gives_no_rows_and_no_counts():
    result = judge_session_results.a_result(
        {judge_session_results.FLIPPED_ID: CellComparison(outcome=CellOutcome.FLIP)},
        with_baseline=False,
    )

    outcomes = case_outcomes(result, judge_session_results.a_judge_fixture())

    assert (outcomes.rows, outcomes.counts) == ([], {})


def test_counts_follow_the_outcome_order_and_leave_out_zeros():
    result = judge_session_results.a_result(
        {
            judge_session_results.NEW_ID: CellComparison(outcome=CellOutcome.NOT_RECORDED),
            judge_session_results.FLIPPED_ID: CellComparison(
                outcome=CellOutcome.FLIP_NOT_REPRODUCED
            ),
            judge_session_results.STEADY_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
        }
    )

    counts = case_outcomes(result, judge_session_results.a_judge_fixture()).counts

    assert list(counts.items()) == [
        (CellOutcome.UNCHANGED, 1),
        (CellOutcome.FLIP_NOT_REPRODUCED, 1),
        (CellOutcome.NOT_RECORDED, 1),
    ]


def test_a_case_always_wrong_in_the_baseline_and_right_in_some_runs_shows_as_partial():
    result = judge_session_results.a_result(
        {
            judge_session_results.STEADY_ID: CellComparison(outcome=CellOutcome.FLIP),
            judge_session_results.PARTIAL_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
            judge_session_results.FLIPPED_ID: CellComparison(outcome=CellOutcome.IMPROVED),
        }
    )

    rows = judge_outcome_rows(result, judge_session_results.a_judge_fixture())

    assert [row.case for row in rows] == [
        judge_session_results.FLIPPED_ID,
        judge_session_results.PARTIAL_ID,
        judge_session_results.STEADY_ID,
    ]
    assert rows[1] == JudgeOutcomeRow(
        outcome="partial",
        case=judge_session_results.PARTIAL_ID,
        origin="cell update_record/input_validation",
        tool_category="update_record/input_validation",
        label=CaseLabel.FAIL,
        baseline="PPP",
        run="FPF",
        retests="-",
        cause="-",
    )


def test_a_partial_case_counts_apart_from_the_unchanged_ones():
    result = judge_session_results.a_result(
        {
            judge_session_results.NEW_ID: CellComparison(outcome=CellOutcome.NOT_RECORDED),
            judge_session_results.PARTIAL_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
            judge_session_results.STEADY_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
        }
    )

    counts = case_outcomes(result, judge_session_results.a_judge_fixture()).counts

    assert list(counts.items()) == [("unchanged", 1), ("partial", 1), ("not_recorded", 1)]


def test_an_unspecified_case_never_shows_as_partial():
    result = judge_session_results.a_result(
        {judge_session_results.UNSPECIFIED_ID: CellComparison(outcome=CellOutcome.UNCHANGED)}
    )

    outcomes = case_outcomes(result, judge_session_results.a_judge_fixture())

    assert (outcomes.rows, list(outcomes.counts.items())) == ([], [("unchanged", 1)])
