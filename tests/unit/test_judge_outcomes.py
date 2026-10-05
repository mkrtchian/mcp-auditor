import tests.unit.support.test_judge_outcomes_given as given
from evals.gate import CellComparison, CellOutcome, FlipCause
from evals.judge_fixture import CaseLabel
from evals.judge_outcomes import JudgeOutcomeRow, case_outcomes, judge_outcome_rows

F, P, U = given.F, given.P, given.U


def test_rows_list_only_the_cases_that_left_unchanged():
    result = given.a_result(
        {
            given.FLIPPED_ID: CellComparison(
                outcome=CellOutcome.FLIP_NOT_REPRODUCED,
                cause=FlipCause.WRONG_VERDICT,
                replays=[True, False, False],
            ),
            given.STEADY_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
        },
        replay_observations={given.FLIPPED_ID: [F, P, U]},
    )

    rows = judge_outcome_rows(result, given.a_judge_fixture())

    assert rows == [
        JudgeOutcomeRow(
            outcome=CellOutcome.FLIP_NOT_REPRODUCED,
            case=given.FLIPPED_ID,
            origin="cell delete_record/input_validation",
            target="delete_record/input_validation",
            label=CaseLabel.PASS,
            baseline="PPP",
            run="PFP",
            replays="FP-",
            cause="wrong_verdict",
        )
    ]


def test_a_case_with_no_replay_and_no_cause_shows_dashes():
    result = given.a_result({given.FLIPPED_ID: CellComparison(outcome=CellOutcome.FLIP)})

    [row] = judge_outcome_rows(result, given.a_judge_fixture())

    assert (row.replays, row.cause) == ("-", "-")


def test_a_case_the_baseline_lacks_reads_as_no_verdict():
    result = given.a_result({given.NEW_ID: CellComparison(outcome=CellOutcome.NOT_RECORDED)})

    [row] = judge_outcome_rows(result, given.a_judge_fixture())

    assert (row.target, row.label, row.baseline, row.run) == (
        "read_file/info_leakage",
        CaseLabel.FAIL,
        "---",
        "FFF",
    )


def test_rows_are_sorted_by_outcome_then_case():
    result = given.a_result(
        {
            given.STEADY_ID: CellComparison(outcome=CellOutcome.FLIP),
            given.NEW_ID: CellComparison(outcome=CellOutcome.NOT_RECORDED),
            given.FLIPPED_ID: CellComparison(outcome=CellOutcome.FLIP),
        }
    )

    rows = judge_outcome_rows(result, given.a_judge_fixture())

    assert [(row.outcome, row.case) for row in rows] == [
        *sorted([(CellOutcome.FLIP, given.FLIPPED_ID), (CellOutcome.FLIP, given.STEADY_ID)]),
        (CellOutcome.NOT_RECORDED, given.NEW_ID),
    ]


def test_no_baseline_gives_no_rows_and_no_counts():
    result = given.a_result(
        {given.FLIPPED_ID: CellComparison(outcome=CellOutcome.FLIP)}, with_baseline=False
    )

    outcomes = case_outcomes(result, given.a_judge_fixture())

    assert (outcomes.rows, outcomes.counts) == ([], {})


def test_counts_follow_the_outcome_order_and_leave_out_zeros():
    result = given.a_result(
        {
            given.NEW_ID: CellComparison(outcome=CellOutcome.NOT_RECORDED),
            given.FLIPPED_ID: CellComparison(outcome=CellOutcome.FLIP_NOT_REPRODUCED),
            given.STEADY_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
        }
    )

    counts = case_outcomes(result, given.a_judge_fixture()).counts

    assert list(counts.items()) == [
        (CellOutcome.UNCHANGED, 1),
        (CellOutcome.FLIP_NOT_REPRODUCED, 1),
        (CellOutcome.NOT_RECORDED, 1),
    ]


def test_a_case_always_wrong_in_the_baseline_and_right_in_some_runs_shows_as_partial():
    result = given.a_result(
        {
            given.STEADY_ID: CellComparison(outcome=CellOutcome.FLIP),
            given.PARTIAL_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
            given.FLIPPED_ID: CellComparison(outcome=CellOutcome.IMPROVED),
        }
    )

    rows = judge_outcome_rows(result, given.a_judge_fixture())

    assert [row.case for row in rows] == [given.FLIPPED_ID, given.PARTIAL_ID, given.STEADY_ID]
    assert rows[1] == JudgeOutcomeRow(
        outcome="partial",
        case=given.PARTIAL_ID,
        origin="cell update_record/input_validation",
        target="update_record/input_validation",
        label=CaseLabel.FAIL,
        baseline="PPP",
        run="FPF",
        replays="-",
        cause="-",
    )


def test_a_partial_case_counts_apart_from_the_unchanged_ones():
    result = given.a_result(
        {
            given.NEW_ID: CellComparison(outcome=CellOutcome.NOT_RECORDED),
            given.PARTIAL_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
            given.STEADY_ID: CellComparison(outcome=CellOutcome.UNCHANGED),
        }
    )

    counts = case_outcomes(result, given.a_judge_fixture()).counts

    assert list(counts.items()) == [("unchanged", 1), ("partial", 1), ("not_recorded", 1)]


def test_an_unspecified_case_never_shows_as_partial():
    result = given.a_result({given.UNSPECIFIED_ID: CellComparison(outcome=CellOutcome.UNCHANGED)})

    outcomes = case_outcomes(result, given.a_judge_fixture())

    assert (outcomes.rows, list(outcomes.counts.items())) == ([], [("unchanged", 1)])
