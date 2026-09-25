"""The gate's judging of completed runs, with a fake replay audit.

Audit counts are asserted on purpose, an exception to the rule against asserting on call
sequences: each audit is a paid server run, and replaying in a mode or state that forbids it
would give the same verdicts.
"""

import tests.unit.support.test_eval_judging_given as given
from evals.baseline import BaselineStatus
from evals.gate import LEGACY_THRESHOLDS, CellOutcome, cell_key
from evals.gate_verdict import GateMode, GateVerdict
from evals.judging import judge_runs

FLIPPED_KEY = cell_key(given.FLIPPED_CELL)


async def test_without_baseline_the_legacy_thresholds_judge_and_nothing_replays():
    audit = given.an_audit_reproducing_the_flip()

    result = await judge_runs(given.a_session(), given.correct_runs(), given.a_replayer(audit))

    assert result.mode == GateMode.LEGACY_THRESHOLDS
    assert result.thresholds == LEGACY_THRESHOLDS
    # The minimal audit reports cover no category, so distribution coverage misses its threshold.
    assert result.verdict == GateVerdict.RED
    assert any("distribution_coverage" in reason for reason in result.reasons)
    assert result.cells == {}
    assert result.deltas == {}
    assert given.no_audit_ran(audit)


async def test_without_baseline_missing_runs_are_not_comparable():
    audit = given.an_audit_reproducing_the_flip()

    result = await judge_runs(
        given.a_session(), given.correct_runs(completed=2), given.a_replayer(audit)
    )

    assert result.verdict == GateVerdict.NOT_COMPARABLE
    assert result.reasons == ["2 of 3 runs completed"]


async def test_a_confirmed_baseline_replays_a_flip_into_a_regression():
    session = given.a_session(baseline=given.a_baseline_all_correct(BaselineStatus.CONFIRMED))
    audit = given.an_audit_reproducing_the_flip()

    result = await judge_runs(
        session, given.runs_missing_the_flipped_cell(), given.a_replayer(audit)
    )

    assert result.cells[FLIPPED_KEY].outcome == CellOutcome.REGRESSION
    assert result.verdict == GateVerdict.RED
    assert f"regression on {FLIPPED_KEY}" in result.reasons
    assert result.deltas
    assert audit.calls[given.FLIPPED_HONEYPOT.name] == 4


async def test_a_confirmed_baseline_with_missing_runs_replays_nothing():
    session = given.a_session(baseline=given.a_baseline_all_correct(BaselineStatus.CONFIRMED))
    audit = given.an_audit_reproducing_the_flip()

    result = await judge_runs(
        session, given.runs_missing_the_flipped_cell(completed=2), given.a_replayer(audit)
    )

    assert result.verdict == GateVerdict.NOT_COMPARABLE
    assert given.no_audit_ran(audit)


async def test_an_exploratory_baseline_leaves_a_flip_unreplayed():
    session = given.a_session(baseline=given.a_baseline_all_correct(BaselineStatus.EXPLORATORY))
    audit = given.an_audit_reproducing_the_flip()

    result = await judge_runs(
        session, given.runs_missing_the_flipped_cell(), given.a_replayer(audit)
    )

    assert result.mode == GateMode.FLOORS_ONLY
    assert result.cells[FLIPPED_KEY].outcome == CellOutcome.FLIP
    assert given.no_audit_ran(audit)


async def test_a_crashing_replay_makes_the_run_not_comparable():
    session = given.a_session(baseline=given.a_baseline_all_correct(BaselineStatus.CONFIRMED))

    result = await judge_runs(
        session, given.runs_missing_the_flipped_cell(), given.a_replayer(given.a_crashing_audit())
    )

    assert result.verdict == GateVerdict.NOT_COMPARABLE
    assert result.reasons == [f"a replay of {given.FLIPPED_HONEYPOT.name} failed"]


async def test_a_cell_the_baseline_did_not_record_is_neither_gated_nor_replayed():
    baseline = given.a_baseline_without_the_flipped_cell(BaselineStatus.CONFIRMED)
    audit = given.an_audit_reproducing_the_flip()

    result = await judge_runs(
        given.a_session(baseline=baseline),
        given.runs_missing_the_flipped_cell(),
        given.a_replayer(audit),
    )

    assert result.cells[FLIPPED_KEY].outcome == CellOutcome.NOT_RECORDED
    assert not any("regression on" in reason for reason in result.reasons)
    assert given.no_audit_ran(audit)


def test_runs_outcome_completed_all_when_every_requested_run_has_details():
    assert given.correct_runs(completed=3).completed_all(3)
    assert not given.correct_runs(completed=2).completed_all(3)
