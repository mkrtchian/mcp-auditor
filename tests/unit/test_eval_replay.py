"""Replay of flipped cells, with a fake audit.

Audit counts are asserted on purpose, an exception to the rule against asserting on call
sequences: stopping as soon as every cell decides is specified behavior, each audit is a
paid server run, and a loop that always spent the rule's replays would give the same
verdicts.
"""

import tests.unit.support.test_eval_replay_given as given
from evals.gate import CellOutcome, ReplayRule
from evals.replay import Replayer

ALPHA_CELL = given.ALPHA_CELL
ALPHA_OTHER_CELL = given.ALPHA_OTHER_CELL
BETA_CELL = given.BETA_CELL


async def test_a_flip_reproduced_four_times_is_a_regression_after_four_audits():
    audit = given.FakeAudit({"alpha": [given.a_replay(reproducing=(ALPHA_CELL,))] * 5})
    replayer = Replayer(audit=audit, rule=ReplayRule(), honeypots=given.HONEYPOTS)

    settled, failures = await replayer.settle_flips(given.cells_flipping(ALPHA_CELL))

    assert settled[ALPHA_CELL].outcome == CellOutcome.REGRESSION
    assert settled[ALPHA_CELL].replays == [True] * 4
    assert audit.calls == {"alpha": 4, "beta": 0}
    assert failures == []


async def test_a_flip_cleared_twice_is_not_reproduced_after_two_audits():
    audit = given.FakeAudit({"alpha": [given.a_replay(clearing=(ALPHA_CELL,))] * 5})
    replayer = Replayer(audit=audit, rule=ReplayRule(), honeypots=given.HONEYPOTS)

    settled, _ = await replayer.settle_flips(given.cells_flipping(ALPHA_CELL))

    assert settled[ALPHA_CELL].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert settled[ALPHA_CELL].replays == [False, False]
    assert audit.calls == {"alpha": 2, "beta": 0}


async def test_two_flips_on_one_server_share_its_audits_until_both_decide():
    mixed = given.a_replay(reproducing=(ALPHA_CELL,), clearing=(ALPHA_OTHER_CELL,))
    audit = given.FakeAudit({"alpha": [mixed] * 5})
    replayer = Replayer(audit=audit, rule=ReplayRule(), honeypots=given.HONEYPOTS)

    settled, _ = await replayer.settle_flips(given.cells_flipping(ALPHA_CELL, ALPHA_OTHER_CELL))

    assert settled[ALPHA_CELL].outcome == CellOutcome.REGRESSION
    assert settled[ALPHA_OTHER_CELL].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert settled[ALPHA_OTHER_CELL].replays == [False, False]
    assert audit.calls == {"alpha": 4, "beta": 0}


async def test_a_flip_on_each_server_audits_each_server_on_its_own():
    audit = given.FakeAudit(
        {
            "alpha": [given.a_replay(reproducing=(ALPHA_CELL,))] * 5,
            "beta": [given.a_replay(clearing=(BETA_CELL,))] * 5,
        }
    )
    replayer = Replayer(audit=audit, rule=ReplayRule(), honeypots=given.HONEYPOTS)

    settled, _ = await replayer.settle_flips(given.cells_flipping(ALPHA_CELL, BETA_CELL))

    assert settled[ALPHA_CELL].outcome == CellOutcome.REGRESSION
    assert settled[BETA_CELL].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert audit.calls == {"alpha": 4, "beta": 2}


async def test_a_replay_does_not_read_the_other_server_cells_as_uncovered():
    audit = given.FakeAudit(
        {
            "alpha": [given.a_replay(clearing=(ALPHA_CELL,))] * 5,
            "beta": [given.a_replay(clearing=(BETA_CELL,))] * 5,
        }
    )
    replayer = Replayer(audit=audit, rule=ReplayRule(), honeypots=given.HONEYPOTS)

    settled, _ = await replayer.settle_flips(given.cells_flipping(ALPHA_CELL, BETA_CELL))

    assert settled[ALPHA_CELL].replays == [False, False]
    assert settled[BETA_CELL].replays == [False, False]


async def test_a_failed_replay_leaves_the_flip_and_is_reported():
    audit = given.FakeAudit({}, failing=frozenset({"alpha"}))
    replayer = Replayer(audit=audit, rule=ReplayRule(), honeypots=given.HONEYPOTS)

    settled, failures = await replayer.settle_flips(given.cells_flipping(ALPHA_CELL))

    assert settled[ALPHA_CELL].outcome == CellOutcome.FLIP
    assert failures == ["a replay of alpha failed"]


async def test_no_flip_means_no_audit():
    audit = given.FakeAudit({})
    replayer = Replayer(audit=audit, rule=ReplayRule(), honeypots=given.HONEYPOTS)
    cells = given.cells_flipping()

    settled, failures = await replayer.settle_flips(cells)

    assert settled == cells
    assert failures == []
    assert audit.calls == {"alpha": 0, "beta": 0}
