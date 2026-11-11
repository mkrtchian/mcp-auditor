"""Retest of flipped cells, with a fake audit.

Audit counts are asserted on purpose, an exception to the rule against asserting on call
sequences: stopping as soon as every cell decides is specified behavior, each audit is a
paid server run, and a loop that always spent the rule's retests would give the same
verdicts.
"""

import tests.unit.support.test_honeypot_retest_given as given
from evals.gate import CellOutcome, RetestRule

ALPHA_CELL = given.ALPHA_CELL
ALPHA_OTHER_CELL = given.ALPHA_OTHER_CELL
BETA_CELL = given.BETA_CELL


async def test_a_flip_reproduced_four_times_is_a_regression():
    audit = given.FakeAudit({"alpha": [given.a_retest(reproducing=(ALPHA_CELL,))] * 5})
    retester = given.a_retester(audit)

    settled, failures = await retester.retest_flips(given.cells_flipping(ALPHA_CELL), RetestRule())

    assert settled[ALPHA_CELL].outcome == CellOutcome.REGRESSION
    assert settled[ALPHA_CELL].retests == [True] * 4
    assert failures == []


async def test_a_flip_cleared_twice_is_not_reproduced():
    audit = given.FakeAudit({"alpha": [given.a_retest(clearing=(ALPHA_CELL,))] * 5})
    retester = given.a_retester(audit)

    settled, _ = await retester.retest_flips(given.cells_flipping(ALPHA_CELL), RetestRule())

    assert settled[ALPHA_CELL].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert settled[ALPHA_CELL].retests == [False, False]


async def test_two_flips_on_one_server_share_its_audits_until_both_decide():
    mixed = given.a_retest(reproducing=(ALPHA_CELL,), clearing=(ALPHA_OTHER_CELL,))
    audit = given.FakeAudit({"alpha": [mixed] * 5})
    retester = given.a_retester(audit)

    settled, _ = await retester.retest_flips(
        given.cells_flipping(ALPHA_CELL, ALPHA_OTHER_CELL), RetestRule()
    )

    assert settled[ALPHA_CELL].outcome == CellOutcome.REGRESSION
    assert settled[ALPHA_OTHER_CELL].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert settled[ALPHA_OTHER_CELL].retests == [False, False]
    assert audit.calls == {"alpha": 4, "beta": 0}


async def test_a_flip_on_each_server_audits_each_server_on_its_own():
    audit = given.FakeAudit(
        {
            "alpha": [given.a_retest(reproducing=(ALPHA_CELL,))] * 5,
            "beta": [given.a_retest(clearing=(BETA_CELL,))] * 5,
        }
    )
    retester = given.a_retester(audit)

    settled, _ = await retester.retest_flips(
        given.cells_flipping(ALPHA_CELL, BETA_CELL), RetestRule()
    )

    assert settled[ALPHA_CELL].outcome == CellOutcome.REGRESSION
    assert settled[BETA_CELL].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert audit.calls == {"alpha": 4, "beta": 2}


async def test_a_retest_does_not_read_the_other_server_cells_as_uncovered():
    audit = given.FakeAudit(
        {
            "alpha": [given.a_retest(clearing=(ALPHA_CELL,))] * 5,
            "beta": [given.a_retest(clearing=(BETA_CELL,))] * 5,
        }
    )
    retester = given.a_retester(audit)

    settled, _ = await retester.retest_flips(
        given.cells_flipping(ALPHA_CELL, BETA_CELL), RetestRule()
    )

    assert settled[ALPHA_CELL].retests == [False, False]
    assert settled[BETA_CELL].retests == [False, False]


async def test_two_servers_retest_side_by_side():
    audit = given.FakeAudit(
        {
            "alpha": [given.a_retest(reproducing=(ALPHA_CELL,))] * 5,
            "beta": [given.a_retest(clearing=(BETA_CELL,))] * 5,
        },
        waiting={"alpha": "beta"},
    )
    retester = given.a_retester(audit)

    settled, failures = await retester.retest_flips(
        given.cells_flipping(ALPHA_CELL, BETA_CELL), RetestRule()
    )

    assert settled[ALPHA_CELL].outcome == CellOutcome.REGRESSION
    assert settled[BETA_CELL].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert failures == []


async def test_failed_retests_are_reported_in_server_order_whatever_fails_first():
    audit = given.FakeAudit({}, failing=frozenset({"alpha", "beta"}), waiting={"alpha": "beta"})
    retester = given.a_retester(audit)

    _, failures = await retester.retest_flips(
        given.cells_flipping(ALPHA_CELL, BETA_CELL), RetestRule()
    )

    assert failures == ["a retest of alpha failed", "a retest of beta failed"]


async def test_a_failed_retest_of_one_server_lets_the_other_settle():
    audit = given.FakeAudit(
        {"beta": [given.a_retest(clearing=(BETA_CELL,))] * 5}, failing=frozenset({"alpha"})
    )
    retester = given.a_retester(audit)

    settled, failures = await retester.retest_flips(
        given.cells_flipping(ALPHA_CELL, BETA_CELL), RetestRule()
    )

    assert settled[ALPHA_CELL].outcome == CellOutcome.FLIP
    assert settled[BETA_CELL].outcome == CellOutcome.FLIP_NOT_REPRODUCED
    assert failures == ["a retest of alpha failed"]


async def test_a_failed_retest_leaves_the_flip_and_is_reported():
    audit = given.FakeAudit({}, failing=frozenset({"alpha"}))
    retester = given.a_retester(audit)

    settled, failures = await retester.retest_flips(given.cells_flipping(ALPHA_CELL), RetestRule())

    assert settled[ALPHA_CELL].outcome == CellOutcome.FLIP
    assert failures == ["a retest of alpha failed"]


async def test_a_failed_retest_warns_its_traceback_apart_from_the_progress():
    audit = given.FakeAudit({}, failing=frozenset({"alpha"}))
    messages: list[str] = []
    warned: list[str] = []
    retester = given.a_retester(audit, announced=messages, warned=warned)

    await retester.retest_flips(given.cells_flipping(ALPHA_CELL), RetestRule())

    assert any("Traceback" in warning for warning in warned)
    assert not any("Traceback" in message for message in messages)
    assert any("retest of alpha failed" in message for message in messages)


async def test_each_retest_attempt_announces_one_progress_line():
    audit = given.FakeAudit({"alpha": [given.a_retest(reproducing=(ALPHA_CELL,))] * 5})
    messages: list[str] = []
    retester = given.a_retester(audit, announced=messages)

    await retester.retest_flips(given.cells_flipping(ALPHA_CELL), RetestRule())

    assert len(messages) == 4


async def test_no_flip_means_no_audit():
    audit = given.FakeAudit({})
    retester = given.a_retester(audit)
    cells = given.cells_flipping()

    settled, failures = await retester.retest_flips(cells, RetestRule())

    assert settled == cells
    assert failures == []
    assert audit.calls == {"alpha": 0, "beta": 0}
