import tests.integration.support.test_cve_replay_given as given
from evals.cve_grammar import CreditCheck


def the_credit_is_kept(check: CreditCheck) -> None:
    assert check.struck == frozenset()
    assert not check.unchecked


def the_flaw_credit_is_struck(check: CreditCheck) -> None:
    assert not check.unchecked
    assert {pair.place_id for pair in check.struck} == {given.FLAW_ID}


def the_credit_is_left_unchecked(check: CreditCheck) -> None:
    assert check.unchecked
    assert check.struck == frozenset()
