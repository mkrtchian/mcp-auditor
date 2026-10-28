import tests.integration.support.test_cve_replay_given as given
from evals.cve_replay import ReplayAttemptFailure, ReplayOutcome, UncheckedReason


def the_credit_is_kept(outcome: ReplayOutcome) -> None:
    assert outcome.check.struck == frozenset()
    _decided_with_no_failed_attempt(outcome)


def the_flaw_credit_is_struck(outcome: ReplayOutcome) -> None:
    assert {pair.place_id for pair in outcome.check.struck} == {given.FLAW_ID}
    _decided_with_no_failed_attempt(outcome)


def the_credit_is_left_unchecked(
    outcome: ReplayOutcome, failures: tuple[ReplayAttemptFailure, ...]
) -> None:
    assert outcome.check.unchecked
    assert outcome.check.struck == frozenset()
    assert outcome.unchecked_reason is UncheckedReason.NO_ATTEMPT_DECIDED
    assert outcome.attempt_failures == failures


def _decided_with_no_failed_attempt(outcome: ReplayOutcome) -> None:
    assert not outcome.check.unchecked
    assert outcome.unchecked_reason is None
    assert outcome.attempt_failures == ()
