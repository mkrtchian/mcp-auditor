from evals.cve.detection.replay import (
    REPLAY_ATTEMPTS,
    ReplayAttemptFailure,
    ReplayOutcome,
    UncheckedReason,
)
from tests.unit.detection.support.test_detection_replay_given import PLACE_ID


def the_credit_is_struck(outcome: ReplayOutcome) -> None:
    assert {pair.place_id for pair in outcome.check.struck} == {PLACE_ID}
    _decided_with_no_failed_attempt(outcome)


def the_credit_is_left_unchecked(outcome: ReplayOutcome, failure: ReplayAttemptFailure) -> None:
    assert outcome.check.unchecked
    assert outcome.unchecked_reason is UncheckedReason.NO_ATTEMPT_DECIDED
    assert outcome.attempt_failures == (failure,) * REPLAY_ATTEMPTS


def _decided_with_no_failed_attempt(outcome: ReplayOutcome) -> None:
    assert not outcome.check.unchecked
    assert outcome.unchecked_reason is None
    assert outcome.attempt_failures == ()
