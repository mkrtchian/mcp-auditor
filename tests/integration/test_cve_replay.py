import pytest

import tests.integration.support.test_cve_replay_given as given
import tests.integration.support.test_cve_replay_then as then
from evals.cve_grammar import CVEStatus, grade_run
from evals.cve_replay import REPLAY_ATTEMPTS, ReplayAttemptFailure, replay_with_causes
from evals.cve_report_units import units_of

pytestmark = pytest.mark.usefixtures("docker_on_the_host")

_LOST_EVERY_TIME = (ReplayAttemptFailure.LOST_CONNECTION,) * REPLAY_ATTEMPTS


async def test_a_declared_path_strikes_the_credit():
    run = given.a_declared_run()

    outcome = await replay_with_causes(run)

    then.the_flaw_credit_is_struck(outcome)
    assert grade_run(run.run_target, units_of(run.report), outcome.check).status == CVEStatus.MISSED


async def test_the_flaw_path_keeps_the_credit():
    run = given.a_flaw_run()

    outcome = await replay_with_causes(run)

    then.the_credit_is_kept(outcome)
    status = grade_run(run.run_target, units_of(run.report), outcome.check).status
    assert status == CVEStatus.DETECTED


async def test_a_chain_second_step_reaching_the_flaw_keeps_the_credit():
    run = given.a_chain_run()

    outcome = await replay_with_causes(run)

    then.the_credit_is_kept(outcome)


async def test_an_old_nonce_in_an_argument_does_not_fool_the_replay():
    run = given.an_echoed_old_nonce_run()

    outcome = await replay_with_causes(run)

    then.the_credit_is_kept(outcome)


async def test_a_fresh_nonce_of_another_location_strikes_nothing():
    run = given.a_fresh_other_location_run()

    outcome = await replay_with_causes(run)

    assert given.FLAW_ID not in {pair.place_id for pair in outcome.check.struck}
    assert not outcome.check.unchecked
    assert outcome.unchecked_reason is None


async def test_a_complete_attempt_decides_when_only_the_patched_teardown_raises():
    run = given.a_declared_run_on_a_server_noisy_at_shutdown()

    outcome = await replay_with_causes(run)

    then.the_flaw_credit_is_struck(outcome)


async def test_a_patched_launch_that_always_fails_leaves_the_credit_unchecked():
    run = given.a_patched_launch_failure_run()

    outcome = await replay_with_causes(run)

    then.the_credit_is_left_unchecked(
        outcome, (ReplayAttemptFailure.LAUNCH_FAILED,) * REPLAY_ATTEMPTS
    )
    grade = grade_run(run.run_target, units_of(run.report), outcome.check)
    assert grade.status == CVEStatus.DETECTED
    assert grade.status_if_unchecked_missed == CVEStatus.MISSED


async def test_a_patched_server_dying_while_answering_leaves_the_credit_unchecked():
    run = given.a_server_dying_while_answering_run()

    outcome = await replay_with_causes(run)

    then.the_credit_is_left_unchecked(outcome, _LOST_EVERY_TIME)


async def test_a_patched_server_dying_after_a_call_leaves_the_credit_unchecked():
    run = given.a_server_dying_after_a_call_run()

    outcome = await replay_with_causes(run, tool_call_timeout=2)

    then.the_credit_is_left_unchecked(outcome, _LOST_EVERY_TIME)


async def test_a_detection_before_a_shared_death_is_decided_and_kept():
    run = given.a_detection_kept_when_the_patched_dies_where_the_vulnerable_did_run()

    outcome = await replay_with_causes(run)

    then.the_credit_is_kept(outcome)
    status = grade_run(run.run_target, units_of(run.report), outcome.check).status
    assert status == CVEStatus.DETECTED


async def test_a_straddling_credit_is_struck_when_the_patched_server_survives():
    run = given.a_straddling_chain_struck_despite_a_lost_connection_run()

    outcome = await replay_with_causes(run)

    then.the_flaw_credit_is_struck(outcome)


async def test_a_transient_patched_death_at_the_vulnerable_loss_is_retried_and_struck():
    run = given.a_transient_patched_death_at_the_vulnerable_loss_run()

    outcome = await replay_with_causes(run)

    then.the_flaw_credit_is_struck(outcome)


async def test_truncated_and_failed_attempts_with_no_complete_one_leave_the_run_unchecked():
    run = given.a_truncated_then_failed_attempts_run()

    outcome = await replay_with_causes(run)

    # The truncated first attempt is no failure: only the two later losses carry a cause.
    then.the_credit_is_left_unchecked(outcome, (ReplayAttemptFailure.LOST_CONNECTION,) * 2)
