import pytest

import tests.integration.support.test_cve_replay_given as given
import tests.integration.support.test_cve_replay_then as then
from evals.cve_grammar import CVEStatus, grade_run
from evals.cve_replay import replay_credit
from evals.cve_report_units import units_of

pytestmark = pytest.mark.usefixtures("docker_on_the_host")


async def test_a_declared_path_strikes_the_credit():
    run = given.a_declared_run()

    check = await replay_credit(run)

    then.the_flaw_credit_is_struck(check)
    assert grade_run(run.run_target, units_of(run.report), check).status == CVEStatus.MISSED


async def test_the_flaw_path_keeps_the_credit():
    run = given.a_flaw_run()

    check = await replay_credit(run)

    then.the_credit_is_kept(check)
    assert grade_run(run.run_target, units_of(run.report), check).status == CVEStatus.DETECTED


async def test_a_chain_second_step_reaching_the_flaw_keeps_the_credit():
    run = given.a_chain_run()

    check = await replay_credit(run)

    then.the_credit_is_kept(check)


async def test_an_old_nonce_in_an_argument_does_not_fool_the_replay():
    run = given.an_echoed_old_nonce_run()

    check = await replay_credit(run)

    then.the_credit_is_kept(check)


async def test_a_fresh_nonce_of_another_location_strikes_nothing():
    run = given.a_fresh_other_location_run()

    check = await replay_credit(run)

    assert given.FLAW_ID not in {pair.place_id for pair in check.struck}
    assert not check.unchecked


async def test_a_complete_attempt_decides_when_only_the_patched_teardown_raises():
    run = given.a_declared_run_on_a_server_noisy_at_shutdown()

    check = await replay_credit(run)

    then.the_flaw_credit_is_struck(check)


async def test_a_patched_launch_that_always_fails_leaves_the_credit_unchecked():
    run = given.a_patched_launch_failure_run()

    check = await replay_credit(run)

    then.the_credit_is_left_unchecked(check)
    grade = grade_run(run.run_target, units_of(run.report), check)
    assert grade.status == CVEStatus.DETECTED
    assert grade.status_if_unchecked_missed == CVEStatus.MISSED


async def test_a_patched_server_dying_while_answering_leaves_the_credit_unchecked():
    run = given.a_server_dying_while_answering_run()

    check = await replay_credit(run)

    then.the_credit_is_left_unchecked(check)


async def test_a_patched_server_dying_after_a_call_leaves_the_credit_unchecked():
    run = given.a_server_dying_after_a_call_run()

    check = await replay_credit(run, tool_call_timeout=2)

    then.the_credit_is_left_unchecked(check)


async def test_a_detection_before_a_shared_death_is_decided_and_kept():
    run = given.a_detection_kept_when_the_patched_dies_where_the_vulnerable_did_run()

    check = await replay_credit(run)

    then.the_credit_is_kept(check)
    assert grade_run(run.run_target, units_of(run.report), check).status == CVEStatus.DETECTED


async def test_a_straddling_credit_is_struck_when_the_patched_server_survives():
    run = given.a_straddling_chain_struck_despite_a_lost_connection_run()

    check = await replay_credit(run)

    then.the_flaw_credit_is_struck(check)


async def test_a_transient_patched_death_at_the_vulnerable_loss_is_retried_and_struck():
    run = given.a_transient_patched_death_at_the_vulnerable_loss_run()

    check = await replay_credit(run)

    then.the_flaw_credit_is_struck(check)


async def test_truncated_and_failed_attempts_with_no_complete_one_leave_the_run_unchecked():
    run = given.a_truncated_then_failed_attempts_run()

    check = await replay_credit(run)

    then.the_credit_is_left_unchecked(check)
