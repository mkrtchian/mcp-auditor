import dataclasses

import pytest

import tests.unit.detection.support.test_detection_replay_given as given
import tests.unit.detection.support.test_detection_replay_then as then
from evals.cve.detection.replay import (
    RecordedCall,
    ReplayAttemptFailure,
    UncheckedReason,
    arguments_agree,
    replay_with_causes,
    replayed_units,
)
from evals.cve.grammar import CreditCheck
from evals.cve.launch_audit import UndecidableLaunch
from evals.cve.report_units import units_of
from mcp_auditor.domain.container_name import declared_container_name
from mcp_auditor.domain.models import AuditReport


def _agree(report: AuditReport, calls: list[RecordedCall]) -> bool:
    return arguments_agree(units_of(report), calls)


def test_a_case_attaches_its_one_call():
    assert _agree(given.a_case_report(), given.calls(given.FLAW_PATH))


def test_a_blocked_case_contributes_no_call():
    assert _agree(given.a_blocked_case_report(), [])


def test_a_chains_steps_attach_in_order():
    report = given.a_chain_report(given.FLAW_PATH, given.OTHER_PATH)

    assert _agree(report, given.calls(given.FLAW_PATH, given.OTHER_PATH))
    assert not _agree(report, given.calls(given.OTHER_PATH, given.FLAW_PATH))


def test_fewer_outputs_than_sending_steps_fill_the_first_sending_steps_in_order():
    report = given.a_blocked_case_and_chain_report(given.FLAW_PATH, given.OTHER_PATH)

    replayed = replayed_units(units_of(report), ["patched-1"])

    assert [[step.outputs for step in unit.steps] for unit in replayed] == [
        [()],
        [("patched-1",), ()],
    ]


def test_an_argument_mismatch_counts_as_a_disagreement():
    assert not _agree(given.a_case_report(), given.calls("/outside/wrong"))


async def test_an_argument_mismatch_makes_the_run_unchecked_without_launching():
    run = dataclasses.replace(given.a_detecting_run(), recorded_calls=given.calls("/outside/wrong"))
    patched = given.APatchedVersion([])

    outcome = await replay_with_causes(run, connect=patched)

    assert outcome.check == CreditCheck(frozenset(), unchecked=True)
    assert outcome.unchecked_reason is UncheckedReason.ARGUMENTS_DISAGREE
    assert outcome.attempt_failures == ()
    assert patched.launches == []


async def test_the_patched_version_is_relaunched_after_the_calls_the_run_was_and_nowhere_else():
    run = given.a_detecting_run(given.OK, given.LOST, given.OK, relaunched_after=[2])
    patched = given.APatchedVersion([given.OK, given.OK, given.OK, given.SERVES_THE_NONCE])

    outcome = await replay_with_causes(run, connect=patched)

    then.the_credit_is_struck(outcome)
    assert patched.events == ["ping", "call", "call", "relaunch", "ping", "call", "call"]


async def test_the_patched_launch_carries_a_container_name():
    run = given.a_detecting_run()
    patched = given.APatchedVersion([given.SERVES_THE_NONCE])

    await replay_with_causes(run, connect=patched)

    (launch,) = patched.launches
    assert isinstance(declared_container_name(launch.args), str)


async def test_a_lost_connection_at_a_relaunch_point_is_kept_and_the_next_call_sent():
    run = given.a_detecting_run(given.LOST, relaunched_after=[1])
    patched = given.APatchedVersion([given.LOST, given.SERVES_THE_NONCE])

    outcome = await replay_with_causes(run, connect=patched)

    then.the_credit_is_struck(outcome)
    assert patched.events == ["ping", "call", "relaunch", "ping", "call"]


async def test_a_timeout_at_a_relaunch_point_is_kept_with_no_ping_and_the_next_call_sent():
    run = given.a_detecting_run(given.TIMEOUT, relaunched_after=[1])
    patched = given.APatchedVersion([given.TIMEOUT, given.SERVES_THE_NONCE])

    outcome = await replay_with_causes(run, connect=patched)

    then.the_credit_is_struck(outcome)
    assert patched.events == ["ping", "call", "relaunch", "ping", "call"]


async def test_a_timeout_elsewhere_on_a_version_that_stops_answering_the_ping_fails_the_attempt():
    run = given.a_detecting_run(given.OK)
    patched = given.APatchedVersion([given.TIMEOUT], ping_answers=(True, False))

    outcome = await replay_with_causes(run, connect=patched)

    then.the_credit_is_left_unchecked(outcome, ReplayAttemptFailure.STOPPED_ANSWERING)


async def test_a_timeout_followed_by_an_answered_ping_is_left_as_answered():
    run = given.a_detecting_run(given.OK)
    patched = given.APatchedVersion([given.TIMEOUT, given.SERVES_THE_NONCE])

    outcome = await replay_with_causes(run, connect=patched)

    then.the_credit_is_struck(outcome)
    assert patched.events == ["ping", "call", "ping", "call"]


async def test_the_timeouts_of_a_version_silent_to_the_control_ping_all_count_as_responses():
    run = given.a_detecting_run(given.OK)
    patched = given.APatchedVersion([given.TIMEOUT, given.SERVES_THE_NONCE], ping_answers=(False,))

    outcome = await replay_with_causes(run, connect=patched)

    then.the_credit_is_struck(outcome)
    assert patched.events == ["ping", "call", "call"]


async def test_a_relaunch_that_fails_fails_the_attempt_as_a_launch():
    run = given.a_detecting_run(given.LOST, relaunched_after=[1])
    patched = given.APatchedVersion([given.LOST], relaunch_answers=(False,))

    outcome = await replay_with_causes(run, connect=patched)

    then.the_credit_is_left_unchecked(outcome, ReplayAttemptFailure.LAUNCH_FAILED)


async def test_a_loss_at_a_relaunch_point_does_not_truncate_after_it():
    # The vulnerable run lost its connection at call 1 and was relaunched there, then answered
    # call 2: a patched loss at call 2 is a loss the vulnerable run did not have.
    run = given.a_detecting_run(given.LOST, relaunched_after=[1])
    patched = given.APatchedVersion([given.OK, given.LOST])

    outcome = await replay_with_causes(run, connect=patched)

    then.the_credit_is_left_unchecked(outcome, ReplayAttemptFailure.LOST_CONNECTION)


async def test_a_relaunch_point_resets_the_losses_the_truncation_reads():
    # A vulnerable loss with no relaunch after it, which a real run no longer has, then a
    # relaunch at call 2: a patched loss at call 3 is a loss since the last relaunch the
    # vulnerable run did not have.
    run = given.a_detecting_run(given.LOST, given.OK, relaunched_after=[2])
    patched = given.APatchedVersion([given.OK, given.OK, given.LOST])

    outcome = await replay_with_causes(run, connect=patched)

    then.the_credit_is_left_unchecked(outcome, ReplayAttemptFailure.LOST_CONNECTION)


async def test_a_launch_whose_container_name_cannot_be_read_stops_the_replay():
    run = given.a_detecting_run(launch_args=["--an-option-no-table-knows", "value"])
    patched = given.APatchedVersion([given.SERVES_THE_NONCE])

    with pytest.raises(UndecidableLaunch):
        await replay_with_causes(run, connect=patched)
