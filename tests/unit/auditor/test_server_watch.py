import pytest

import tests.unit.auditor.support.test_server_watch_given as given
from mcp_auditor.domain.models import ToolResponse
from mcp_auditor.domain.server_liveness import RelaunchCause, UnsentCause
from mcp_auditor.domain.server_watch import (
    LOST_CONNECTION_RESPONSES,
    TIMEOUTS_IN_A_ROW,
    ServerWatch,
    WatchReaction,
    is_lost_connection,
    is_timeout,
)


def test_a_lost_connection_asks_for_a_relaunch_at_once():
    watch = given.a_watch()

    reaction = watch.after_response("read_file", given.LOST_CONNECTION)

    assert reaction is WatchReaction.RELAUNCH
    assert watch.relaunch_cause() is RelaunchCause.LOST_CONNECTION


def test_a_timeout_on_a_server_that_answered_the_control_ping_asks_for_a_ping():
    watch = given.a_watch(control_ping_answered=True)

    assert watch.after_response("read_file", given.TIMEOUT) is WatchReaction.PING


def test_an_unanswered_ping_after_a_timeout_asks_for_a_relaunch():
    watch = given.a_watch()
    watch.after_response("read_file", given.TIMEOUT)

    reaction = watch.after_ping("read_file", answered=False)

    assert reaction is WatchReaction.RELAUNCH
    assert watch.relaunch_cause() is RelaunchCause.UNANSWERED_PING


def test_an_answered_ping_after_a_timeout_asks_for_nothing():
    watch = given.a_watch()
    watch.after_response("read_file", given.TIMEOUT)

    assert watch.after_ping("read_file", answered=True) is WatchReaction.NOTHING


def test_a_server_silent_to_the_control_ping_is_never_pinged_and_its_timeouts_count():
    watch = given.a_watch(control_ping_answered=False)

    reactions = [watch.after_response("read_file", given.TIMEOUT) for _ in range(TIMEOUTS_IN_A_ROW)]

    assert reactions == [WatchReaction.NOTHING] * TIMEOUTS_IN_A_ROW
    assert watch.unsent_cause("read_file") is UnsentCause.TOOL_TIMING_OUT


def test_timeouts_in_a_row_stop_the_tool_and_no_other():
    watch = given.a_watch()

    given.timeouts_on(watch, "read_file", TIMEOUTS_IN_A_ROW)

    assert watch.unsent_cause("read_file") is UnsentCause.TOOL_TIMING_OUT
    assert watch.unsent_cause("list_files") is None


def test_a_second_tool_timing_out_after_a_stopped_one_takes_the_server_as_stuck():
    watch = given.a_watch()
    given.timeouts_on(watch, "read_file", TIMEOUTS_IN_A_ROW)

    reaction = given.timeouts_on(watch, "list_files", TIMEOUTS_IN_A_ROW)

    assert reaction is WatchReaction.RELAUNCH
    assert watch.relaunch_cause() is RelaunchCause.STUCK
    assert watch.unsent_cause("list_files") is None


def test_after_a_stuck_relaunch_the_tool_timing_out_again_is_stopped_with_no_second_relaunch():
    watch = given.a_watch()
    given.timeouts_on(watch, "read_file", TIMEOUTS_IN_A_ROW)
    given.timeouts_on(watch, "list_files", TIMEOUTS_IN_A_ROW)
    watch.after_relaunch("list_files", succeeded=True)

    reaction = given.timeouts_on(watch, "list_files", TIMEOUTS_IN_A_ROW)

    assert reaction is WatchReaction.NOTHING
    assert watch.unsent_cause("list_files") is UnsentCause.TOOL_TIMING_OUT


def test_a_relaunch_resets_the_timeout_count_of_its_tool_and_keeps_its_relaunch_count():
    watch = given.a_watch()
    given.timeouts_on(watch, "read_file", TIMEOUTS_IN_A_ROW - 1)
    watch.after_response("read_file", given.TIMEOUT)
    watch.after_ping("read_file", answered=False)
    watch.after_relaunch("read_file", succeeded=True)

    given.timeouts_on(watch, "read_file", TIMEOUTS_IN_A_ROW - 1)
    cause_short_of_the_timeouts_in_a_row = watch.unsent_cause("read_file")
    given.a_relaunch_from(watch, "read_file")

    assert cause_short_of_the_timeouts_in_a_row is None
    assert watch.unsent_cause("read_file") is UnsentCause.RELAUNCHES_IN_A_ROW


def test_relaunches_in_a_row_stop_the_tool():
    watch = given.a_watch()

    given.relaunches_in_a_row(watch, "read_file")

    assert watch.unsent_cause("read_file") is UnsentCause.RELAUNCHES_IN_A_ROW


def test_a_timeout_on_a_server_that_answers_the_ping_does_not_reset_the_relaunch_count():
    watch = given.a_watch()
    given.a_relaunch_from(watch, "read_file")
    given.timeouts_on(watch, "read_file", 1)

    given.a_relaunch_from(watch, "read_file")

    assert watch.unsent_cause("read_file") is UnsentCause.RELAUNCHES_IN_A_ROW


def test_a_real_response_resets_the_timeout_count():
    watch = given.a_watch()
    given.timeouts_on(watch, "read_file", TIMEOUTS_IN_A_ROW - 1)
    watch.after_response("read_file", given.ANSWER)

    given.timeouts_on(watch, "read_file", TIMEOUTS_IN_A_ROW - 1)

    assert watch.unsent_cause("read_file") is None


def test_a_real_response_resets_the_relaunch_count_and_forgets_the_tool_stopped_before():
    watch = given.a_watch()
    given.a_relaunch_from(watch, "list_files")
    given.timeouts_on(watch, "read_file", TIMEOUTS_IN_A_ROW)
    watch.after_response("list_files", given.ANSWER)
    given.a_relaunch_from(watch, "list_files")

    reaction = given.timeouts_on(watch, "search", TIMEOUTS_IN_A_ROW)

    assert reaction is WatchReaction.NOTHING
    assert watch.unsent_cause("search") is UnsentCause.TOOL_TIMING_OUT
    assert watch.unsent_cause("list_files") is None


def test_a_failed_relaunch_takes_the_server_as_down_for_every_tool():
    watch = given.a_watch()
    watch.after_response("read_file", given.LOST_CONNECTION)

    watch.after_relaunch("read_file", succeeded=False)

    assert watch.taken_as_down is True
    assert watch.unsent_cause("read_file") is UnsentCause.SERVER_DOWN
    assert watch.unsent_cause("list_files") is UnsentCause.SERVER_DOWN


def test_a_fresh_watch_stops_nothing():
    watch = ServerWatch()

    assert watch.taken_as_down is False
    assert watch.unsent_cause("read_file") is None


def test_only_a_timeout_error_is_a_timeout():
    assert is_timeout(given.TIMEOUT) is True
    assert is_timeout(given.LOST_CONNECTION) is False
    assert is_timeout(ToolResponse(content="timed out", is_error=True)) is False


@pytest.mark.parametrize(("error_type", "content"), LOST_CONNECTION_RESPONSES)
def test_each_lost_connection_response_reads_as_a_lost_connection(
    error_type: str, content: str | None
):
    response = ToolResponse(content=content or "stream gone", is_error=True, error_type=error_type)

    assert is_lost_connection(response) is True


def test_another_mcp_error_is_not_a_lost_connection():
    response = ToolResponse(content="Invalid params", is_error=True, error_type="McpError")

    assert is_lost_connection(response) is False
