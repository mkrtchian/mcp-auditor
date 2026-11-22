from mcp_auditor.domain.models import ToolResponse
from mcp_auditor.domain.server_watch import RELAUNCHES_IN_A_ROW, ServerWatch, WatchReaction
from tests.fakes.mcp_client import a_lost_connection_response, a_timeout_response

TIMEOUT = a_timeout_response()
LOST_CONNECTION = a_lost_connection_response()
ANSWER = ToolResponse(content="ok")


def a_watch(control_ping_answered: bool = True) -> ServerWatch:
    watch = ServerWatch()
    watch.control_ping_answered(control_ping_answered)
    return watch


def timeouts_on(watch: ServerWatch, tool_name: str, count: int) -> WatchReaction:
    """Each timeout on a server that answers the ping it asks for, the last reaction returned."""
    reaction = WatchReaction.NOTHING
    for _ in range(count):
        reaction = watch.after_response(tool_name, TIMEOUT)
        if reaction is WatchReaction.PING:
            reaction = watch.after_ping(tool_name, answered=True)
    return reaction


def relaunches_in_a_row(watch: ServerWatch, tool_name: str) -> None:
    for _ in range(RELAUNCHES_IN_A_ROW):
        a_relaunch_from(watch, tool_name)


def a_relaunch_from(watch: ServerWatch, tool_name: str) -> None:
    watch.after_response(tool_name, LOST_CONNECTION)
    watch.after_relaunch(tool_name, succeeded=True)
