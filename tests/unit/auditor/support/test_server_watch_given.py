from mcp_auditor.domain.models import ToolResponse
from mcp_auditor.domain.server_watch import RELAUNCHES_IN_A_ROW, ServerWatch, WatchStep

TIMEOUT = ToolResponse(
    content="Tool call timed out after 30s", is_error=True, error_type="TimeoutError"
)
LOST_CONNECTION = ToolResponse(content="Connection closed", is_error=True, error_type="McpError")
ANSWER = ToolResponse(content="ok")


def a_watch(control_ping_answered: bool = True) -> ServerWatch:
    watch = ServerWatch()
    watch.control_ping_answered(control_ping_answered)
    return watch


def timeouts_on(watch: ServerWatch, tool_name: str, count: int) -> WatchStep:
    """Each timeout on a server that answers the ping it asks for, the last step returned."""
    step = WatchStep.NOTHING
    for _ in range(count):
        step = watch.after_response(tool_name, TIMEOUT)
        if step is WatchStep.PING:
            step = watch.after_ping(tool_name, answered=True)
    return step


def a_relaunch_from(watch: ServerWatch, tool_name: str) -> None:
    watch.after_response(tool_name, LOST_CONNECTION)
    watch.after_relaunch(tool_name, succeeded=True)


def relaunches_in_a_row(watch: ServerWatch, tool_name: str) -> None:
    for _ in range(RELAUNCHES_IN_A_ROW):
        a_relaunch_from(watch, tool_name)
