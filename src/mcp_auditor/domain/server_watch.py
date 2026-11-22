"""When a call that timed out or lost its connection is followed by a ping or a relaunch, and
when a tool stops being called (ADR 036). Pure: the caller sends the pings and relaunches."""

from collections import Counter
from enum import StrEnum
from typing import Final

from mcp_auditor.domain.models import ToolResponse
from mcp_auditor.domain.server_liveness import RelaunchCause, UnsentCause

TIMEOUTS_IN_A_ROW: Final = 3
RELAUNCHES_IN_A_ROW: Final = 2

# A server gone mid-call looks like an ordinary error: SDK 1.30 turns a call in flight when the
# server exits into an McpError reading "Connection closed", and the stdio transport surfaces a
# closed or broken stream under anyio's own error names. Any other McpError (invalid params, a
# removed tool) and a TimeoutError on a live server are ordinary responses.
LOST_CONNECTION_RESPONSES: tuple[tuple[str, str | None], ...] = (
    ("McpError", "Connection closed"),
    ("ClosedResourceError", None),
    ("BrokenResourceError", None),
)


class WatchReaction(StrEnum):
    NOTHING = "nothing"
    PING = "ping"
    RELAUNCH = "relaunch"


class ServerWatch:
    def __init__(self) -> None:
        self._ping_answered = False
        self._timeouts: Counter[str] = Counter()
        self._relaunches: Counter[str] = Counter()
        self._stopped: dict[str, UnsentCause] = {}
        self._stopped_last_for_timing_out: str | None = None
        self._relaunch_cause: RelaunchCause | None = None
        self._down = False

    @property
    def taken_as_down(self) -> bool:
        return self._down

    def unsent_cause(self, tool_name: str) -> UnsentCause | None:
        if self._down:
            return UnsentCause.SERVER_DOWN
        return self._stopped.get(tool_name)

    def control_ping_answered(self, answered: bool) -> None:
        self._ping_answered = answered

    def after_response(self, tool_name: str, response: ToolResponse) -> WatchReaction:
        if is_lost_connection(response):
            return self._relaunch_for(RelaunchCause.LOST_CONNECTION)
        if not is_timeout(response):
            self._answered(tool_name)
            return WatchReaction.NOTHING
        if self._ping_answered:
            return WatchReaction.PING
        return self._timed_out(tool_name)

    def after_ping(self, tool_name: str, answered: bool) -> WatchReaction:
        if not answered:
            return self._relaunch_for(RelaunchCause.UNANSWERED_PING)
        return self._timed_out(tool_name)

    def relaunch_cause(self) -> RelaunchCause:
        assert self._relaunch_cause is not None, "no relaunch was asked for"
        return self._relaunch_cause

    def after_relaunch(self, tool_name: str, succeeded: bool) -> None:
        if not succeeded:
            self._down = True
            return
        self._timeouts[tool_name] = 0
        self._relaunches[tool_name] += 1
        if self._relaunch_cause is RelaunchCause.STUCK:
            self._stopped_last_for_timing_out = None
        if self._relaunches[tool_name] >= RELAUNCHES_IN_A_ROW:
            self._stopped[tool_name] = UnsentCause.RELAUNCHES_IN_A_ROW

    def _relaunch_for(self, cause: RelaunchCause) -> WatchReaction:
        self._relaunch_cause = cause
        return WatchReaction.RELAUNCH

    def _answered(self, tool_name: str) -> None:
        self._timeouts[tool_name] = 0
        self._relaunches[tool_name] = 0
        self._stopped_last_for_timing_out = None

    def _timed_out(self, tool_name: str) -> WatchReaction:
        self._timeouts[tool_name] += 1
        if self._timeouts[tool_name] < TIMEOUTS_IN_A_ROW:
            return WatchReaction.NOTHING
        if self._stopped_last_for_timing_out is not None:
            return self._relaunch_for(RelaunchCause.STUCK)
        self._stopped[tool_name] = UnsentCause.TOOL_TIMING_OUT
        self._stopped_last_for_timing_out = tool_name
        return WatchReaction.NOTHING


def is_timeout(response: ToolResponse) -> bool:
    return response.error_type == "TimeoutError"


def is_lost_connection(response: ToolResponse) -> bool:
    return response.is_error and any(
        response.error_type == error_type and (content is None or response.content == content)
        for error_type, content in LOST_CONNECTION_RESPONSES
    )
