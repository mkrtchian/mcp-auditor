"""The exits of the nuisance suite rule, in its list order, and the exit the admission records."""

from datetime import date
from enum import StrEnum

from pydantic import BaseModel


class ExitReason(StrEnum):
    NO_COUNTED_FLAW = "no_counted_flaw"
    COUNTED_FLAW_NEVER_FIXED = "counted_flaw_never_fixed"
    NO_COUNTED_TOOL_LEFT = "no_counted_tool_left"
    NOT_OVER_STDIO = "not_over_stdio"
    NOT_UNDER_DOCKER = "not_under_docker"
    EXCLUDED_SERVER = "excluded_server"
    ACCEPTANCE_TARGET_SERVER = "acceptance_target_server"
    SPENT_BY_A_READING = "spent_by_a_reading"


EXIT_REASON_TEXTS = {
    ExitReason.NO_COUNTED_FLAW: "no counted flaw",
    ExitReason.COUNTED_FLAW_NEVER_FIXED: "a counted flaw never fixed",
    ExitReason.NO_COUNTED_TOOL_LEFT: "no counted tool left",
    ExitReason.NOT_OVER_STDIO: "does not run over stdio",
    ExitReason.NOT_UNDER_DOCKER: "its patched version does not run under Docker",
    ExitReason.EXCLUDED_SERVER: "an excluded server",
    ExitReason.ACCEPTANCE_TARGET_SERVER: "the server of a current or dropped acceptance target",
    ExitReason.SPENT_BY_A_READING: "spent by a reading",
}


class RecordedExit(BaseModel):
    server_package: str
    reason: ExitReason
    logged_on: date  # the nuisance suite log entry that states the facts the reason rests on
