"""Why the auditor relaunched the audited server, or withheld a call (ADR 036).

`models.py` imports this module, so it imports nothing from `models.py`."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel


class RelaunchCause(StrEnum):
    LOST_CONNECTION = "lost_connection"
    UNANSWERED_PING = "unanswered_ping"
    STUCK = "stuck"


class UnsentCause(StrEnum):
    TOOL_TIMING_OUT = "tool_timing_out"
    RELAUNCHES_IN_A_ROW = "relaunches_in_a_row"
    SERVER_DOWN = "server_down"


@dataclass(frozen=True)
class UnsentPayload:
    # No field is named like a ToolResponse or BlockedPayload field: an outcome a caller
    # forgets to handle is a type error, never a silent success.
    cause: UnsentCause


class Relaunch(BaseModel):
    tool_name: str
    arguments: dict[str, Any]
    cause: RelaunchCause
    succeeded: bool
