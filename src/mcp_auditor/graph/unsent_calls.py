"""The calls the auditor withholds from a stopped tool or a server taken as down (ADR 036).
They are counted apart, and never enter `processed_cases` or a chain's steps."""

from typing import Any

from mcp_auditor.domain.models import TestCase
from mcp_auditor.domain.server_liveness import UnsentPayload


def case_not_sent(
    state: dict[str, Any], unsent: UnsentPayload, pending: list[TestCase]
) -> dict[str, Any]:
    return {
        "current_case": None,
        "pending_cases": pending,
        "unsent_cases": state.get("unsent_cases", 0) + 1,
        "unsent_cause": unsent.cause,
    }


def count_unsent_chain(state: dict[str, Any]) -> dict[str, Any]:
    """A chain whose first step is not sent is counted, never recorded: an empty chain would
    read as one that ran."""
    return {
        "unsent_chains": state.get("unsent_chains", 0) + 1,
        "current_chain_goal": None,
        "unsent_step_cause": None,
    }
