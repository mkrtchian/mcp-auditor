"""The calls the auditor withholds from a stopped tool or a server taken as down (ADR 036).
They are counted apart, and never enter `processed_cases` or a chain's steps."""

from typing import Any

from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import CoverageGap, TestCase, ToolReport
from mcp_auditor.domain.server_liveness import UnsentCause, UnsentPayload


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


def make_count_chains_not_planned(server: AuditedServer):
    def count_chains_not_planned(state: dict[str, Any]) -> dict[str, Any]:
        # The chains of the tool audited before stay in the state until a chain audit runs.
        return {
            "completed_chains": [],
            "unsent_chains": state["chain_budget"],
            "unsent_cause": server.unsent_cause(state["current_tool"].name),
        }

    return count_chains_not_planned


def coverage_gap_of_tool(state: dict[str, Any]) -> CoverageGap | None:
    generation_gap: CoverageGap | None = state.get("coverage_gap")
    unsent_cases = state.get("unsent_cases", 0)
    unsent_chains = state.get("unsent_chains", 0)
    if unsent_cases + unsent_chains == 0:
        return generation_gap
    generated = generation_gap or CoverageGap(
        requested_cases=state["test_budget"],
        received_cases=len(state["processed_cases"]) + unsent_cases,
        missing_categories=[],
    )
    return generated.model_copy(
        update={
            "unsent_cases": unsent_cases,
            "unsent_chains": unsent_chains,
            "unsent_cause": state.get("unsent_cause"),
        }
    )


def report_tools_left(state: dict[str, Any]) -> dict[str, Any]:
    left = state["discovered_tools"][len(state["tool_reports"]) :]
    gap = CoverageGap(
        requested_cases=state["test_budget"],
        received_cases=0,
        missing_categories=[],
        unsent_chains=state["chain_budget"],
        unsent_cause=UnsentCause.SERVER_DOWN,
    )
    return {"tool_reports": [ToolReport(tool=tool, cases=[], coverage_gap=gap) for tool in left]}
