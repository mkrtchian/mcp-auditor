from mcp_auditor.domain.models import AuditReport, CoverageGap, ToolResponse
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause
from mcp_auditor.domain.shown_response import MAX_SHOWN_LENGTH
from tests.unit.cve.support import test_cve_grammar_given as grammar


def a_response(error_type: str | None, content: str) -> ToolResponse:
    return ToolResponse(content=content, is_error=error_type is not None, error_type=error_type)


LOST = a_response("McpError", "Connection closed")
ANSWERED = a_response(None, "ok")


class NoisyClient:
    non_protocol_lines = 2


def a_report_with(relaunches: int, gaps: list[tuple[int, int]]) -> AuditReport:
    """`gaps` holds the cases and chains not sent on each tool, one tool per gap."""
    relaunched = [
        Relaunch(
            tool_name="read", arguments={}, cause=RelaunchCause.LOST_CONNECTION, succeeded=True
        )
        for _ in range(relaunches)
    ]
    tools = [
        grammar.a_tool_report(f"tool_{index}").model_copy(
            update={"coverage_gap": _a_gap(unsent_cases, unsent_chains)}
        )
        for index, (unsent_cases, unsent_chains) in enumerate(gaps)
    ]
    report = grammar.a_report_of_tools(grammar.a_tool_report("whole"), *tools)
    return report.model_copy(update={"relaunches": relaunched})


def a_report_with_one_cut_response_on_each_of(tools: int) -> AuditReport:
    cut = grammar.a_case(response="x" * (MAX_SHOWN_LENGTH + 1))
    shown_whole = grammar.a_case(response="ok")
    return grammar.a_report_of_tools(
        *(grammar.a_tool_report(f"tool_{index}", [cut, shown_whole]) for index in range(tools))
    )


def _a_gap(unsent_cases: int, unsent_chains: int) -> CoverageGap:
    return CoverageGap(
        requested_cases=10,
        received_cases=10,
        missing_categories=[],
        unsent_cases=unsent_cases,
        unsent_chains=unsent_chains,
    )
