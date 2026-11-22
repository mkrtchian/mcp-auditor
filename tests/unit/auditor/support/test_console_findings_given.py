from mcp_auditor.domain.models import (
    AuditCategory,
    AuditReport,
    ProviderUsage,
    Severity,
    ToolDefinition,
    ToolReport,
)
from tests.unit.auditor.support.report_builders import a_failing_case, a_passing_case


def a_report_with_one_pass_plus_failures(
    failures_per_tool: dict[str, list[tuple[Severity, AuditCategory, str]]],
) -> AuditReport:
    tool_reports: list[ToolReport] = []
    for tool_name, failures in failures_per_tool.items():
        cases = [a_passing_case(tool_name)]
        for severity, category, justification in failures:
            cases.append(a_failing_case(tool_name, severity, category, justification))
        tool_reports.append(
            ToolReport(
                tool=ToolDefinition(name=tool_name, description="", input_schema={}),
                cases=cases,
            )
        )
    return _a_report(tool_reports)


def a_report_with_n_results(pass_count: int, fail_count: int) -> AuditReport:
    passing = [a_passing_case("tool_a") for _ in range(pass_count)]
    failing = [
        a_failing_case("tool_a", Severity.MEDIUM, AuditCategory.INJECTION, "vuln")
        for _ in range(fail_count)
    ]
    return _a_report(
        [
            ToolReport(
                tool=ToolDefinition(name="tool_a", description="", input_schema={}),
                cases=passing + failing,
            )
        ]
    )


def _a_report(tool_reports: list[ToolReport]) -> AuditReport:
    return AuditReport(
        server_command="python server.py",
        tool_reports=tool_reports,
        provider_usage=ProviderUsage(input_tokens=100, output_tokens=50),
    )
