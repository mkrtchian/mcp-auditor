from mcp_auditor.domain.models import (
    AttackChain,
    AuditReport,
    ProviderUsage,
    TestCase,
    ToolDefinition,
    ToolReport,
)


def a_tool_report(
    name: str, cases: list[TestCase] | None = None, chains: list[AttackChain] | None = None
) -> ToolReport:
    return ToolReport(
        tool=ToolDefinition(name=name, description="test", input_schema={"type": "object"}),
        cases=cases or [],
        chains=chains or [],
    )


def a_report_of_tools(*tool_reports: ToolReport) -> AuditReport:
    return AuditReport(
        target="test", tool_reports=list(tool_reports), provider_usage=ProviderUsage()
    )
