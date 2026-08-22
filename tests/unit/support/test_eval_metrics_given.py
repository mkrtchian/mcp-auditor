from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    ChainGoal,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)


def a_report(
    results_by_tool: dict[str, list[EvalResult]],
    chains_by_tool: dict[str, list[AttackChain]] | None = None,
) -> AuditReport:
    chains_map = chains_by_tool or {}
    tool_reports = [
        _a_tool_report(name, results, chains_map.get(name, []))
        for name, results in results_by_tool.items()
    ]
    return AuditReport(target="test", tool_reports=tool_reports, token_usage=TokenUsage())


def _a_tool_report(name: str, results: list[EvalResult], chains: list[AttackChain]) -> ToolReport:
    return ToolReport(
        tool=ToolDefinition(name=name, description="test", input_schema={"type": "object"}),
        cases=[_a_case_for(result) for result in results],
        chains=chains,
    )


def _a_case_for(result: EvalResult) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            category=result.category,
            description="test",
            arguments=result.payload,
        ),
        eval_result=result,
    )


def a_chain(tool: str, category: AuditCategory, verdict: EvalVerdict) -> AttackChain:
    return AttackChain(
        goal=ChainGoal(
            description="test chain",
            category=category,
            first_step=AuditPayload(category=category, description="test", arguments={}),
        ),
        steps=[],
        eval_result=a_result(tool, category, verdict),
    )


def a_result(tool: str, category: AuditCategory, verdict: EvalVerdict) -> EvalResult:
    return EvalResult(
        tool_name=tool,
        category=category,
        payload={},
        verdict=verdict,
        justification="test",
        severity=Severity.LOW,
    )


def and_a_blocked_case(report: AuditReport, tool: str, category: AuditCategory) -> AuditReport:
    blocked = TestCase(
        payload=AuditPayload(category=category, description="test", arguments={"q": "rm -rf /"}),
        blocked_reason="destructive filesystem command: rm -rf",
    )
    tool_reports = [
        tr.model_copy(update={"cases": [*tr.cases, blocked]}) if tr.tool.name == tool else tr
        for tr in report.tool_reports
    ]
    return report.model_copy(update={"tool_reports": tool_reports})


def and_a_blocked_chain(report: AuditReport, tool: str, category: AuditCategory) -> AuditReport:
    blocked = AttackChain(
        goal=ChainGoal(
            description="test chain",
            category=category,
            first_step=AuditPayload(category=category, description="test", arguments={}),
        ),
        steps=[],
        blocked_reason="destructive SQL statement: drop table",
    )
    tool_reports = [
        tr.model_copy(update={"chains": [*tr.chains, blocked]}) if tr.tool.name == tool else tr
        for tr in report.tool_reports
    ]
    return report.model_copy(update={"tool_reports": tool_reports})
