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


def _a_tool_report(
    name: str, results: list[EvalResult], chains: list[AttackChain]
) -> ToolReport:
    return ToolReport(
        tool=ToolDefinition(name=name, description="test", input_schema={"type": "object"}),
        cases=[_a_case_for(result) for result in results],
        chains=chains,
    )


def _a_case_for(result: EvalResult) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            tool_name=result.tool_name,
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
            first_step=AuditPayload(
                tool_name=tool, category=category, description="test", arguments={}
            ),
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
