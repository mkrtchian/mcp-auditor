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


def a_result(tool: str, category: AuditCategory, verdict: EvalVerdict) -> EvalResult:
    return EvalResult(
        tool_name=tool,
        category=category,
        payload={},
        verdict=verdict,
        justification="test",
        severity=Severity.LOW,
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


def a_report(
    results_by_tool: dict[str, list[EvalResult]],
    chains_by_tool: dict[str, list[AttackChain]] | None = None,
) -> AuditReport:
    chains_map = chains_by_tool or {}
    tool_reports = [
        ToolReport(
            tool=ToolDefinition(name=name, description="test", input_schema={"type": "object"}),
            cases=[
                TestCase(
                    payload=AuditPayload(
                        tool_name=r.tool_name,
                        category=r.category,
                        description="test",
                        arguments=r.payload,
                    ),
                    eval_result=r,
                )
                for r in results
            ],
            chains=chains_map.get(name, []),
        )
        for name, results in results_by_tool.items()
    ]
    return AuditReport(target="test", tool_reports=tool_reports, token_usage=TokenUsage())
