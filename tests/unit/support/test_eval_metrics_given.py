from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)

FAIL = EvalVerdict.FAIL
PASS = EvalVerdict.PASS
INPUT_VALIDATION = AuditCategory.INPUT_VALIDATION
ERROR_HANDLING = AuditCategory.ERROR_HANDLING
INFO_LEAKAGE = AuditCategory.INFO_LEAKAGE
INJECTION = AuditCategory.INJECTION
RESOURCE_ABUSE = AuditCategory.RESOURCE_ABUSE

ALL_CATEGORIES = list(AuditCategory)


def a_result(tool: str, category: AuditCategory, verdict: EvalVerdict) -> EvalResult:
    return EvalResult(
        tool_name=tool,
        category=category,
        payload={},
        verdict=verdict,
        justification="test",
        severity=Severity.LOW,
    )


def a_report(results_by_tool: dict[str, list[EvalResult]]) -> AuditReport:
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
        )
        for name, results in results_by_tool.items()
    ]
    return AuditReport(target="test", tool_reports=tool_reports, token_usage=TokenUsage())
