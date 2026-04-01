from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    ChainGoal,
    ChainStep,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)

TOOL = ToolDefinition(name="get_user", description="Fetches a user", input_schema={})


def a_judged_case(
    verdict: EvalVerdict,
    category: AuditCategory = AuditCategory.INPUT_VALIDATION,
) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            tool_name="get_user",
            category=category,
            description="test desc",
            arguments={"id": 1},
        ),
        response="some response",
        error=None,
        eval_result=EvalResult(
            tool_name="get_user",
            category=category,
            payload={"id": 1},
            verdict=verdict,
            justification="because",
            severity=Severity.HIGH,
        ),
    )


def an_unjudged_case() -> TestCase:
    return TestCase(
        payload=AuditPayload(
            tool_name="get_user",
            category=AuditCategory.INPUT_VALIDATION,
            description="test",
            arguments={},
        ),
    )


def a_report(cases: list[TestCase], chains: list[AttackChain] | None = None) -> AuditReport:
    return AuditReport(
        target="test",
        tool_reports=[ToolReport(tool=TOOL, cases=cases, chains=chains or [])],
        token_usage=TokenUsage(),
    )


def a_chain_with_leakage_verdict() -> AttackChain:
    payload = AuditPayload(
        tool_name="get_user",
        category=AuditCategory.INFO_LEAKAGE,
        description="step 1",
        arguments={"action": "list"},
    )
    return AttackChain(
        goal=ChainGoal(
            description="probe then exploit",
            category=AuditCategory.INFO_LEAKAGE,
            first_step=payload,
        ),
        steps=[
            ChainStep(payload=payload, response="['proj_001']", observation="found ids"),
        ],
        eval_result=EvalResult(
            tool_name="get_user",
            category=AuditCategory.INFO_LEAKAGE,
            payload={"action": "list"},
            verdict=EvalVerdict.FAIL,
            justification="leaked internal data",
            severity=Severity.HIGH,
        ),
    )


