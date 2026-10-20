import tests.unit.support.test_chain_nodes_given as given
from mcp_auditor.domain import (
    AttackChain,
    AuditCategory,
    AuditReport,
    EvalResult,
    EvalVerdict,
    ProviderUsage,
    Severity,
    ToolDefinition,
    ToolReport,
)


class TestAuditReportChainFindings:
    def test_includes_chain_fail_verdicts(self):
        chain = AttackChain(
            goal=given.a_chain_goal(),
            steps=[given.a_chain_step()],
            eval_result=given.a_fail_eval_result(),
        )
        tool = ToolDefinition(name="t", description="t", input_schema={})
        report = AuditReport(
            target="test",
            tool_reports=[ToolReport(tool=tool, cases=[], chains=[chain])],
            provider_usage=ProviderUsage(),
        )

        assert len(report.findings) == 1
        assert report.findings[0].verdict == EvalVerdict.FAIL

    def test_excludes_chain_pass_verdicts(self):
        pass_result = EvalResult(
            tool_name="t",
            category=AuditCategory.INJECTION,
            payload={},
            verdict=EvalVerdict.PASS,
            justification="safe",
            severity=Severity.LOW,
        )
        chain = AttackChain(
            goal=given.a_chain_goal(),
            steps=[given.a_chain_step()],
            eval_result=pass_result,
        )
        tool = ToolDefinition(name="t", description="t", input_schema={})
        report = AuditReport(
            target="test",
            tool_reports=[ToolReport(tool=tool, cases=[], chains=[chain])],
            provider_usage=ProviderUsage(),
        )

        assert len(report.findings) == 0
