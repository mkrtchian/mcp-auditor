from mcp_auditor.domain import (
    AttackChain,
    AuditCategory,
    AuditReport,
    EvalVerdict,
    JudgeResult,
    ProviderUsage,
    Severity,
    ToolDefinition,
    ToolReport,
)
from tests.unit.auditor.support.chain_states import a_chain_goal, a_chain_step, a_fail_judge_result


class TestAuditReportChainFindings:
    def test_includes_chain_fail_verdicts(self):
        chain = AttackChain(
            goal=a_chain_goal(),
            steps=[a_chain_step()],
            judge_result=a_fail_judge_result(),
        )
        tool = ToolDefinition(name="t", description="t", input_schema={})
        report = AuditReport(
            server_command="test",
            tool_reports=[ToolReport(tool=tool, cases=[], chains=[chain])],
            provider_usage=ProviderUsage(),
        )

        assert len(report.findings) == 1
        assert report.findings[0].verdict == EvalVerdict.FAIL

    def test_excludes_chain_pass_verdicts(self):
        pass_result = JudgeResult(
            tool_name="t",
            category=AuditCategory.INJECTION,
            arguments={},
            verdict=EvalVerdict.PASS,
            justification="safe",
            severity=Severity.LOW,
        )
        chain = AttackChain(
            goal=a_chain_goal(),
            steps=[a_chain_step()],
            judge_result=pass_result,
        )
        tool = ToolDefinition(name="t", description="t", input_schema={})
        report = AuditReport(
            server_command="test",
            tool_reports=[ToolReport(tool=tool, cases=[], chains=[chain])],
            provider_usage=ProviderUsage(),
        )

        assert len(report.findings) == 0
