import tests.unit.support.test_chain_nodes_given as given
from mcp_auditor.domain import (
    AttackChain,
    AuditCategory,
    AuditReport,
    ChainPlanBatch,
    EvalResult,
    EvalVerdict,
    Severity,
    StepObservation,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)


class TestAttackChain:
    def test_constructs_with_goal_and_steps(self):
        goal = given.a_chain_goal()
        steps = [given.a_chain_step()]
        chain = AttackChain(goal=goal, steps=steps)

        assert chain.goal == goal
        assert len(chain.steps) == 1
        assert chain.eval_result is None

    def test_constructs_with_eval_result(self):
        chain = AttackChain(
            goal=given.a_chain_goal(),
            steps=[given.a_chain_step()],
            eval_result=given.a_fail_eval_result(),
        )

        assert chain.eval_result is not None
        assert chain.eval_result.verdict == EvalVerdict.FAIL


class TestToolReportWithChains:
    def test_roundtrip_serialization(self):
        chain = AttackChain(
            goal=given.a_chain_goal(),
            steps=[given.a_chain_step()],
            eval_result=given.a_fail_eval_result(),
        )
        report = ToolReport(
            tool=ToolDefinition(name="t", description="t", input_schema={}),
            cases=[],
            chains=[chain],
        )

        rebuilt = ToolReport.model_validate(report.model_dump())

        assert len(rebuilt.chains) == 1
        assert rebuilt.chains[0].goal.description == chain.goal.description
        assert rebuilt.chains[0].eval_result is not None


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
            token_usage=TokenUsage(),
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
            token_usage=TokenUsage(),
        )

        assert len(report.findings) == 0


class TestStepObservation:
    def test_parses_with_next_step_hint(self):
        obs = StepObservation(
            observation="Found internal path",
            should_continue=True,
            next_step_hint="Try path traversal",
        )

        assert obs.next_step_hint == "Try path traversal"

    def test_parses_without_next_step_hint(self):
        obs = StepObservation(
            observation="Dead end",
            should_continue=False,
        )

        assert obs.next_step_hint == ""


class TestChainPlanBatch:
    def test_wraps_list_of_chain_goals(self):
        goals = [given.a_chain_goal(), given.a_chain_goal(description="second goal")]
        batch = ChainPlanBatch(chains=goals)

        assert len(batch.chains) == 2
        assert batch.chains[1].description == "second goal"
