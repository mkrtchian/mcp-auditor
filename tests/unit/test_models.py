"""Only tests that validate OUR design choices — enum constraints, union types,
custom methods, serialization of non-trivial types. Does not test that
Pydantic constructors work or that Python lists hold items.
"""

from typing import Any

import pytest

from mcp_auditor.domain import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    ChainGoal,
    ChainPlanBatch,
    ChainStep,
    EvalResult,
    EvalVerdict,
    Severity,
    StepObservation,
    TestCase,
    TokenUsage,
    ToolDefinition,
    ToolReport,
    ToolResponse,
)
from mcp_auditor.domain.models import order_tools_for_audit


class TestEnumConstraints:
    def test_rejects_unknown_category(self):
        with pytest.raises(ValueError):
            _a_payload(category="unknown_category")

    def test_rejects_unknown_severity(self):
        with pytest.raises(ValueError):
            EvalResult(
                tool_name="t",
                category=AuditCategory.INJECTION,
                payload={},
                verdict=EvalVerdict.FAIL,
                justification="j",
                severity="unknown",  # type: ignore[arg-type]
            )


class TestToolDefinition:
    def test_roundtrip_serialization(self):
        tool = ToolDefinition(
            name="get_user",
            description="Fetch a user by ID",
            input_schema={"type": "object", "properties": {"id": {"type": "integer"}}},
        )

        rebuilt = ToolDefinition.model_validate_json(tool.model_dump_json())

        assert rebuilt == tool


class TestTestCase:
    def test_response_accepts_dict(self):
        test_case = TestCase(payload=_a_payload(), response={"result": "ok"})

        assert test_case.response == {"result": "ok"}

    def test_response_accepts_string(self):
        test_case = TestCase(payload=_a_payload(), response="raw text")

        assert test_case.response == "raw text"


class TestToolResponse:
    def test_default_is_not_error(self):
        response = ToolResponse(content="ok")

        assert response.is_error is False

    def test_explicit_error_flag(self):
        response = ToolResponse(content="boom", is_error=True)

        assert response.is_error is True

    def test_error_type_defaults_to_none(self):
        response = ToolResponse(content="ok")

        assert response.error_type is None

    def test_error_type_captures_exception_class(self):
        response = ToolResponse(content="boom", is_error=True, error_type="ConnectionError")

        assert response.error_type == "ConnectionError"


class TestTokenUsage:
    def test_add_accumulates(self):
        a = TokenUsage(input_tokens=100, output_tokens=50)
        b = TokenUsage(input_tokens=200, output_tokens=100)

        total = a.add(b)

        assert total.input_tokens == 300
        assert total.output_tokens == 150

    def test_add_does_not_mutate(self):
        a = TokenUsage(input_tokens=100, output_tokens=50)
        b = TokenUsage(input_tokens=200, output_tokens=100)

        a.add(b)

        assert a.input_tokens == 100
        assert a.output_tokens == 50


class TestSeverityComparison:
    def test_critical_is_greater_than_low(self):
        assert Severity.CRITICAL > Severity.LOW

    def test_low_is_less_than_high(self):
        assert Severity.LOW < Severity.HIGH

    def test_medium_is_greater_or_equal_to_medium(self):
        assert Severity.MEDIUM >= Severity.MEDIUM

    def test_ordering_matches_declaration(self):
        assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


class TestAuditReportFindings:
    def test_detects_findings_at_exact_threshold(self):
        report = _a_report_with_finding(Severity.HIGH)

        assert report.has_findings_at_or_above(Severity.HIGH) is True

    def test_detects_findings_above_threshold(self):
        report = _a_report_with_finding(Severity.CRITICAL)

        assert report.has_findings_at_or_above(Severity.HIGH) is True

    def test_ignores_findings_below_threshold(self):
        report = _a_report_with_finding(Severity.LOW)

        assert report.has_findings_at_or_above(Severity.HIGH) is False

    def test_empty_report_has_no_findings(self):
        report = AuditReport(target="test", tool_reports=[], token_usage=TokenUsage())

        assert report.has_findings_at_or_above(Severity.LOW) is False


def _a_report_with_finding(severity: Severity) -> AuditReport:
    result = EvalResult(
        tool_name="t",
        category=AuditCategory.INJECTION,
        payload={},
        verdict=EvalVerdict.FAIL,
        justification="vuln",
        severity=severity,
    )
    case = TestCase(
        payload=AuditPayload(
            tool_name="t",
            category=AuditCategory.INJECTION,
            description="test",
            arguments={},
        ),
        eval_result=result,
    )
    tool = ToolDefinition(name="t", description="t", input_schema={})
    return AuditReport(
        target="test",
        tool_reports=[ToolReport(tool=tool, cases=[case])],
        token_usage=TokenUsage(),
    )


class TestOrderToolsForAudit:
    def test_read_like_tools_sort_before_others(self):
        tools = [
            _a_tool(name="delete_user"),
            _a_tool(name="get_user"),
            _a_tool(name="list_items"),
        ]

        result = order_tools_for_audit(tools)

        assert [t.name for t in result] == ["get_user", "list_items", "delete_user"]

    def test_ties_broken_by_parameter_count(self):
        three_params = _a_tool(
            name="get_details",
            input_schema={
                "type": "object",
                "properties": {"a": {}, "b": {}, "c": {}},
            },
        )
        one_param = _a_tool(
            name="get_summary",
            input_schema={"type": "object", "properties": {"a": {}}},
        )

        result = order_tools_for_audit([three_params, one_param])

        assert [t.name for t in result] == ["get_summary", "get_details"]

    def test_stable_within_same_group(self):
        tools = [_a_tool(name="create_x"), _a_tool(name="update_y")]

        result = order_tools_for_audit(tools)

        assert [t.name for t in result] == ["create_x", "update_y"]

    def test_empty_list(self):
        assert order_tools_for_audit([]) == []

    def test_all_read_prefixes_recognized(self):
        prefixes = [
            "get_",
            "list_",
            "read_",
            "search_",
            "find_",
            "fetch_",
            "show_",
            "describe_",
            "check_",
        ]
        tools = [_a_tool(name=f"{p}thing") for p in prefixes]
        tools.append(_a_tool(name="delete_thing"))

        result = order_tools_for_audit(tools)

        assert result[-1].name == "delete_thing"


def _a_tool(
    name: str = "test_tool",
    input_schema: dict[str, Any] | None = None,
) -> ToolDefinition:
    return ToolDefinition(name=name, description="desc", input_schema=input_schema or {})


class TestAttackChain:
    def test_constructs_with_goal_and_steps(self):
        goal = _a_chain_goal()
        steps = [_a_chain_step()]
        chain = AttackChain(goal=goal, steps=steps)

        assert chain.goal == goal
        assert len(chain.steps) == 1
        assert chain.eval_result is None

    def test_constructs_with_eval_result(self):
        chain = AttackChain(
            goal=_a_chain_goal(),
            steps=[_a_chain_step()],
            eval_result=_a_fail_eval_result(),
        )

        assert chain.eval_result is not None
        assert chain.eval_result.verdict == EvalVerdict.FAIL


class TestToolReportWithChains:
    def test_roundtrip_serialization(self):
        chain = AttackChain(
            goal=_a_chain_goal(),
            steps=[_a_chain_step()],
            eval_result=_a_fail_eval_result(),
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
            goal=_a_chain_goal(),
            steps=[_a_chain_step()],
            eval_result=_a_fail_eval_result(),
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
            goal=_a_chain_goal(),
            steps=[_a_chain_step()],
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
        goals = [_a_chain_goal(), _a_chain_goal(description="second goal")]
        batch = ChainPlanBatch(chains=goals)

        assert len(batch.chains) == 2
        assert batch.chains[1].description == "second goal"


def _a_chain_goal(
    description: str = "Probe then exploit path traversal",
) -> ChainGoal:
    return ChainGoal(
        description=description,
        category=AuditCategory.INJECTION,
        first_step=AuditPayload(
            tool_name="get_file",
            category=AuditCategory.INJECTION,
            description="Initial probe",
            arguments={"path": "/etc/passwd"},
        ),
    )


def _a_chain_step(
    response: str | None = "file not found",
    observation: str = "Error reveals path validation",
) -> ChainStep:
    return ChainStep(
        payload=AuditPayload(
            tool_name="get_file",
            category=AuditCategory.INJECTION,
            description="probe",
            arguments={"path": "/etc/passwd"},
        ),
        response=response,
        observation=observation,
    )


def _a_fail_eval_result() -> EvalResult:
    return EvalResult(
        tool_name="t",
        category=AuditCategory.INJECTION,
        payload={"path": "/etc/passwd"},
        verdict=EvalVerdict.FAIL,
        justification="path traversal succeeded",
        severity=Severity.HIGH,
    )


def _a_payload(**overrides: Any) -> AuditPayload:
    defaults: dict[str, Any] = {
        "tool_name": "test_tool",
        "category": AuditCategory.INPUT_VALIDATION,
        "description": "test payload",
        "arguments": {},
    }
    return AuditPayload(**(defaults | overrides))
