from typing import Any

from mcp_auditor.domain import (
    AttackChain,
    AttackContext,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainStep,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    ToolDefinition,
)
from mcp_auditor.graph.chain_prompts import (
    build_chain_judge_prompt,
    build_chain_planning_prompt,
    build_step_observation_prompt,
    build_step_planning_prompt,
)


def _a_tool(
    name: str = "get_user",
    description: str = "Fetch user by ID",
    input_schema: dict[str, Any] | None = None,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=input_schema or {},
    )


def _a_chain_goal(
    description: str = "Probe error messages to discover internal paths, then traverse",
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
    response: str | None = "file not found: /var/data",
    error: str | None = None,
    observation: str = "Revealed internal path /var/data",
) -> ChainStep:
    return ChainStep(
        payload=AuditPayload(
            tool_name="get_file",
            category=AuditCategory.INJECTION,
            description="probe",
            arguments={"path": "/etc/passwd"},
        ),
        response=response,
        error=error,
        observation=observation,
    )


def _a_single_step_case(
    response: str = "sqlite3.OperationalError",
    verdict: EvalVerdict = EvalVerdict.FAIL,
) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            tool_name="get_user",
            category=AuditCategory.INJECTION,
            description="SQL injection probe",
            arguments={"id": "1 OR 1=1"},
        ),
        response=response,
        eval_result=EvalResult(
            tool_name="get_user",
            category=AuditCategory.INJECTION,
            payload={"id": "1 OR 1=1"},
            verdict=verdict,
            justification="vulnerable",
            severity=Severity.HIGH,
        ),
    )


class TestChainPlanningPrompt:
    def test_includes_tool_name(self):
        prompt = build_chain_planning_prompt(
            tool=_a_tool(name="get_file"),
            single_step_cases=[],
            attack_context=AttackContext(),
            chain_budget=3,
        )

        assert "get_file" in prompt

    def test_includes_single_step_summary(self):
        cases = [_a_single_step_case(response="sqlite3.OperationalError")]

        prompt = build_chain_planning_prompt(
            tool=_a_tool(),
            single_step_cases=cases,
            attack_context=AttackContext(),
            chain_budget=3,
        )

        assert "sqlite3.OperationalError" in prompt

    def test_includes_attack_context_when_non_empty(self):
        prompt = build_chain_planning_prompt(
            tool=_a_tool(),
            single_step_cases=[],
            attack_context=AttackContext(db_engine="sqlite"),
            chain_budget=3,
        )

        assert "sqlite" in prompt

    def test_omits_attack_context_when_empty(self):
        prompt = build_chain_planning_prompt(
            tool=_a_tool(),
            single_step_cases=[],
            attack_context=AttackContext(),
            chain_budget=3,
        )

        assert "Previous tool audits" not in prompt

    def test_includes_chain_budget(self):
        prompt = build_chain_planning_prompt(
            tool=_a_tool(),
            single_step_cases=[],
            attack_context=AttackContext(),
            chain_budget=5,
        )

        assert "5" in prompt


class TestStepPlanningPrompt:
    def test_includes_goal_description(self):
        goal = _a_chain_goal(description="Discover internal paths then traverse")

        prompt = build_step_planning_prompt(
            tool=_a_tool(),
            goal=goal,
            chain_history=[],
            observation_hint="",
        )

        assert "Discover internal paths then traverse" in prompt

    def test_includes_chain_history(self):
        steps = [_a_chain_step(response="file not found: /var/data")]

        prompt = build_step_planning_prompt(
            tool=_a_tool(),
            goal=_a_chain_goal(),
            chain_history=steps,
            observation_hint="",
        )

        assert "file not found: /var/data" in prompt

    def test_includes_observation_hint(self):
        prompt = build_step_planning_prompt(
            tool=_a_tool(),
            goal=_a_chain_goal(),
            chain_history=[_a_chain_step()],
            observation_hint="Try path traversal from /var/data",
        )

        assert "Try path traversal from /var/data" in prompt


class TestStepObservationPrompt:
    def test_includes_goal_description(self):
        goal = _a_chain_goal(description="Explore error paths")

        prompt = build_step_observation_prompt(
            tool=_a_tool(),
            goal=goal,
            chain_history=[],
            latest_response="internal error at /opt/app",
            latest_error=None,
        )

        assert "Explore error paths" in prompt

    def test_includes_latest_response(self):
        prompt = build_step_observation_prompt(
            tool=_a_tool(),
            goal=_a_chain_goal(),
            chain_history=[],
            latest_response="sqlite3.OperationalError: table users",
            latest_error=None,
        )

        assert "sqlite3.OperationalError: table users" in prompt

    def test_includes_latest_error(self):
        prompt = build_step_observation_prompt(
            tool=_a_tool(),
            goal=_a_chain_goal(),
            chain_history=[],
            latest_response=None,
            latest_error="connection refused",
        )

        assert "connection refused" in prompt

    def test_includes_chain_history(self):
        steps = [_a_chain_step(observation="Revealed internal path /var/data")]

        prompt = build_step_observation_prompt(
            tool=_a_tool(),
            goal=_a_chain_goal(),
            chain_history=steps,
            latest_response="new response",
            latest_error=None,
        )

        assert "Revealed internal path /var/data" in prompt


class TestChainJudgePrompt:
    def test_includes_tool_name(self):
        chain = AttackChain(
            goal=_a_chain_goal(),
            steps=[_a_chain_step()],
        )

        prompt = build_chain_judge_prompt(
            tool=_a_tool(name="get_file"),
            chain=chain,
        )

        assert "get_file" in prompt

    def test_includes_full_chain_steps(self):
        steps = [
            _a_chain_step(response="path /var/data revealed"),
            _a_chain_step(response="traversal succeeded: root:x:0:0"),
        ]
        chain = AttackChain(goal=_a_chain_goal(), steps=steps)

        prompt = build_chain_judge_prompt(tool=_a_tool(), chain=chain)

        assert "path /var/data revealed" in prompt
        assert "traversal succeeded: root:x:0:0" in prompt

    def test_asks_for_verdict(self):
        chain = AttackChain(
            goal=_a_chain_goal(),
            steps=[_a_chain_step()],
        )

        prompt = build_chain_judge_prompt(tool=_a_tool(), chain=chain)

        assert "FAIL" in prompt
        assert "PASS" in prompt
