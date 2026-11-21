import tests.unit.auditor.support.test_shown_response_then as shown_then
from mcp_auditor.domain import AttackChain, AttackContext, AuditCategory
from mcp_auditor.domain.category_guidance import CATEGORY_GUIDANCE
from mcp_auditor.graph.chain_prompts import (
    RESPONSE_SNIPPET_LENGTH,
    build_chain_judge_prompt,
    build_chain_planning_prompt,
    build_step_observation_prompt,
    build_step_planning_prompt,
)
from mcp_auditor.graph.prompts import (
    JUDGING_RULES,
    NON_DESTRUCTIVE_CONSTRAINT,
    build_judge_prompt,
    format_attack_context,
)
from tests.unit.auditor.support.chain_states import a_chain_goal, a_chain_step, a_tool
from tests.unit.auditor.support.test_chain_nodes_given import (
    a_blocked_single_step_case,
    a_single_step_case,
)
from tests.unit.auditor.support.test_shown_response_given import a_long_text


class TestChainPlanningPrompt:
    def test_includes_tool_name(self):
        prompt = build_chain_planning_prompt(
            tool=a_tool(name="get_file"),
            single_step_cases=[],
            attack_context=AttackContext(),
            chain_budget=3,
        )

        assert "get_file" in prompt

    def test_includes_single_step_summary(self):
        cases = [a_single_step_case(response="sqlite3.OperationalError")]

        prompt = build_chain_planning_prompt(
            tool=a_tool(),
            single_step_cases=cases,
            attack_context=AttackContext(),
            chain_budget=3,
        )

        assert "sqlite3.OperationalError" in prompt

    def test_includes_attack_context_when_non_empty(self):
        prompt = build_chain_planning_prompt(
            tool=a_tool(),
            single_step_cases=[],
            attack_context=AttackContext(db_engine="sqlite"),
            chain_budget=3,
        )

        assert "sqlite" in prompt

    def test_omits_attack_context_when_empty(self):
        prompt = build_chain_planning_prompt(
            tool=a_tool(),
            single_step_cases=[],
            attack_context=AttackContext(),
            chain_budget=3,
        )

        attack_context_header = format_attack_context(
            AttackContext(db_engine="sqlite")
        ).splitlines()[0]
        assert attack_context_header not in prompt

    def test_carries_the_non_destructive_constraint(self):
        prompt = build_chain_planning_prompt(
            tool=a_tool(),
            single_step_cases=[],
            attack_context=AttackContext(),
            chain_budget=3,
        )

        assert NON_DESTRUCTIVE_CONSTRAINT in prompt

    def test_omits_blocked_case_from_summary(self):
        cases = [a_single_step_case(response="ok"), a_blocked_single_step_case()]

        prompt = build_chain_planning_prompt(
            tool=a_tool(),
            single_step_cases=cases,
            attack_context=AttackContext(),
            chain_budget=3,
        )

        assert "Case 1" in prompt
        assert "Case 2" not in prompt

    def test_bounds_each_error_and_keeps_the_response_snippet(self):
        response, error = a_long_text("response"), a_long_text("error")
        cases = [a_single_step_case(response=response, error=error)]

        prompt = build_chain_planning_prompt(
            tool=a_tool(),
            single_step_cases=cases,
            attack_context=AttackContext(),
            chain_budget=3,
        )

        assert f"Response: {response[:RESPONSE_SNIPPET_LENGTH]}..." in prompt
        shown_then.shows_cut(prompt, error)

    def test_includes_chain_budget(self):
        prompt = build_chain_planning_prompt(
            tool=a_tool(),
            single_step_cases=[],
            attack_context=AttackContext(),
            chain_budget=17,
        )

        assert "17" in prompt


class TestStepPlanningPrompt:
    def test_includes_goal_description(self):
        goal = a_chain_goal(description="Discover internal paths then traverse")

        prompt = build_step_planning_prompt(
            tool=a_tool(),
            goal=goal,
            chain_history=[],
            observation_hint="",
        )

        assert "Discover internal paths then traverse" in prompt

    def test_carries_the_non_destructive_constraint(self):
        prompt = build_step_planning_prompt(
            tool=a_tool(),
            goal=a_chain_goal(),
            chain_history=[],
            observation_hint="",
        )

        assert NON_DESTRUCTIVE_CONSTRAINT in prompt

    def test_includes_chain_history(self):
        steps = [a_chain_step(response="file not found: /var/data")]

        prompt = build_step_planning_prompt(
            tool=a_tool(),
            goal=a_chain_goal(),
            chain_history=steps,
            observation_hint="",
        )

        assert "file not found: /var/data" in prompt

    def test_bounds_the_response_and_the_error_of_each_step(self):
        response, error = a_long_text("response"), a_long_text("error")

        prompt = build_step_planning_prompt(
            tool=a_tool(),
            goal=a_chain_goal(),
            chain_history=[a_chain_step(response=response, error=error)],
            observation_hint="",
        )

        shown_then.shows_cut(prompt, response)
        shown_then.shows_cut(prompt, error)

    def test_includes_observation_hint(self):
        prompt = build_step_planning_prompt(
            tool=a_tool(),
            goal=a_chain_goal(),
            chain_history=[a_chain_step()],
            observation_hint="Try path traversal from /var/data",
        )

        assert "Try path traversal from /var/data" in prompt


class TestStepObservationPrompt:
    def test_includes_goal_description(self):
        goal = a_chain_goal(description="Explore error paths")

        prompt = build_step_observation_prompt(
            tool=a_tool(),
            goal=goal,
            chain_steps=[a_chain_step(response="internal error at /opt/app")],
        )

        assert "Explore error paths" in prompt

    def test_includes_latest_response(self):
        prompt = build_step_observation_prompt(
            tool=a_tool(),
            goal=a_chain_goal(),
            chain_steps=[a_chain_step(response="sqlite3.OperationalError: table users")],
        )

        assert "sqlite3.OperationalError: table users" in prompt

    def test_includes_latest_error(self):
        prompt = build_step_observation_prompt(
            tool=a_tool(),
            goal=a_chain_goal(),
            chain_steps=[a_chain_step(response=None, error="connection refused")],
        )

        assert "connection refused" in prompt

    def test_bounds_the_response_and_the_error_of_the_history_and_the_latest_step(self):
        texts = [a_long_text(label) for label in ("r1", "e1", "r2", "e2")]
        steps = [
            a_chain_step(response=texts[0], error=texts[1]),
            a_chain_step(response=texts[2], error=texts[3]),
        ]

        prompt = build_step_observation_prompt(
            tool=a_tool(),
            goal=a_chain_goal(),
            chain_steps=steps,
        )

        for text in texts:
            shown_then.shows_cut(prompt, text)

    def test_includes_chain_history(self):
        steps = [
            a_chain_step(observation="Revealed internal path /var/data"),
            a_chain_step(response="new response"),
        ]

        prompt = build_step_observation_prompt(
            tool=a_tool(),
            goal=a_chain_goal(),
            chain_steps=steps,
        )

        assert "Revealed internal path /var/data" in prompt


class TestChainJudgePrompt:
    def test_includes_tool_name(self):
        chain = AttackChain(
            goal=a_chain_goal(),
            steps=[a_chain_step()],
        )

        prompt = build_chain_judge_prompt(
            tool=a_tool(name="get_file"),
            chain=chain,
        )

        assert "get_file" in prompt

    def test_includes_full_chain_steps(self):
        steps = [
            a_chain_step(response="path /var/data revealed"),
            a_chain_step(response="traversal succeeded: root:x:0:0"),
        ]
        chain = AttackChain(goal=a_chain_goal(), steps=steps)

        prompt = build_chain_judge_prompt(tool=a_tool(), chain=chain)

        assert "path /var/data revealed" in prompt
        assert "traversal succeeded: root:x:0:0" in prompt

    def test_bounds_the_response_and_the_error_of_each_step(self):
        response, error = a_long_text("response"), a_long_text("error")
        chain = AttackChain(
            goal=a_chain_goal(), steps=[a_chain_step(response=response, error=error)]
        )

        prompt = build_chain_judge_prompt(tool=a_tool(), chain=chain)

        shown_then.shows_cut(prompt, response)
        shown_then.shows_cut(prompt, error)

    def test_includes_the_guidance_of_the_target_category(self):
        chain = AttackChain(
            goal=a_chain_goal(category=AuditCategory.INFO_LEAKAGE),
            steps=[a_chain_step()],
        )

        prompt = build_chain_judge_prompt(tool=a_tool(), chain=chain)

        assert CATEGORY_GUIDANCE[AuditCategory.INFO_LEAKAGE] in prompt

    def test_states_the_same_rules_as_the_single_call_judge(self):
        chain = AttackChain(goal=a_chain_goal(), steps=[a_chain_step()])
        single_call_case = a_single_step_case()

        chain_prompt = build_chain_judge_prompt(tool=a_tool(), chain=chain)
        single_call_prompt = build_judge_prompt(tool=a_tool(), test_case=single_call_case)

        assert JUDGING_RULES in chain_prompt
        assert JUDGING_RULES in single_call_prompt
