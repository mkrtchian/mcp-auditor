from mcp_auditor.domain import AuditCategory, AuditPayload, TestCase
from mcp_auditor.graph.prompts import (
    build_attack_generation_prompt,
    build_judge_prompt,
)


class TestAttackGenerationPrompt:
    def test_includes_tool_name(self):
        prompt = build_attack_generation_prompt(
            tool_name="get_user",
            tool_description="Fetch user by ID",
            input_schema={"type": "object"},
            budget=5,
            categories=[AuditCategory.INJECTION],
        )

        assert "get_user" in prompt

    def test_includes_schema(self):
        schema = {"type": "object", "properties": {"id": {"type": "integer"}}}

        prompt = build_attack_generation_prompt(
            tool_name="t",
            tool_description="d",
            input_schema=schema,
            budget=5,
            categories=[AuditCategory.INJECTION],
        )

        assert "integer" in prompt

    def test_includes_all_categories(self):
        all_categories = list(AuditCategory)

        prompt = build_attack_generation_prompt(
            tool_name="t",
            tool_description="d",
            input_schema={},
            budget=10,
            categories=all_categories,
        )

        for category in all_categories:
            assert category.value in prompt

    def test_includes_budget(self):
        prompt = build_attack_generation_prompt(
            tool_name="t",
            tool_description="d",
            input_schema={},
            budget=10,
            categories=[AuditCategory.INJECTION],
        )

        assert "10" in prompt


class TestJudgePrompt:
    def test_includes_response(self):
        test_case = _a_test_case(response="tool output here")

        prompt = build_judge_prompt(
            tool_name="get_user",
            tool_description="Fetch user by ID",
            test_case=test_case,
        )

        assert "tool output here" in prompt

    def test_includes_error_when_present(self):
        test_case = _a_test_case(error="connection refused")

        prompt = build_judge_prompt(
            tool_name="get_user",
            tool_description="Fetch user by ID",
            test_case=test_case,
        )

        assert "connection refused" in prompt

    def test_includes_payload_description(self):
        test_case = _a_test_case(
            description="SQL injection via id param",
        )

        prompt = build_judge_prompt(
            tool_name="get_user",
            tool_description="Fetch user by ID",
            test_case=test_case,
        )

        assert "SQL injection via id param" in prompt


def _a_test_case(
    description: str = "test description",
    response: str | None = None,
    error: str | None = None,
) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            tool_name="get_user",
            category=AuditCategory.INJECTION,
            description=description,
            arguments={"id": "1 OR 1=1"},
        ),
        response=response,
        error=error,
    )
