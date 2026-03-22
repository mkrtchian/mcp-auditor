from typing import Any

from mcp_auditor.domain import AuditCategory, AuditPayload, TestCase, ToolDefinition
from mcp_auditor.graph.prompts import (
    build_attack_generation_prompt,
    build_judge_prompt,
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


class TestAttackGenerationPrompt:
    def test_includes_tool_name(self):
        prompt = build_attack_generation_prompt(
            tool=_a_tool(input_schema={"type": "object"}),
            budget=5,
            categories=[AuditCategory.INJECTION],
        )

        assert "get_user" in prompt

    def test_includes_schema(self):
        schema = {"type": "object", "properties": {"id": {"type": "integer"}}}

        prompt = build_attack_generation_prompt(
            tool=_a_tool(input_schema=schema),
            budget=5,
            categories=[AuditCategory.INJECTION],
        )

        assert "integer" in prompt

    def test_includes_all_categories(self):
        all_categories = list(AuditCategory)

        prompt = build_attack_generation_prompt(
            tool=_a_tool(),
            budget=10,
            categories=all_categories,
        )

        for category in all_categories:
            assert category.value in prompt

    def test_includes_budget(self):
        prompt = build_attack_generation_prompt(
            tool=_a_tool(),
            budget=10,
            categories=[AuditCategory.INJECTION],
        )

        assert "10" in prompt


class TestJudgePrompt:
    def test_includes_response(self):
        test_case = _a_test_case(response="tool output here")

        prompt = build_judge_prompt(tool=_a_tool(), test_case=test_case)

        assert "tool output here" in prompt

    def test_includes_error_when_present(self):
        test_case = _a_test_case(error="connection refused")

        prompt = build_judge_prompt(tool=_a_tool(), test_case=test_case)

        assert "connection refused" in prompt

    def test_includes_payload_description(self):
        test_case = _a_test_case(
            description="SQL injection via id param",
        )

        prompt = build_judge_prompt(tool=_a_tool(), test_case=test_case)

        assert "SQL injection via id param" in prompt

    def test_includes_category_guidance(self):
        test_case = _a_test_case()

        prompt = build_judge_prompt(tool=_a_tool(), test_case=test_case)

        assert "User input is executed as code" in prompt

    def test_fallback_when_no_response_and_no_error(self):
        test_case = _a_test_case(response=None, error=None)

        prompt = build_judge_prompt(tool=_a_tool(), test_case=test_case)

        assert "no response and no error" in prompt


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
