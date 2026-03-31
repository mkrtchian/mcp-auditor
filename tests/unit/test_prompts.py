import tests.unit.support.test_prompts_given as given
from mcp_auditor.domain import AttackContext, AuditCategory
from mcp_auditor.graph.prompts import (
    build_attack_generation_prompt,
    build_context_extraction_prompt,
    build_judge_prompt,
    format_attack_context,
)


class TestAttackGenerationPrompt:
    def test_includes_tool_name(self):
        prompt = build_attack_generation_prompt(
            tool=given.a_tool(input_schema={"type": "object"}),
            budget=5,
            categories=[AuditCategory.INJECTION],
        )

        assert "get_user" in prompt

    def test_includes_schema(self):
        schema = {"type": "object", "properties": {"id": {"type": "integer"}}}

        prompt = build_attack_generation_prompt(
            tool=given.a_tool(input_schema=schema),
            budget=5,
            categories=[AuditCategory.INJECTION],
        )

        assert "integer" in prompt

    def test_includes_all_categories(self):
        all_categories = list(AuditCategory)

        prompt = build_attack_generation_prompt(
            tool=given.a_tool(),
            budget=10,
            categories=all_categories,
        )

        for category in all_categories:
            assert category.value in prompt

    def test_includes_budget(self):
        prompt = build_attack_generation_prompt(
            tool=given.a_tool(),
            budget=10,
            categories=[AuditCategory.INJECTION],
        )

        assert "10" in prompt

    def test_includes_attack_context_when_provided(self):
        prompt = build_attack_generation_prompt(
            tool=given.a_tool(),
            budget=5,
            categories=[AuditCategory.INJECTION],
            attack_context=AttackContext(db_engine="sqlite"),
        )

        assert "sqlite" in prompt

    def test_omits_attack_context_when_none(self):
        prompt = build_attack_generation_prompt(
            tool=given.a_tool(),
            budget=5,
            categories=[AuditCategory.INJECTION],
        )

        assert "Previous tool audits" not in prompt

    def test_omits_attack_context_when_empty(self):
        prompt = build_attack_generation_prompt(
            tool=given.a_tool(),
            budget=5,
            categories=[AuditCategory.INJECTION],
            attack_context=AttackContext(),
        )

        assert "Previous tool audits" not in prompt


class TestFormatAttackContext:
    def test_empty_context_returns_empty_string(self):
        assert format_attack_context(AttackContext()) == ""

    def test_context_with_db_engine(self):
        result = format_attack_context(AttackContext(db_engine="sqlite"))

        assert "sqlite" in result

    def test_context_with_multiple_fields(self):
        result = format_attack_context(
            AttackContext(
                db_engine="postgresql",
                framework="django",
                exposed_internals=["/opt/app/db.sqlite3"],
            )
        )

        assert "postgresql" in result
        assert "django" in result
        assert "/opt/app/db.sqlite3" in result


class TestContextExtractionPrompt:
    def test_includes_tool_name(self):
        report = given.a_tool_report(tool_name="get_user")

        prompt = build_context_extraction_prompt(report, AttackContext())

        assert "get_user" in prompt

    def test_includes_response_content(self):
        report = given.a_tool_report(response="sqlite3.OperationalError: no such table")

        prompt = build_context_extraction_prompt(report, AttackContext())

        assert "sqlite3.OperationalError" in prompt

    def test_includes_existing_context_when_non_empty(self):
        existing = AttackContext(db_engine="sqlite")

        prompt = build_context_extraction_prompt(given.a_tool_report(), existing)

        assert "sqlite" in prompt

    def test_omits_existing_context_when_empty(self):
        prompt = build_context_extraction_prompt(given.a_tool_report(), AttackContext())

        assert "What we already know" not in prompt


class TestJudgePrompt:
    def test_includes_response(self):
        test_case = given.a_test_case(response="tool output here")

        prompt = build_judge_prompt(tool=given.a_tool(), test_case=test_case)

        assert "tool output here" in prompt

    def test_includes_error_when_present(self):
        test_case = given.a_test_case(error="connection refused")

        prompt = build_judge_prompt(tool=given.a_tool(), test_case=test_case)

        assert "connection refused" in prompt

    def test_includes_payload_description(self):
        test_case = given.a_test_case(
            description="SQL injection via id param",
        )

        prompt = build_judge_prompt(tool=given.a_tool(), test_case=test_case)

        assert "SQL injection via id param" in prompt

    def test_includes_category_guidance(self):
        test_case = given.a_test_case()

        prompt = build_judge_prompt(tool=given.a_tool(), test_case=test_case)

        assert "User input is executed as code" in prompt

    def test_fallback_when_no_response_and_no_error(self):
        test_case = given.a_test_case(response=None, error=None)

        prompt = build_judge_prompt(tool=given.a_tool(), test_case=test_case)

        assert "no response and no error" in prompt
