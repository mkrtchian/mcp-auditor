"""Tests for domain model validation and behavior.

Only tests that validate OUR design choices — enum constraints, union types,
custom methods, serialization of non-trivial types. Does not test that
Pydantic constructors work or that Python lists hold items.
"""

from typing import Any

import pytest

from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    EvalResult,
    EvalVerdict,
    TestCase,
    TokenUsage,
    ToolDefinition,
)


def _a_payload(**overrides: Any) -> AuditPayload:
    defaults: dict[str, Any] = {
        "tool_name": "test_tool",
        "category": AuditCategory.INPUT_VALIDATION,
        "description": "test payload",
        "arguments": {},
    }
    return AuditPayload(**(defaults | overrides))


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
