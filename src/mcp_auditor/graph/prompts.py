import json
from typing import Any

from mcp_auditor.domain.models import AuditCategory, TestCase


def build_attack_generation_prompt(
    tool_name: str,
    tool_description: str,
    input_schema: dict[str, Any],
    budget: int,
    categories: list[AuditCategory],
) -> str:
    category_list = "\n".join(f"- {c.value}" for c in categories)
    schema_json = json.dumps(input_schema, indent=2)

    return f"""You are a security auditor for MCP (Model Context Protocol) tool servers.

Your task: generate exactly {budget} test cases for the tool "{tool_name}".

Tool description: {tool_description}

Input schema:
```json
{schema_json}
```

Distribute test cases across these attack categories:
{category_list}

For each test case, provide:
- tool_name: the name of the tool to call
- category: one of the categories listed above
- description: what this test case verifies
- arguments: a dictionary of arguments matching the input schema, crafted as adversarial payloads

Focus on MCP-specific risks:
- Prompt injection through tool arguments
- Information leakage via error messages
- Resource abuse through crafted inputs
- Input validation bypasses

Consider the input schema when designing relevant payloads."""


def build_judge_prompt(
    tool_name: str,
    tool_description: str,
    test_case: TestCase,
) -> str:
    outcome_section = _format_outcome(test_case)

    return f"""You are a security evaluator for MCP tool servers.

Your task: evaluate the result of a security test against the tool "{tool_name}".

Tool description: {tool_description}

Test case description: {test_case.payload.description}

Attack payload arguments: {json.dumps(test_case.payload.arguments)}

{outcome_section}

Decide whether the tool's behavior represents a security concern:
- PASS: the tool handled the adversarial input safely
- FAIL: the tool exhibited unsafe behavior

Be strict about:
- Information leakage (stack traces, internal paths, database details)
- Injection vulnerabilities (arguments reflected unsanitized in outputs)

Provide a justification and severity (low, medium, high, critical)."""


def _format_outcome(test_case: TestCase) -> str:
    parts: list[str] = []
    if test_case.response is not None:
        response_text = (
            json.dumps(test_case.response)
            if isinstance(test_case.response, dict)
            else str(test_case.response)
        )
        parts.append(f"Tool response:\n{response_text}")
    if test_case.error is not None:
        parts.append(f"Tool error:\n{test_case.error}")
    if not parts:
        parts.append("The tool produced no response and no error.")
    return "\n\n".join(parts)
