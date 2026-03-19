import json

from mcp_auditor.domain.models import AuditCategory, TestCase, ToolDefinition


def build_attack_generation_prompt(
    tool: ToolDefinition,
    budget: int,
    categories: list[AuditCategory],
) -> str:
    category_list = "\n".join(f"- {c.value}" for c in categories)
    schema_json = json.dumps(tool.input_schema, indent=2)

    return f"""You are a security auditor for MCP (Model Context Protocol) tool servers.

Your task: generate exactly {budget} test cases for the tool "{tool.name}".

Tool description: {tool.description}

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


_CATEGORY_GUIDANCE: dict[str, str] = {
    "info_leakage": """What counts as info_leakage:
- Stack traces, internal file paths, database connection strings, or server configuration exposed in responses or errors
- PII (emails, roles, internal identifiers) returned when not required by the tool's purpose
What does NOT count:
- Documentation paths (e.g., /help/api-guide) or user-facing URLs
- Generic error messages that reveal no internal structure""",
    "injection": """What counts as injection:
- User input is executed as code, SQL, or commands (e.g., SQL injection, command injection)
- User input is reflected unsanitized in a way that could alter execution
What does NOT count:
- The tool echoing input in an error message (that's error_handling or info_leakage, not injection)""",
    "input_validation": """What counts as input_validation failure:
- The tool accepts clearly invalid input without rejecting it (e.g., negative IDs, wrong types, out-of-range values)
- Missing boundary checks that allow nonsensical operations
What does NOT count:
- The tool crashes on bad input (that's error_handling)
- The tool processes a malicious payload that exploits its core function (that's injection, not input_validation). For example, a SQL execution tool accepting SQL is not an input_validation failure even if the SQL is malicious.""",
    "error_handling": """What counts as error_handling failure:
- Unhandled exceptions (raw KeyError, ValueError, TypeError surfaced to the caller)
- Missing graceful error responses for predictable failure modes (e.g., not-found, invalid format)
What does NOT count:
- Clean, structured error messages (e.g., "Invalid category", "ID must be between 1 and 1000")
- The tool successfully processing input and returning a result (even if the input was malicious — that's injection, not error_handling)
- The tool returning the input value as-is is NOT safe error handling if it indicates an unhandled exception""",
    "resource_abuse": """What counts as resource_abuse:
- The tool allows unbounded resource consumption (unlimited memory, CPU, disk, network)
- No rate limiting, size caps, or timeout protections
What does NOT count:
- The tool capping or limiting results (that's proper mitigation)
- Other vulnerabilities like path leaks or injection (those are different categories)""",
}


def build_judge_prompt(
    tool: ToolDefinition,
    test_case: TestCase,
) -> str:
    outcome_section = _format_outcome(test_case)

    category = test_case.payload.category
    category_guidance = _CATEGORY_GUIDANCE.get(category, "")

    return f"""You are a security evaluator for MCP tool servers.

Your task: evaluate whether the tool "{tool.name}" has a **{category}** vulnerability based on this test result.

IMPORTANT: You are evaluating ONLY the "{category}" category. Even if you notice other security issues (e.g., information leakage when testing for injection), you must judge ONLY whether a {category} problem exists.

Tool description: {tool.description}

Test category: {category}
{category_guidance}

Test case description: {test_case.payload.description}

Attack payload arguments: {json.dumps(test_case.payload.arguments)}

{outcome_section}

Decide:
- FAIL: the tool exhibited a **{category}** vulnerability
- PASS: no {category} problem detected (even if other issues exist)

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
