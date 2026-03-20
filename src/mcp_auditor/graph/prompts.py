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

IMPORTANT — test design guidance per category:

- info_leakage: Probe what the tool reveals in BOTH success and error responses. For error-path leakage: use non-existent IDs, boundary values, or invalid inputs to trigger verbose errors that might expose file paths, DB schemas, or stack traces. For response-path leakage: use NORMAL, VALID inputs that are likely to return actual data — common first names (Alice, Bob, John), small IDs (1, 2, 3), common categories — and check if the response includes internal fields like emails, roles, internal IDs, or infrastructure details. Always include at least one normal-use test case — info leakage often hides in successful responses, not just errors.

- input_validation: Test with values that match the EXPECTED TYPE but are semantically invalid. For integer fields: zero, negative numbers, extremely large values — test zero specifically as it's a common boundary error. For string fields: empty strings, whitespace-only strings. Do NOT send wrong types (e.g., a string for an integer field) — the framework's schema validation catches type mismatches before the tool logic runs, making such tests uninformative.

- injection: Craft payloads that attempt SQL injection, command injection, or code execution through the tool's arguments. Use the tool's expected input types.

- error_handling: Trigger predictable error conditions — not-found IDs, invalid formats, boundary violations — and check whether the tool exposes raw exceptions or internal details.

- resource_abuse: Craft inputs designed to cause unbounded resource consumption — extremely large limits, wildcard queries, cross-joins.

Always send arguments that conform to the schema's type constraints. The goal is to test the TOOL's logic, not the schema validator."""


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
- The tool accepts clearly invalid input without rejecting OR normalizing it (e.g., negative IDs used as-is, wrong types, out-of-range values processed verbatim)
- Missing boundary checks that allow nonsensical operations
- An error that merely echoes back the raw input value (e.g., error: "0", error: "-1") without a descriptive validation message — this is a raw unhandled exception, not proper input validation. Compare: "0" (raw exception) vs. "user_id must be positive" (proper validation).
What does NOT count:
- The tool crashes on bad input (that's error_handling)
- The tool processes input through its core function (that's injection, not input_validation). A tool whose purpose is to accept and forward text (SQL queries, search terms, commands) is NOT failing input_validation by accepting that text — even if it's empty, malformed, or adversarial. Example: a SQL execution tool accepting an empty string query and returning results is NOT an input_validation failure — executing queries is what the tool does.
- The tool silently clamps or normalizes out-of-range values to a safe range. Clamping IS valid input handling — the tool does not need to reject the request as long as the invalid value does not reach downstream logic. Example: if limit=-1 and the response shows "showing 1", the tool clamped the negative value to 1 — that is NOT an input_validation failure.
- A text-search or lookup tool treating user input as a literal search term (not as code or commands) is working correctly. Receiving a SQL/injection payload as a search query and returning "no results" is NOT an input_validation failure — the tool correctly treated the input as data.""",
    "error_handling": """What counts as error_handling failure:
- Unhandled exceptions (raw KeyError, ValueError, TypeError surfaced to the caller)
- Missing graceful error responses for predictable failure modes (e.g., not-found, invalid format)
What does NOT count:
- Clean, structured error messages (e.g., "Invalid category", "ID must be between 1 and 1000")
- The tool successfully processing input and returning a result — even if the response contains suspicious content like internal paths or metadata. If the tool returned a success response, there was no error to handle. Sensitive data in a success response is info_leakage, NOT error_handling.
- The tool returning the input value as-is is NOT safe error handling if it indicates an unhandled exception
- A tool that passes input through to a backend system (e.g., SQL engine, API) is not required to pre-validate the input's syntax. If the tool's purpose is to forward queries, silently processing malformed input is expected behavior, not an error_handling failure.
- A tool accepting edge-case inputs (negative IDs, empty strings) and returning a success response is NOT an error_handling failure — that's input_validation (if it should have rejected them) but the tool did not crash or produce an unhandled exception.""",
    "resource_abuse": """What counts as resource_abuse:
- The tool allows unbounded resource consumption (unlimited memory, CPU, disk, network) — e.g., returning millions of rows, loading unbounded data into memory
- No size caps on operations that could grow without limit
What does NOT count:
- The tool capping or limiting results (that's proper mitigation)
- Other vulnerabilities like path leaks or injection (those are different categories)
- Single-item operations (delete one record, look up one user, execute one query that returns a fixed number of rows). These are inherently bounded and do NOT require rate limiting to pass.
- The absence of rate limiting alone is NOT resource_abuse unless the tool performs an operation that can consume unbounded resources in a single call.""",
}


def build_judge_prompt(
    tool: ToolDefinition,
    test_case: TestCase,
) -> str:
    outcome_section = _format_outcome(test_case)

    category = test_case.payload.category
    category_guidance = _CATEGORY_GUIDANCE.get(category, "")

    return f"""You are a security evaluator for MCP tool servers.

Your task: evaluate whether the tool "{tool.name}" has a **{category}** vulnerability based on the ACTUAL BEHAVIOR observed in this test result.

IMPORTANT RULES:
1. You are evaluating ONLY the "{category}" category. Even if you notice other security issues (e.g., information leakage when testing for injection), you must judge ONLY whether a {category} problem exists.
2. Base your verdict ONLY on what the tool actually did (the response/error below), NOT on what the test description expected to happen. The test description is just context — the tool's actual behavior is the evidence.
3. Consider the tool's stated purpose. A tool designed to execute queries, search text, or delete records is expected to do those things. Performing its core function is not a vulnerability.

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
