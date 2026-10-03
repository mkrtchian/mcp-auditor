import json

from mcp_auditor.domain.category_guidance import CATEGORY_GUIDANCE
from mcp_auditor.domain.models import (
    AttackContext,
    AuditCategory,
    TestCase,
    ToolDefinition,
    ToolReport,
)

NON_DESTRUCTIVE_CONSTRAINT = """NON-DESTRUCTIVE PAYLOADS. This applies to every payload you generate:
- Never destroy state and never affect host availability: no deleting or overwriting files, no DROP, TRUNCATE or DELETE FROM, no recursive permission change, no disk or raw-device write (mkfs, dd of=, truncate -s), no forced version-control write, no shutdown, reboot, poweroff, runlevel change or kill of PID 1, no fork bomb.
- To prove an injection landed, prefer evidence of what it reaches: read something whose disclosure would matter, a credential or configuration file (`.env`, `~/.ssh/id_rsa`, a cloud credential directory), the process environment (`env`), a path the tool's own arguments already reach. Quote the value that came back.
- When nothing worth reading is in reach, a reflected marker still proves the injection ran: `echo mcp-auditor-probe`, `id`, `whoami`, `SELECT` / `UNION SELECT` rather than DDL or DML. It proves execution, not impact.
- A destructive payload proves nothing more than a benign marker does, and it corrupts the rest of the audit."""


REDACTION_NOTICE = (
    "REDACTED VALUES. A marker such as `[value of NAME, redacted by mcp-auditor]` stands for a value "
    "the server returned: mcp-auditor replaced the value of the environment variable NAME before "
    "showing you the output. Read the marker as that value."
)


def with_redaction_notice(prompt: str) -> str:
    return f"{prompt}\n\n{REDACTION_NOTICE}"


def format_tool_header(tool: ToolDefinition) -> str:
    description = tool.description or "No description provided"
    schema_json = json.dumps(tool.input_schema, indent=2)
    return f"Tool description: {description}\n\nInput schema:\n```json\n{schema_json}\n```"


def build_attack_generation_prompt(
    tool: ToolDefinition,
    budget: int,
    categories: list[AuditCategory],
    attack_context: AttackContext | None = None,
) -> str:
    category_list = "\n".join(f"- {c.value}" for c in categories)
    tool_header = format_tool_header(tool)
    context_section = build_context_section(attack_context)

    return f"""You are a security auditor for MCP (Model Context Protocol) tool servers.

Your task: generate exactly {budget} test cases for the tool "{tool.name}".

{tool_header}

Distribute test cases across these attack categories:
{category_list}

For each test case, provide:
- category: one of the categories listed above
- description: what this test case verifies
- arguments: a dictionary of arguments matching the input schema, crafted as adversarial payloads

IMPORTANT — test design guidance per category:

- info_leakage: Probe what the tool reveals in BOTH success and error responses. You MUST include both kinds of test: (1) Error-path leakage: use non-existent IDs, boundary values, or invalid inputs to trigger verbose errors that might expose file paths, DB schemas, or stack traces. (2) Response-path leakage: use NORMAL, VALID inputs that are most likely to return actual data — use a common first name for name searches, small IDs (1, 2, 3), common categories — and check if the response includes internal fields like emails, roles, internal IDs, or infrastructure details. If you have 2+ test cases for info_leakage, one MUST be error-path and one MUST be response-path.

- input_validation: Test with values that match the EXPECTED TYPE but are semantically invalid. For integer fields: zero, negative numbers and values beyond any plausible limit, the classic boundary values. For string fields: empty strings, whitespace-only strings. Do NOT send wrong types (e.g., a string for an integer field) — the framework's schema validation catches type mismatches before the tool logic runs, making such tests uninformative.

- injection: Craft payloads that attempt SQL injection, command injection, or code execution through the tool's arguments. Use the tool's expected input types. Prove execution with evidence that comes back in the response: a reflected marker returned as command output, or a query result.

- error_handling: Trigger predictable error conditions — not-found IDs, invalid formats, boundary violations — and check whether the tool exposes raw exceptions or internal details.

- resource_abuse: Craft inputs designed to cause unbounded resource consumption: limits or counts beyond any plausible bound, wildcard queries, cross-joins.

Keep every literal short. An integer beyond any plausible limit needs at most 10 digits (2^31 already has 10). A string argument stays under 1,000 characters. A string longer than a few dozen characters is composed from varied text, such as numbered segments (`seg-01-seg-02-...`), never from one character repeated. Resource exhaustion is probed by what the argument asks the tool to do, not by the size of the argument itself.
{context_section}
{NON_DESTRUCTIVE_CONSTRAINT}

Always send arguments that conform to the schema's type constraints. The goal is to test the TOOL's logic, not the schema validator."""


def build_context_section(attack_context: AttackContext | None) -> str:
    if attack_context is None:
        return ""
    rendered = format_attack_context(attack_context)
    if not rendered:
        return ""
    return f"\n{rendered}\n"


def format_attack_context(context: AttackContext) -> str:
    if context.is_empty:
        return ""
    lines = ["Previous tool audits revealed the following about this server:"]
    if context.db_engine is not None:
        lines.append(f"- Database engine: {context.db_engine}")
    if context.framework is not None:
        lines.append(f"- Framework: {context.framework}")
    if context.language is not None:
        lines.append(f"- Language: {context.language}")
    if context.exposed_internals:
        lines.append(f"- Exposed internals: {', '.join(context.exposed_internals)}")
    if context.effective_payloads:
        lines.append(f"- Effective patterns: {', '.join(context.effective_payloads)}")
    if context.observations:
        lines.append(f"- Observations: {context.observations}")
    lines.append("")
    lines.append(
        "Use this intelligence to craft more targeted payloads. "
        "For example, if the server uses SQLite, use SQLite-specific "
        "injection syntax rather than generic SQL."
    )
    return "\n".join(lines)


def build_context_extraction_prompt(
    tool_report: ToolReport,
    existing_context: AttackContext,
) -> str:
    tool = tool_report.tool
    description = tool.description or "No description provided"

    cases_section = _format_cases_for_extraction(tool_report) or "No test results available."
    existing_section = _format_existing_context(existing_context)

    return f"""You are analyzing the results of a security audit on the MCP tool "{tool.name}".

Tool description: {description}

Test results:
{cases_section}
{existing_section}
Extract any intelligence about the server from these results. Look for:
- Database engine (e.g., if you see sqlite3.OperationalError, set db_engine to "sqlite")
- Framework or language hints (e.g., Python tracebacks, Express.js error formats)
- Exposed internal details (file paths, table names, config keys)
- Which attack patterns were effective
- Any other observations about the server's behavior

Preserve all previous findings and add new ones. Do not lose information from earlier audits."""


def _format_cases_for_extraction(tool_report: ToolReport) -> str:
    parts: list[str] = []
    for i, case in enumerate(tool_report.cases, 1):
        if case.blocked_reason is not None:
            continue
        lines = [f"Case {i}: {case.payload.description}"]
        if case.response is not None:
            response_text = (
                json.dumps(case.response) if isinstance(case.response, dict) else str(case.response)
            )
            lines.append(f"  Response: {response_text}")
        if case.error is not None:
            lines.append(f"  Error: {case.error}")
        if case.eval_result is not None:
            lines.append(f"  Verdict: {case.eval_result.verdict}")
            lines.append(f"  Justification: {case.eval_result.justification}")
        parts.append("\n".join(lines))
    return "\n\n".join(parts)


def _format_existing_context(existing_context: AttackContext) -> str:
    rendered = format_attack_context(existing_context)
    if not rendered:
        return ""
    return f"\nWhat we already know:\n{rendered}\n"


def build_judge_prompt(
    tool: ToolDefinition,
    test_case: TestCase,
) -> str:
    outcome_section = _format_outcome(test_case)

    category = test_case.payload.category
    category_guidance = CATEGORY_GUIDANCE.get(category, "")

    description = tool.description or "No description provided"

    return f"""You are a security evaluator for MCP tool servers.

Your task: evaluate whether the tool "{tool.name}" has a **{category}** vulnerability based on the ACTUAL BEHAVIOR observed in this test result.

IMPORTANT RULES:
1. You are evaluating ONLY the "{category}" category. Even if you notice other security issues (e.g., information leakage when testing for injection), you must judge ONLY whether a {category} problem exists.
2. Base your verdict ONLY on what the tool actually did (the response/error below), NOT on what the test description expected to happen. The test description is just context — the tool's actual behavior is the evidence.
3. Consider the tool's stated purpose. A tool is expected to do what its description says it does. Performing its core function is not a vulnerability.

Tool description: {description}

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
