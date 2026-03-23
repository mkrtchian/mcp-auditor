# Shared by both attack generation and judge prompts in graph/prompts.py.
# Changes here affect how test cases are generated AND how results are evaluated.
from mcp_auditor.domain.models import AuditCategory

CATEGORY_GUIDANCE: dict[AuditCategory, str] = {
    AuditCategory.INFO_LEAKAGE: """What counts as info_leakage:
- Stack traces, internal file paths, database connection strings, or server configuration exposed in responses or errors
- PII (emails, roles, internal identifiers) returned when not required by the tool's purpose
What does NOT count:
- Documentation paths (e.g., /help/api-guide) or user-facing URLs
- Generic error messages that reveal no internal structure""",
    AuditCategory.INJECTION: """What counts as injection:
- User input is executed as code, SQL, or commands (e.g., SQL injection, command injection)
- User input is reflected unsanitized in a way that could alter execution
What does NOT count:
- The tool echoing input in an error message (that's error_handling or info_leakage, not injection)""",
    AuditCategory.INPUT_VALIDATION: """What counts as input_validation failure:
- The tool accepts clearly invalid input without rejecting OR normalizing it (e.g., negative IDs used as-is, wrong types, out-of-range values processed verbatim)
- Missing boundary checks that allow nonsensical operations
- An error that merely echoes back the raw input value (e.g., error: "0", error: "-1") without a descriptive validation message — this is a raw unhandled exception, not proper input validation. Compare: "0" (raw exception) vs. "user_id must be positive" (proper validation).
What does NOT count:
- The tool crashes on bad input (that's error_handling)
- The tool processes input through its core function (that's injection, not input_validation). A tool whose purpose is to accept and forward text (SQL queries, search terms, commands) is NOT failing input_validation by accepting that text — even if it's empty, malformed, or adversarial. Example: a SQL execution tool accepting an empty string query and returning results is NOT an input_validation failure — executing queries is what the tool does.
- The tool silently clamps or normalizes out-of-range values to a safe range. Clamping IS valid input handling — the tool does not need to reject the request as long as the invalid value does not reach downstream logic. Example: if limit=-1 and the response shows "showing 1", the tool clamped the negative value to 1 — that is NOT an input_validation failure.
- A text-search or lookup tool treating user input as a literal search term (not as code or commands) is working correctly. Receiving a SQL/injection payload as a search query and returning "no results" is NOT an input_validation failure — the tool correctly treated the input as data.""",
    AuditCategory.ERROR_HANDLING: """What counts as error_handling failure:
- Unhandled exceptions (raw KeyError, ValueError, TypeError surfaced to the caller)
- Missing graceful error responses for predictable failure modes (e.g., not-found, invalid format)
What does NOT count:
- Clean, structured error messages (e.g., "Invalid category", "ID must be between 1 and 1000")
- The tool successfully processing input and returning a result — even if the response contains suspicious content like internal paths or metadata. If the tool returned a success response, there was no error to handle. Sensitive data in a success response is info_leakage, NOT error_handling.
- The tool returning the input value as-is is NOT safe error handling if it indicates an unhandled exception
- A tool that passes input through to a backend system (e.g., SQL engine, API) is not required to pre-validate the input's syntax. If the tool's purpose is to forward queries, silently processing malformed input is expected behavior, not an error_handling failure.
- A tool accepting edge-case inputs (negative IDs, empty strings) and returning a success response is NOT an error_handling failure — that's input_validation (if it should have rejected them) but the tool did not crash or produce an unhandled exception.""",
    AuditCategory.RESOURCE_ABUSE: """What counts as resource_abuse:
- The tool allows unbounded resource consumption (unlimited memory, CPU, disk, network) — e.g., returning millions of rows, loading unbounded data into memory
- No size caps on operations that could grow without limit
What does NOT count:
- The tool capping or limiting results (that's proper mitigation)
- Other vulnerabilities like path leaks or injection (those are different categories)
- Single-item operations (delete one record, look up one user, execute one query that returns a fixed number of rows). These are inherently bounded and do NOT require rate limiting to pass.
- The absence of rate limiting alone is NOT resource_abuse unless the tool performs an operation that can consume unbounded resources in a single call.""",
}
