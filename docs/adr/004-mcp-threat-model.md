# ADR 004: MCP-Specific Threat Model

**Date:** 2026-03-15
**Status:** Accepted

## Context
`mcp-auditor` needs audit categories to structure test generation and reporting. The categories must be specific to the MCP threat surface — not a generic checklist.

Unlike a traditional API called by deterministic code, an MCP server is called by an LLM client whose inputs are hard to predict and whose error interpretation is non-deterministic. This creates a specific risk profile:
- The LLM may send semantically invalid inputs that pass schema validation but break server logic.
- Unhandled errors are interpreted by the LLM, leading to unpredictable downstream behavior.
- An attacker can use prompt injection to make the LLM send malicious payloads to the server on their behalf.

## Decision
Define 5 audit categories targeting the most likely MCP-specific failure modes for an MVP:

### INPUT_VALIDATION
Does the server validate types, ranges, and formats declared in its `inputSchema`? MCP tools declare a JSON Schema for their inputs — but the server may not actually enforce it. An LLM client could send values that match the schema type but are semantically invalid (negative IDs, empty strings where non-empty is expected).

### ERROR_HANDLING
Does the server handle error cases gracefully? In the MCP context, an unhandled exception typically surfaces as a raw error in the tool response. A well-behaved server should return structured error content, not crash. This matters because the LLM client will attempt to interpret the error — garbage in means unpredictable behavior. Note: a single failure (e.g., an unhandled exception with a stack trace) can be both an ERROR_HANDLING and an INFO_LEAKAGE finding — the categories are not mutually exclusive.

### INJECTION
Is the server vulnerable to injection via string parameters? MCP tools can accept free-text inputs that end up in SQL queries, shell commands, or file paths on the server side. Classic injection vectors (SQL injection, path traversal, command injection) apply here. In the MCP context, the attack vector is indirect: an attacker crafts a prompt that causes the LLM to send a malicious payload to the server.

### INFO_LEAKAGE
Do error responses leak internal information? A server that exposes filesystem paths, library versions, database structure, or stack traces in its error messages gives an LLM client (or an attacker controlling the LLM) information to craft more targeted attacks. A well-behaved server returns generic error messages without internal details.

### RESOURCE_ABUSE
Does the server handle out-of-bounds payloads? Strings of 1MB, numbers at int64 limits, deeply nested objects. An LLM client — whether buggy or manipulated via prompt injection — could send oversized payloads. The server should reject them gracefully, not hang or crash.

## Why these 5 and not others?

The categories were selected by asking: **what can go wrong when an LLM calls a tool?** Each category maps to a distinct failure mode observable from the client side (which is all `mcp-auditor` can see — it's a black-box auditor):

| Category | Failure mode | Observable signal |
|---|---|---|
| INPUT_VALIDATION | Server doesn't enforce its own schema | Unexpected success or wrong behavior on invalid input |
| ERROR_HANDLING | Server crashes or returns raw errors | Stack traces, unstructured error messages |
| INJECTION | Server executes unsanitized input | Evidence of command/query execution in response |
| INFO_LEAKAGE | Server exposes internals in errors | File paths, versions, DB structure in error messages |
| RESOURCE_ABUSE | Server hangs or crashes on large payloads | Timeout, out-of-memory, or no response |

### Categories considered and deferred

- **ACCESS_CONTROL** (does a tool access resources outside its intended scope?): relevant but hard to test black-box — the auditor can't know what a tool *should* access. Partially covered by INJECTION (path traversal). Better suited to a future white-box analysis mode.
- **AUTHENTICATION / AUTHORIZATION**: MCP servers accessed via stdio run as local processes — auth is typically handled at the OS level, not the protocol level. Relevant for future HTTP/SSE transport support.
- **RATE_LIMITING**: a server-level concern, not specific to the tool interface `mcp-auditor` tests.

### Why 5?

Pragmatic constraint. With a default budget of 10 tests per tool, 5 categories allow at least 2 tests per category. Fewer categories would miss coverage; more would spread the budget too thin. The prompt requests at least 2 tests per category, but LLMs don't count reliably — actual distribution is verified post-generation and logged as a warning if skewed, without re-generating (cost trade-off).

## Trade-offs
- **Breadth over depth.** 2 tests per category is thin for any single threat. The trade-off is deliberate: for an automated first-pass audit, broad coverage is more valuable than exhaustive testing of one vector. Users can increase `--budget` for deeper audits.
- **Black-box only.** All categories are designed to be testable from the client side. This means some threats (e.g., access control violations that don't surface in the response) are invisible to `mcp-auditor`.
- **Opinionated selection.** Some MCP servers may have threat surfaces not covered here. The roadmap includes extensibility for custom categories.
