# ADR 008: OWASP MCP Top 10 Mapping

**Date:** 2026-03-22
**Status:** Accepted

## Context

The OWASP MCP Top 10 is a published project providing industry-standard threat classification for MCP servers. mcp-auditor uses 5 internal audit categories (ADR 004). Mapping findings to OWASP codes adds credibility and aligns reports with a recognized taxonomy.

This is pass 1: enrich rendering only. No new categories, no prompt changes, no model changes, no new test logic.

## Decision

### Mapping table

| AuditCategory      | OWASP MCP Code | OWASP Title                          |
|---------------------|----------------|--------------------------------------|
| `injection`         | MCP-05         | Command Injection & Execution        |
| `info_leakage`      | MCP-10         | Context Injection & Over-Sharing     |
| `resource_abuse`    | —              | No honest mapping                    |
| `input_validation`  | —              | No single OWASP mapping              |
| `error_handling`    | —              | No single OWASP mapping              |

`resource_abuse` (oversized payloads, unbounded consumption) does not map to MCP-02 (Privilege Escalation via Scope Creep) — these are different threats. Better to leave it unmapped than force a misleading correspondence.

`input_validation` and `error_handling` are cross-cutting concerns that can contribute to multiple OWASP categories depending on context. Pass 2 will introduce new categories with direct OWASP mappings.

### Render-time derivation, not stored field

The OWASP code is a pure derivation of `AuditCategory` — `INJECTION` always maps to `MCP-05`, with no exceptions. Storing it on `EvalResult` would create a field that can be inconsistent with `category` and would require changes to the model, the node layer, and deserialization — all for zero semantic gain. Instead, renderers call `owasp_label_for(category)` or `owasp_id_for(category)` at display time. The mapping is domain knowledge (lives in `domain/owasp.py`), the display is a presentation concern.

Markdown headings use the full label (`injection / MCP-05: Command Injection & Execution`) because headings have room. Console lines use the code only (`injection / MCP-05`) because console lines are space-constrained. JSON output includes an `owasp` object (`{"code": "MCP-05", "title": "..."}`) on eval results with a mapped category — injected at render time via `_inject_owasp_into_json`, not stored on the model.

## Consequences

- Markdown, console, and JSON output show OWASP codes for mapped categories automatically.
- Unmapped categories display exactly as before — no regressions.
- When pass 2 adds new `AuditCategory` values with OWASP mappings, only `OWASP_BY_CATEGORY` needs an entry. The mapping functions handle missing keys by returning `None`.
