# ADR 009: Cross-Tool Learning

**Date:** 2026-03-23
**Status:** Accepted

## Context

The audit graph processes tools sequentially but statelessly — the generator for tool B receives the same information as for tool A: the tool definition, the budget, and the category list. It doesn't know that tool A's errors exposed `sqlite3.OperationalError`, that file paths under `/opt/mcp-server/` leaked in responses, or that error-path probing was particularly effective.

A human pentester accumulates this intelligence naturally. After probing `get_user` and seeing SQLite errors, they would immediately target `execute_query` with SQLite-specific injection syntax rather than generic SQL. The current graph cannot do this.

This is also the first feature where LangGraph's value goes beyond orchestration (ADR 001). A plain async loop could pass an `attack_context` variable between iterations just as easily. But with LangGraph, the accumulated context is checkpointed (survives crashes mid-audit) and traced in LangSmith (each tool's context delta is visible as a node output). These are operational benefits, not expressiveness ones — but they matter for a tool that runs 100+ LLM calls per audit.

## Decision

Add cross-tool learning via three changes:

1. **Tool ordering** — a deterministic heuristic that runs read-like tools first.
2. **Context extraction** — a new LLM node after each tool audit that synthesizes intelligence from the results.
3. **Context-aware generation** — the generation prompt receives accumulated context and adapts payloads.

### Tool ordering

A pure function `order_tools_for_audit(tools) -> tools` applied after discovery. Read-like tools (prefixes: `get_`, `list_`, `read_`, `search_`, `find_`, `fetch_`, `show_`, `describe_`, `check_`) sort before others. Tie-break by ascending parameter count (fewer params = simpler to probe). Stable within groups.

Read-like tools are better first because they reveal system internals (database engine, internal fields, path structure) without side effects. Write/execute tools benefit most from this intelligence.

### Context extraction

A new `extract_attack_context` node in the main graph, between `finalize_tool_audit` and the tool routing edge. It calls the LLM with the just-completed `ToolReport` and the existing `AttackContext`, and returns an enriched context.

The extraction is **per-tool, not per-execution**. The injection point for context is the generation prompt, and generation happens once per tool (batch). Intra-tool learning (adapting payloads between executions of the same tool) would require changing the batch-then-execute model to an interleaved generate/execute loop — a separate, larger architectural change.

### Context model

`AttackContext` is a lightly structured Pydantic model: a few typed fields for high-value, recurrent signals (database engine, framework, exposed paths) plus a free-text field for the long tail. The LLM fills what it can infer; everything defaults to empty. This hybrid gives testability on the common signals without rigidity — see "Structured context with rigid schema" in alternatives.

### Context merging

The extraction prompt instructs the LLM to return a *merged* context (existing + new), not a delta. Merging is a semantic operation, not a mechanical one — if tool A exposes `sqlite3.OperationalError` and tool B mentions `database.yml` referencing PostgreSQL, the merge must interpret whether these are two backends or a misread. Code-level merge (list concatenation, field overwrite) cannot make this judgment. The risk of the LLM dropping previous findings is mitigated by explicit prompt instructions ("preserve all previous findings") and by the context being small (a handful of fields).

## Alternatives considered

### How to extract context

#### Deterministic extraction (regex-based)

Pattern matching on responses for known signatures: `sqlite3.OperationalError` → SQLite, `Traceback (most recent call last)` → Python, file paths in errors. This is free in tokens and predictable.

**Rejected** because the most valuable signals are semantic inferences — "this server doesn't validate input boundaries, so sibling tools probably don't either" — that regex cannot capture. The LLM catches both syntactic patterns (which it recognizes as well as regex) and semantic ones, in a single call. A hybrid approach (deterministic + LLM) would cover both, but maintaining two extraction paths adds complexity without proportional value — the LLM already handles the syntactic patterns that regex would catch.

#### Merging extraction into the generation call

Instead of a separate extraction call, pass previous `ToolReport`s into the generation prompt and let the generator both learn and generate in one call.

**Rejected** because it conflates two responsibilities: backward-looking (what did we learn?) and forward-looking (what do we test?). The generation prompt is already complex (budget, categories, per-category guidance). Adding extraction makes it harder to test, harder to debug when distribution is skewed (is it the context or the base prompt?), and harder to evolve independently. A separate small call is cheap and keeps concerns clean.

### When to extract

#### Per-execution context update (intra-tool learning)

Update context after each test case execution, not just after each tool. Would allow later test cases within the same tool to adapt based on earlier responses.

**Rejected for now** because the current architecture generates all test cases in batch before execution starts. Intra-tool learning requires an interleaved generate/execute model — a different architectural change. Cross-tool learning is the natural fit for the current batch model and delivers value without restructuring the subgraph. The two features are complementary, not competing.

### Whether to order tools

#### No ordering

Keep discovery order (server-defined). Rely on the LLM to extract value regardless of which tool runs first.

**Rejected** because ordering is a pure function with zero cost that meaningfully improves context quality. A `delete_user` tool probed first reveals less about the system than `get_user`. The heuristic has minor limitations — it relies on naming conventions that may not always reflect actual behavior (e.g., `get_auth_token` sounds read-like but might create a token), and renaming a tool changes audit order — but the expected value is clearly positive for the common case.

### How to structure the context

#### Rigid schema (many typed fields)

A fully typed model with fields for every conceivable signal (OS, auth mechanism, rate limiting behavior, etc.).

**Rejected** because over-constraining the schema makes it rigid and forces frequent model updates as we discover new signal types. The hybrid approach (few typed fields + free-text) captures the common cases precisely and the long tail flexibly.

## Consequences

- **Cost**: one additional LLM call per tool for extraction. With a budget of 10, each tool costs 1 generation + 10 judgments + 1 extraction = 12 calls, so the extraction adds ~8% overhead. The calls are small (input: tool report, output: lightweight structured model).
- **Latency**: one additional round-trip per tool, sequential. Not parallelizable since each extraction depends on the previous context.
- **Tool order becomes intentional**: tools are no longer audited in server-defined order. This is observable in reports (tool order may differ from `list_tools` order). The ordering function is deterministic and testable.
- **First tool is unaffected**: the first tool audited receives no context, identical behavior to today. The feature's value scales with the number of tools.
- **Context is unbounded initially**: no cap on `exposed_internals` or `observations` size. For typical servers (5-10 tools) this is fine. If servers with many tools cause prompt bloat, a summarization step can be added later without changing the architecture.
- **Testability**: the extraction node is tested in isolation with `FakeLLM`. The ordering function is a pure function tested with unit tests. The generation prompt's context section is tested by asserting on prompt content.
- **Eval validation**: the existing honeypot (`dummy_server.py`) already has the ideal scenario — `get_user` leaks SQLite errors, `execute_query` is vulnerable to injection. Cross-tool learning is validated indirectly via existing recall/precision metrics. No new honeypot needed.
