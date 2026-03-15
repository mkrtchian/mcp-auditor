# ADR 001: Why LangGraph

**Date:** 2026-03-15
**Status:** Accepted

## Context
`mcp-auditor` needs to orchestrate a multi-step async workflow: discover MCP tools, generate attack payloads via LLM, execute them, judge responses via LLM, loop over test cases and tools, then produce a report. Could a simple async loop do this?

## Decision
Use LangGraph as the orchestration framework.

## Rationale

**Checkpointing.** An audit of 10 tools × 10 tests = ~110 LLM calls (10 generation + 100 judgement — execution is MCP-only, no LLM). If the process crashes or hits a rate limit at tool 8, we need to resume without re-executing (and re-paying for) tools 1-7. Building durable checkpointing from scratch — serialize state after each node, persist to disk, resume from the right point with the right state — is significant custom code. LangGraph provides this out of the box via pluggable checkpointers. We use `AsyncSqliteSaver` from `langgraph-checkpoint-sqlite` to persist graph state after each node. Resume is a one-liner with the same `thread_id`.

**Observability via LangSmith.** LangGraph integrates natively with LangSmith, which traces every node execution, LLM call, and state transition automatically. For an agentic tool where debugging means understanding what prompt was sent, what the LLM returned, and how long each step took across 100+ calls, this is hard to replicate with hand-rolled logging.

**Declarative routing.** The audit workflow has non-trivial control flow: conditional branching (retry or move on?), looping over tools and test cases, routing based on results. With LangGraph, this control flow is expressed as a graph — visible, testable, and self-documenting. In a plain async loop, the same logic is scattered across nested `if/else` and `while` blocks.

## Trade-offs
- **Framework coupling.** LangGraph imposes its own model of state, nodes, and edges. Nodes must conform to `(state) -> state_update` signatures. This constrains how we structure code and adds cognitive overhead for contributors unfamiliar with the framework.
- **Evolving API.** LangGraph's API is still maturing — breaking changes between minor versions are possible. Pinning versions mitigates this but doesn't eliminate upgrade friction.
- **Overhead for simple paths.** For the happy path (no crashes, no retries), a plain async loop would be simpler and faster to write. The framework earns its keep primarily in failure/resume scenarios and as the workflow grows in complexity.
- **Debugging indirection.** When something goes wrong inside the graph, stack traces go through LangGraph internals. This can make debugging harder than stepping through a plain function.

## Alternatives considered
- **Plain async loop**: Simpler and faster to build initially, but checkpointing, observability, and declarative routing would all need to be built from scratch. The break-even point is low given the workflow complexity.

## Future considerations
- **Human-in-the-loop.** LangGraph supports natively interrupting the graph and resuming after user input. If `mcp-auditor` adds an interactive mode (e.g., confirming before executing a potentially destructive test), this is trivial to implement. With a plain loop, it would require a significant redesign.
- **Parallel fan-out.** Auditing multiple tools in parallel while maintaining state consistency. LangGraph's fan-out/fan-in patterns handle this natively.
