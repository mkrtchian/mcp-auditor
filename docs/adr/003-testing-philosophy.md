# ADR 003: Testing Philosophy

**Date:** 2026-03-15
**Status:** Accepted

## Context
`mcp-auditor` contains three fundamentally different types of logic that require different validation strategies:
- **In-process deterministic code**: orchestration, routing, state transitions, prompt construction, report formatting.
- **Adapter integration**: does our `StdioMCPClient` actually communicate correctly with a real MCP server? Deterministic too, but requires an external process.
- **Non-deterministic AI**: quality of LLM-generated attack payloads, accuracy of LLM-as-a-judge verdicts.

Conflating them leads to untested adapters (assuming the SDK just works), false confidence (fakes pretending to validate AI quality), or slow/expensive test suites (calling real LLMs in CI).

## Decision
Three levels of testing, each with its own scope, cost, and execution context. The investment follows the testing pyramid: extensive unit tests on observable behavior (fast, free, high coverage), a thin layer of integration tests for adapter correctness (real MCP server, no LLM), and targeted evals against a ground truth with clear acceptance criteria (recall ≥ 80%, precision 100%) rather than high volume.

### Unit tests (`tests/unit/`) — validate code
Fast, free, in-process. Use fakes (`FakeLLM`, `FakeMCPClient`), no external calls. Run in CI on every push.

What they cover:
- **Prompt construction**: `build_attack_generation_prompt()` and `build_judge_prompt()` are pure functions. Tests verify they include the right information (tool name, schema, categories, payload, response).
- **Graph orchestration**: with `FakeLLM` returning canned responses, verify routing, state accumulation, loop counts, error handling.
- **Routing logic**: `test_case_router` and `tool_router` make correct decisions based on state.
- **Category distribution check**: post-generation verification logic.
- **Models**: Pydantic validation, serialization, edge cases.
- **Report formatting**: Markdown and JSON output from known `test_results`.

What they do NOT cover: the quality of LLM responses. A `FakeLLM` returns whatever it's configured to return regardless of the prompt. This is by design — it tests that the graph handles responses correctly, not that the responses are good.

**Why fakes, not mocks:** mocks (`MagicMock`) verify *how* code calls dependencies — tests become coupled to implementation details and break on refactors. Fakes *behave* like real dependencies without side effects (network, cost, non-determinism). Tests assert on observable outputs (state, results), not on call sequences.

### Integration tests (`tests/integration/`) — validate the MCP adapter
Verify that `StdioMCPClient` communicates correctly with a real MCP server process. No LLM involved. Run in CI on every push.

What they cover:
- Launch the honeypot server, connect the real `StdioMCPClient`, verify `list_tools()` and `call_tool()` with known payloads.
- Verify that vulnerable tools return exploitable errors and that the healthy tool returns clean responses.
- Catch regressions in adapter code or MCP SDK compatibility.

Note: the `LLMPort` adapter (`AnthropicLLM`) is not integration-tested separately — its correctness is validated indirectly by evals, which exercise the full pipeline including real LLM calls.

### Evals (`evals/`) — validate prompt quality
Run the full system (real prompts + real LLM + real MCP server) against the honeypot and measure output quality against a ground truth. Non-deterministic, cost API tokens, run on demand (not in CI).

What they measure:
- **Recall**: does the judge detect known flaws?
- **Precision**: does the judge flag false positives on the healthy tool?
- **Consistency**: are verdicts stable across multiple runs?
- **Distribution**: do generated tests cover all categories?

Evals are the feedback loop for iterating on prompts.

## Trade-offs
- **Evals are expensive and manual.** They cost API tokens and cannot run in CI by default. There is a gap between "unit tests pass" and "the tool works well" that only surfaces when evals are explicitly run.
- **Integration tests need a server process.** They are slower than unit tests and require the honeypot to be available. A broken honeypot blocks CI.
- **Fakes require maintenance** when ports change. But since ports are stable Protocol classes with few methods, this is rare.
- **No integration test for `AnthropicLLM`.** We rely on evals to catch adapter issues. If evals aren't run regularly, a broken LLM adapter could go unnoticed.
