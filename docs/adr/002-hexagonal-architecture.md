# ADR 002: Hexagonal Architecture

**Date:** 2026-03-15
**Status:** Accepted

## Context
`mcp-auditor` depends on two external systems: an MCP server (via the MCP SDK) and an LLM API (via LangChain/Anthropic initially). Both are slow, costly, and non-deterministic (for the LLM). The graph logic — routing, state management, prompt construction, report formatting — is deterministic and should be testable without calling either.

## Decision
Use hexagonal architecture (ports and adapters) with two main secondary ports:
- `MCPClientPort`: abstracts MCP server interactions.
- `LLMPort`: abstracts LLM calls (generic structured output).

Ports are `Protocol` classes in `domain/`. Adapters live in `infra/`. Fakes (`FakeLLM`, `FakeMCPClient`) implement the ports with deterministic behavior for unit tests — they are real in-memory objects, not `MagicMock`. See ADR 003 for the full testing philosophy.

### Generic port, not domain-aware

The prompts — what to test, how to judge — are part the core domain logic of mcp-auditor. The question is: who owns them, the graph nodes or the LLM adapter?

**Option A (rejected): domain-aware port.** The port exposes domain-specific methods like `generate_test_cases(tool_schema)` and `judge_response(test_case, response)`. Each method builds the prompt internally, calls the LLM, and returns parsed results. Graph nodes become trivial pass-throughs with no visible logic. Prompts are buried in infra, hard to test and hard to iterate on.

**Option B (chosen): generic port.** The `LLMPort` exposes a single method: `generate_structured(prompt, output_schema) -> BaseModel`. It knows nothing about the domain — it just sends text and parses the response. Graph nodes build the prompts themselves (via pure functions in `graph/prompts.py`), then pass them to the port. The port abstracts *which model* answers and infrastructure concerns, not *what question* is asked.

### MCP client lifecycle: adapter's responsibility

The `MCPClientPort` only exposes business operations (`list_tools`, `call_tool`). It has no `connect()` or `close()` — the port assumes the connection is already established.

Connection lifecycle is the adapter's responsibility. The `StdioMCPClient` adapter exposes an async context manager (`async with StdioMCPClient.connect(cmd, args) as client:`) that the CLI manages. Graph nodes receive an already-connected client.

Implementation detail: the MCP Python SDK uses two nested context managers (`stdio_client` for the transport, then `ClientSession` for the protocol session). The adapter encapsulates both behind a single context manager.

### Dependency injection via closures

**The problem:** LangGraph nodes must be functions with signature `(state) -> state_update`. But our nodes need access to ports (`LLMPort`, `MCPClientPort`). We can't put ports in the state — they're not serializable. So how do nodes get their dependencies?

**The solution: factory functions (closures).** A factory takes the port as argument and returns the node function. The node "closes over" the port — it captures it from the enclosing scope.

```python
# Factory: takes the port, returns the node
def make_generate_test_cases(llm: LLMPort):
    # Node: has access to `llm` via closure
    async def generate_test_cases(state: GraphState) -> dict:
        prompt = build_attack_generation_prompt(...)
        batch = await llm.generate_structured(prompt, TestCaseBatch)
        return {"pending_test_cases": [...]}
    return generate_test_cases

# At graph build time:
builder.add_node("generate_test_cases", make_generate_test_cases(llm))

# In tests, just pass a fake:
builder.add_node("generate_test_cases", make_generate_test_cases(FakeLLM()))
```

**Why not RunnableConfig?** LangGraph offers an alternative where dependencies are passed via `config["configurable"]["llm"]` at invoke time. We chose closures because: (1) `config["configurable"]` is `dict[str, Any]` — with pyright strict, every access requires a cast and a missing dependency is a runtime error, not a type error; (2) the graph is built once per CLI invocation, so runtime swapping adds no value. If closures conflict with LangGraph's compilation constraints, RunnableConfig is a viable fallback.

## Trade-offs
- **More indirection.** A request flows through port → adapter → SDK. More files, more layers to navigate to follow a single execution path.
- **Boilerplate.** Protocols, factory functions, fakes — all need to be written and maintained alongside the real adapters. For a project with only 2 ports, this is a non-trivial ratio of infrastructure code to business logic.
- **Over-engineering risk.** A CLI tool with 2 external dependencies could work fine with direct calls. The hexagonal structure only pays off if we actually test through it.

We accept these costs because this project is developed with AI-assisted coding (Claude Code). The agent generates boilerplate fast — the marginal cost of Protocols, factories, and fakes is low. What's expensive is debugging non-deterministic failures in production-like code. Exhaustive unit tests of business logic, made possible by the port/fake boundary, catch issues that would otherwise only surface during real LLM calls.
