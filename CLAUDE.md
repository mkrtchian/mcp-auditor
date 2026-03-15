# mcp-auditor

Agentic QA & fuzzing CLI for MCP servers, built with LangGraph.

## Commands

```bash
uv run pytest                    # Unit + integration tests
uv run pytest tests/unit         # Unit tests only
uv run pytest tests/integration  # Integration tests only (needs dummy server)
uv run ruff check .              # Lint
uv run ruff format .             # Format
uv run pyright                   # Type check (strict mode)
```

## Architecture

Hexagonal architecture. See `docs/adr/002-hexagonal-architecture.md` for rationale.

```
src/mcp_auditor/
├── domain/     Pydantic models, Protocol ports. No dependencies on infra or frameworks.
├── graph/      LangGraph state, nodes (via factory functions), prompts (pure functions), builder.
├── infra/      Adapters: StdioMCPClient, AnthropicLLM, fakes for tests.
└── cli.py      Entry point. Manages adapter lifecycle, builds graph, runs it.
```

- **Ports** (`domain/`): `MCPClientPort` and `LLMPort` are `Protocol` classes. The graph depends only on these.
- **Adapters** (`infra/`): Implement ports. `StdioMCPClient` wraps the MCP SDK. `AnthropicLLM` wraps LangChain's `ChatAnthropic`.
- **Fakes** (`infra/`): `FakeLLM` and `FakeMCPClient` — deterministic, configurable per test. Not mocks.
- **Nodes** (`graph/`): Built via factory functions (`make_node(port)`) for dependency injection. Prompts are pure functions in `graph/prompts.py`.

## Conventions

- Python 3.13+, strict typing. Pyright in strict mode.
- Prompts are pure functions `(data) -> str` in `graph/prompts.py`. They are domain logic, not infra.
- Three levels of tests (see ADR 003): unit tests validate code (fakes, in-process), integration tests validate the MCP adapter (real server, no LLM), evals (`evals/`) validate prompt quality on a ground truth honeypot. Never test LLM quality with fakes.
- Pydantic models for all structured data. `BaseModel`, not dataclasses.
- Async throughout. Nodes are async functions.

## Documentation

- `docs/adr/` — Architecture Decision Records. Explain *why*, not *how*.
- `plans/` — Spec-driven-dev plans for each feature increment. `plans/init.md` is the global skeleton (gitignored).
