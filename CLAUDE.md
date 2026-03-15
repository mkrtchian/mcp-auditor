# mcp-auditor

## Commands

```bash
uv run pytest                    # Unit + integration tests
uv run pytest tests/unit         # Unit tests only
uv run pytest tests/integration  # Integration tests only
uv run ruff check .              # Lint
uv run ruff format .             # Format
uv run pyright                   # Type check (strict mode)
```

## Coding standards

- Code in the style of **Kent Beck**, **Martin Fowler**, **Robert C. Martin**, **Eric Evans** — the XP, software craftsmanship, and DDD tradition.
- Prompts are **domain logic**, not infra. They live in `graph/prompts.py` as pure functions `(data) -> str`. Never put prompt construction in adapters.
- Graph nodes are built via **factory functions** (`make_node(port)`) for dependency injection. Ports are `Protocol` classes in `domain/`.
- All code, comments, docstrings, and identifiers in **English**.
- **Newspaper rule** (Clean Code): read a module top-to-bottom like an article. Public/high-level functions first, private/low-level helpers right below their callers.
- Functions should rarely exceed **20 lines**, files should rarely exceed **300 lines**. When they do, split.
- **Naming over comments.** Code should read without them. Reserve comments for non-obvious logic, hacks, or workarounds. Use **domain-relevant, readable names** — no abbreviations except in very short scopes (e.g. comprehensions).

## Testing standards

- Test **behavior**, not implementation. Tests assert on observable outcomes, never on internal structure or call sequences.
- Unit tests are exhaustive on the domain/graph core (the hexagon interior), using fakes. But **maintainability beats coverage** — delete a fragile test rather than keep it. A test that breaks on every refactor without catching bugs is a liability.
- Fakes (`FakeLLM`, `FakeMCPClient`), not mocks. Fakes are real implementations with deterministic, configurable behavior.
- Three test levels (see `docs/adr/003-testing-philosophy.md`): unit (fakes, in-process), integration (real MCP server, no LLM), evals (`evals/`, real LLM against honeypot ground truth). **Never test LLM quality with fakes** — that's what evals are for.
- **Given/When/Then pattern**: test files stay ultra-readable by extracting setup into `given.py` and assertions into `then.py`, one pair per test file (e.g. `test_audit.py` + `test_audit_given.py` + `test_audit_then.py`). The test file reads like a spec. Only extract into given/then when the function **actually abstracts something** — if it's just a one-liner wrapper, inline it instead.

```python
# test_audit.py
import tests.unit.test_audit_given as given
import tests.unit.test_audit_then as then

async def test_detects_missing_input_validation():
    tool = given.a_tool_with_weak_validation()
    fake_llm = given.a_fake_llm_returning(category="input_validation")
    state = given.an_audit_state(tools=[tool])
    graph = build_graph(llm=fake_llm, mcp_client=FakeMCPClient([tool]))  # trivial — inline

    results = await graph.ainvoke(state)

    then.verdicts_failure_for(results, tool="get_user", category="input_validation")
```

## Workflow

- **Test-first**: write tests before implementation, run them to confirm they fail, then write the code to make them pass — a test that was never red might pass for the wrong reason.
- **Run unit tests frequently** — after each meaningful change, not just at the end.
- **Refactor continuously.** After green tests, look for simplification opportunities before moving on.

## Landmines

- Integration tests require the dummy server (`tests/dummy_server.py`) to be spawned as a subprocess — the test fixtures handle this, but the server must be a valid MCP stdio server (reads stdin, writes stdout).
- The MCP SDK uses **two nested async context managers** (`stdio_client` + `ClientSession`). The adapter wraps both into a single `async with`. Don't try to manage them separately.
- `with_structured_output` returns a single `BaseModel`, not a list — that's why `TestCaseBatch` exists as a wrapper.

## Pointers

- `docs/adr/` — Architecture Decision Records. Explain *why*, not *how*. **Immutable once accepted** — to change a decision, write a new ADR that supersedes the previous one.
- `plans/` — **Spec-driven development**: before implementing a non-trivial feature, write a plan as a markdown file in `plans/` for review. The user reviews and approves the plan before any code is written. Naming convention: `YYYY-MM-DD_short_description.md` (e.g. `2026-03-15_llm_adapter.md`). **Immutable once implemented** — plans are not living documentation. They serve as historical context for what was done. Never update a past plan, write a new one for new changes.