# Plan: LLM Adapter (AnthropicLLM + FakeLLM)

## Context

The `LLMPort` protocol is defined in `domain/ports.py` with two members:
- `async generate_structured[T: BaseModel](prompt: str, output_schema: type[T]) -> T`
- `usage_stats: TokenUsage` (property)

No adapter implements it yet. The graph layer needs both a real adapter for production and a fake for unit tests. This plan delivers both, with no graph code.

## Approach

Two classes, each in its own file:

1. **`AnthropicLLM`** (`src/mcp_auditor/adapters/llm.py`) — wraps `ChatAnthropic` + `with_structured_output`. Accumulates token usage across calls. Relies on langchain's built-in retry (`max_retries` param) rather than custom retry logic.

2. **`FakeLLM`** (`tests/fakes/llm.py`) — returns canned `BaseModel` responses from a queue. Tracks usage with synthetic values. No unit tests for the fake itself — correctness surfaces when graph tests use it.

## Files to create

### `src/mcp_auditor/adapters/llm.py`

```python
from langchain_anthropic import ChatAnthropic
from pydantic import BaseModel

from mcp_auditor.domain.models import TokenUsage


class AnthropicLLM:
    def __init__(self, model: str = "claude-sonnet-4-6-latest", max_retries: int = 3):
        self._model = ChatAnthropic(model=model, max_retries=max_retries)
        self._usage = TokenUsage()

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> T:
        structured = self._model.with_structured_output(
            output_schema, include_raw=True
        )
        response = await structured.ainvoke(prompt)
        self._accumulate_usage(response["raw"].usage_metadata)
        return response["parsed"]

    @property
    def usage_stats(self) -> TokenUsage:
        return self._usage

    def _accumulate_usage(self, metadata: dict | None) -> None:
        if metadata:
            self._usage = self._usage.add(
                TokenUsage(
                    input_tokens=metadata["input_tokens"],
                    output_tokens=metadata["output_tokens"],
                )
            )
```

Key decisions:
- `include_raw=True` so we can access `usage_metadata` on the underlying `AIMessage`. Without it, `with_structured_output` returns only the parsed Pydantic object and we lose token info.
- `max_retries=3` (langchain default is 2). Covers 429, 5xx, timeouts. Non-transient errors (400, auth) fail immediately — this is langchain's built-in behavior.
- No `temperature` param in constructor — structured output works best with default. Can be added later if needed.

### `tests/fakes/llm.py`

```python
from collections import deque

from pydantic import BaseModel

from mcp_auditor.domain.models import TokenUsage


class FakeLLM:
    def __init__(self, responses: list[BaseModel]):
        self._responses: deque[BaseModel] = deque(responses)
        self._usage = TokenUsage()

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> T:
        response = self._responses.popleft()
        self._usage = self._usage.add(TokenUsage(input_tokens=10, output_tokens=5))
        return response  # type: ignore[return-value]

    @property
    def usage_stats(self) -> TokenUsage:
        return self._usage
```

Key decisions:
- Queue-based (deque): each call pops the next response. Raises `IndexError` if more calls than expected — a clear test failure signal.
- Synthetic token values (10/5) — enough to test accumulation logic in report generation later.
- `type: ignore` on return: the fake doesn't validate that the response matches `output_schema`. The caller (test) is responsible for providing the right type. This keeps the fake simple.

## Files to modify

### `src/mcp_auditor/adapters/__init__.py`

Add `AnthropicLLM` to exports:
```python
from mcp_auditor.adapters.llm import AnthropicLLM
from mcp_auditor.adapters.mcp_client import StdioMCPClient

__all__ = ["AnthropicLLM", "StdioMCPClient"]
```

### `tests/fakes/__init__.py`

Add `FakeLLM` to exports:
```python
from tests.fakes.llm import FakeLLM
from tests.fakes.mcp_client import FakeMCPClient

__all__ = ["FakeLLM", "FakeMCPClient"]
```

### `tests/unit/test_ports.py`

Replace the inline `FakeLLM` stub with the real `FakeLLM` from `tests/fakes/`:

```python
from tests.fakes import FakeLLM, FakeMCPClient
```

Remove the inline `FakeLLM` class and the inline `FakeMCPClient` class. Also clean up the imports — after removing the inline classes, `Any`, `BaseModel`, `TokenUsage`, `ToolDefinition`, and `ToolResponse` become unused. The import line should become:

```python
from tests.fakes import FakeLLM, FakeMCPClient
from mcp_auditor.domain import LLMPort, MCPClientPort
```

The `FakeLLM` constructor now requires a `responses` argument — pass an empty list for the structural typing check:

```python
def test_fake_llm_satisfies_port() -> None:
    llm: LLMPort = FakeLLM(responses=[])
    assert llm is not None
```

Same for `FakeMCPClient` — already takes `tools` as required arg:
```python
def test_fake_mcp_client_satisfies_port() -> None:
    client: MCPClientPort = FakeMCPClient(tools=[])
    assert client is not None
```

## What stays unchanged

- `domain/models.py` — `TokenUsage` already has the right shape
- `domain/ports.py` — `LLMPort` protocol unchanged
- `adapters/mcp_client.py` — no changes
- `tests/fakes/mcp_client.py` — no changes
- `tests/unit/test_models.py` — no changes
- `tests/integration/` — no changes (no integration test for LLM adapter per ADR 003)

## Edge cases

- **Empty response queue in FakeLLM**: `deque.popleft()` raises `IndexError` — no silent failure, test fails loudly.
- **`usage_metadata` is None**: could happen if API changes. The `_accumulate_usage` guard (`if metadata`) skips accumulation silently. Acceptable for MVP — tokens are a nice-to-have, not critical.
- **Structured output parsing failure**: langchain raises `OutputParserException`. Let it propagate — the graph node calling this will handle or surface it.

## Test scenarios

No new test files. The only test change is in `test_ports.py`: replacing inline stubs with the real fakes. This validates structural typing against `LLMPort` and `MCPClientPort`.

The `FakeLLM` will be exercised extensively by graph unit tests. The `AnthropicLLM` will be exercised by evals.

## Verification

```bash
uv run pytest tests/unit/test_ports.py -v   # Structural typing still passes
uv run ruff check .                          # Lint clean
uv run pyright                               # Type check clean
```

## Implementation steps

### Step 1: Add AnthropicLLM adapter, FakeLLM fake, and update test_ports

**Files**:
- Create `src/mcp_auditor/adapters/llm.py`
- Create `tests/fakes/llm.py`
- Modify `src/mcp_auditor/adapters/__init__.py`
- Modify `tests/fakes/__init__.py`
- Modify `tests/unit/test_ports.py`

**Do**:

1. Create `tests/fakes/llm.py` with the `FakeLLM` class:
   - Constructor takes `responses: list[BaseModel]`, stores them in a `deque`.
   - `async generate_structured[T: BaseModel](self, prompt: str, output_schema: type[T]) -> T` pops the next response from the deque. Uses `# type: ignore[return-value]` on the return.
   - Accumulates synthetic `TokenUsage(input_tokens=10, output_tokens=5)` per call.
   - `usage_stats` property returns the accumulated `TokenUsage`.

2. Create `src/mcp_auditor/adapters/llm.py` with the `AnthropicLLM` class:
   - Constructor takes `model: str = "claude-sonnet-4-6-latest"` and `max_retries: int = 3`. Instantiates `ChatAnthropic(model=model, max_retries=max_retries)` and initializes `_usage = TokenUsage()`.
   - `async generate_structured[T: BaseModel](self, prompt: str, output_schema: type[T]) -> T` calls `self._model.with_structured_output(output_schema, include_raw=True)`, then `await structured.ainvoke(prompt)`. Accumulates usage from `response["raw"].usage_metadata`, returns `response["parsed"]`.
   - Private `_accumulate_usage(self, metadata: dict | None) -> None` guards on `if metadata` and calls `self._usage = self._usage.add(TokenUsage(input_tokens=metadata["input_tokens"], output_tokens=metadata["output_tokens"]))`.
   - `usage_stats` property returns `self._usage`.

3. Update `src/mcp_auditor/adapters/__init__.py`: add `AnthropicLLM` import and export alongside `StdioMCPClient`.

4. Update `tests/fakes/__init__.py`: add `FakeLLM` import and export alongside `FakeMCPClient`.

5. Update `tests/unit/test_ports.py`:
   - Replace all inline fake classes and unused imports with `from tests.fakes import FakeLLM, FakeMCPClient` and `from mcp_auditor.domain import LLMPort, MCPClientPort`.
   - Remove the inline `FakeMCPClient` and `FakeLLM` class definitions.
   - Update `test_fake_llm_satisfies_port` to pass `responses=[]` to `FakeLLM`.
   - Update `test_fake_mcp_client_satisfies_port` to pass `tools=[]` to `FakeMCPClient`.
   - Keep the module-level docstring.

**Test**: The two existing tests in `test_ports.py` must still pass, confirming that the real `FakeLLM` and `FakeMCPClient` from `tests/fakes/` satisfy the `LLMPort` and `MCPClientPort` protocols respectively.

**Verify**:
```bash
uv run pytest tests/unit/test_ports.py -v   # Both structural typing tests pass
uv run ruff check .                          # Lint clean
uv run ruff format --check .                 # Format clean
uv run pyright                               # Type check clean (strict)
```
