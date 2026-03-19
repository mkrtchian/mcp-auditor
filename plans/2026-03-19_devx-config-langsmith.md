# DevX: Central Config, LangSmith, LangGraph Studio

**Date:** 2026-03-19


## Context

The project has grown past its initial feature-complete state but lacks developer-experience infrastructure that a production-grade GenAI project should have:

- **No `.env` file system.** API keys are passed via raw env vars with no template or documentation.
- **No central configuration.** Model names are hardcoded in adapter constructors (`AnthropicLLM`, `GoogleLLM`). The provider is selected via a bare `os.environ.get()` in `create_llm()`. Changing the model requires editing source code.
- **No observability.** LangGraph supports LangSmith tracing out of the box via env vars, but nothing is set up. There's no way to inspect graph runs, compare prompt iterations, or correlate eval scores with traces.
- **No LangGraph Studio config.** Studio enables visual step-through debugging of the graph (inspect state between nodes, replay runs). The project uses LangGraph but can't be opened in Studio.

## Approach

Seven changes, all additive — no existing behavior changes:

1. `.env.example` + `.env` in `.gitignore` (already there) — template for all env vars
2. `src/mcp_auditor/config.py` — central `Settings` class using `pydantic-settings`, loads from `.env` + env vars
3. Wire `Settings` into `adapters/llm.py`, `cli.py`, and `evals/run_evals.py` — replace hardcoded values and scattered `os.environ.get()`
4. Separate judge LLM — `build_graph` accepts an optional `judge_llm` parameter, allowing a stronger model for verdict classification
5. LangSmith integration — env vars for tracing + custom run metadata on graph invocations
6. `langgraph.json` + `create_graph()` entry point — LangGraph Studio support
7. `py.typed` marker

### Hexagonal boundary

`config.py` lives at `src/mcp_auditor/config.py` (package root, outside the hexagon). It is infrastructure — it reads env vars and `.env` files. `domain/` and `graph/` never import it. Only `adapters/` and `cli.py` use it.

## Files to create

### `.env.example`

```env
# LLM Provider: "google" (default) or "anthropic"
MCP_AUDITOR_PROVIDER=google

# Model overrides (optional — defaults are set in config.py)
# MCP_AUDITOR_MODEL=gemini-3.1-flash-lite-preview
# MCP_AUDITOR_JUDGE_MODEL=claude-sonnet-4-6-latest

# API keys (set the one matching your provider)
# GOOGLE_API_KEY=your-key-here
# ANTHROPIC_API_KEY=your-key-here

# LangSmith (optional — enables tracing when set)
# LANGSMITH_API_KEY=your-key-here
# LANGCHAIN_TRACING_V2=true
# LANGCHAIN_PROJECT=mcp-auditor
```

### `src/mcp_auditor/config.py`

```python
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "MCP_AUDITOR_"}

    provider: str = "google"
    model: str = ""
    judge_model: str = ""
    langsmith_project: str = "mcp-auditor"

    def resolve_model(self) -> str:
        if self.model:
            return self.model
        return _default_model(self.provider)

    def resolve_judge_model(self) -> str:
        if self.judge_model:
            return self.judge_model
        return self.resolve_model()


def _default_model(provider: str) -> str:
    defaults = {
        "google": "gemini-3.1-flash-lite-preview",
        "anthropic": "claude-haiku-4-5-20251001",
    }
    if provider not in defaults:
        raise ValueError(f"Unknown provider: {provider!r}. Use 'google' or 'anthropic'.")
    return defaults[provider]


def load_settings() -> Settings:
    return Settings()
```

Key design decisions:
- `env_prefix = "MCP_AUDITOR_"` — all app-specific env vars are namespaced. `MCP_AUDITOR_PROVIDER`, `MCP_AUDITOR_MODEL`, `MCP_AUDITOR_JUDGE_MODEL`.
- `model` defaults to empty string → `resolve_model()` falls back to provider-specific default. This keeps the defaults in one place instead of scattered across adapter constructors.
- `judge_model` defaults to empty string → `resolve_judge_model()` falls back to the main model. Allows using a stronger model for the judge node (verdict classification) while keeping a cheaper model for test case generation.
- `langsmith_project` — read as `MCP_AUDITOR_LANGSMITH_PROJECT`, defaults to `"mcp-auditor"`. Used to set `LANGCHAIN_PROJECT` if LangSmith tracing is enabled.
- `pydantic-settings` loads from env vars automatically. It also supports `.env` files via `model_config = {"env_file": ".env"}`, but we don't set that here — the `.env` file is loaded by the shell or by LangGraph Studio. This avoids double-loading and keeps the `Settings` class testable without file I/O.

### `langgraph.json`

```json
{
  "dependencies": ["."],
  "graphs": {
    "audit": "./src/mcp_auditor/studio.py:create_graph"
  },
  "env": ".env"
}
```

### `src/mcp_auditor/studio.py`

Entry point for LangGraph Studio. Studio requires a module-level `CompiledStateGraph` or a factory function `() -> CompiledStateGraph`.

```python
from mcp_auditor.adapters.llm import create_llm
from mcp_auditor.config import load_settings
from mcp_auditor.graph.builder import build_graph


def create_graph():
    """Factory for LangGraph Studio.

    Studio calls this once to get the compiled graph. The graph is then
    invoked with state via the Studio UI. Note: the MCP client requires
    a running server — Studio users must configure the target server
    command in the Studio UI or via environment variables.
    """
    settings = load_settings()
    llm = create_llm(settings)
    # Studio doesn't support async context managers for MCP client lifecycle.
    # For now, return a graph without an MCP client — Studio can be used to
    # inspect the graph structure and step through LLM-only nodes.
    # Full MCP integration requires the CLI's async with block.
    return build_graph(llm, mcp_client=_placeholder_mcp_client())
```

**Important constraint:** `StdioMCPClient` requires an async context manager (`async with StdioMCPClient.connect(...)`) to manage the subprocess lifecycle. Studio's factory function is synchronous and called once. Two options:

- **Option A (recommended):** Return the graph with a placeholder MCP client. Studio users can inspect graph structure, step through LLM nodes (generate_test_cases, judge_response), and debug prompts. MCP tool execution nodes will fail gracefully. This covers the most valuable Studio use case (prompt debugging) without fighting the async lifecycle.
- **Option B:** Create a `StudioMCPClient` adapter that lazily connects on first `call_tool()`. More complex, couples Studio concerns into the adapter layer. Not worth it now.

We go with Option A. The placeholder raises a clear error if MCP nodes are invoked:

```python
from typing import Any

from mcp_auditor.domain.models import ToolDefinition, ToolResponse
from mcp_auditor.domain.ports import MCPClientPort


class _StudioMCPPlaceholder:
    """Placeholder for Studio — MCP operations require the CLI."""

    async def list_tools(self) -> list[ToolDefinition]:
        raise NotImplementedError(
            "MCP tool discovery requires a running server. Use the CLI: mcp-auditor run"
        )

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        raise NotImplementedError(
            "MCP tool execution requires a running server. Use the CLI: mcp-auditor run"
        )


def _placeholder_mcp_client() -> MCPClientPort:
    return _StudioMCPPlaceholder()  # type: ignore[return-value]
```

### `src/mcp_auditor/py.typed`

Empty file (PEP 561 marker).

## Files to modify

### `src/mcp_auditor/adapters/llm.py`

**What changes:**
- `create_llm()` takes a `Settings` parameter instead of reading `os.environ` directly.
- `AnthropicLLM` and `GoogleLLM` constructors receive the model name from `Settings.resolve_model()` instead of hardcoding defaults.

```python
# Before
def create_llm() -> "AnthropicLLM | GoogleLLM":
    provider = os.environ.get("MCP_AUDITOR_PROVIDER", "google").lower()
    if provider == "anthropic":
        return AnthropicLLM()
    ...

# After
def create_llm(settings: Settings) -> "AnthropicLLM | GoogleLLM":
    model = settings.resolve_model()
    if settings.provider == "anthropic":
        return AnthropicLLM(model=model)
    if settings.provider == "google":
        return GoogleLLM(model=model)
    raise ValueError(f"Unknown provider: {settings.provider!r}.")
```

- Remove `import os` (no longer needed).
- `AnthropicLLM.__init__` and `GoogleLLM.__init__` keep their `model` parameter but lose their default values — the default is now in `Settings`.
- Add `create_judge_llm(settings)` — same logic as `create_llm` but uses `settings.resolve_judge_model()`. If the judge model is the same as the main model, callers can just reuse the main LLM instance (the CLI handles this).

```python
def create_judge_llm(settings: Settings) -> "AnthropicLLM | GoogleLLM":
    model = settings.resolve_judge_model()
    if settings.provider == "anthropic":
        return AnthropicLLM(model=model)
    if settings.provider == "google":
        return GoogleLLM(model=model)
    raise ValueError(f"Unknown provider: {settings.provider!r}.")
```

### `src/mcp_auditor/cli.py`

**What changes:**
- Import and use `load_settings()` at the start of `_run_audit()`.
- Pass `settings` to `create_llm(settings)`.
- Attach custom metadata to graph invocation config for LangSmith tracing.

```python
# In _run_audit():
settings = load_settings()
llm = create_llm(settings)

# When invoking the graph, add metadata to config:
config: dict[str, Any] = {
    "configurable": {"thread_id": thread_id},
    "metadata": {
        "target": target_str,
        "budget": budget,
        "provider": settings.provider,
        "model": settings.resolve_model(),
    },
}
```

The `metadata` dict is automatically picked up by LangSmith tracing (if enabled via env vars). It appears in the LangSmith dashboard as run metadata, filterable and searchable. No `langsmith` import needed — LangChain's callback system handles it.

Create the judge LLM and pass both to `build_graph`:

```python
# In _run_audit():
settings = load_settings()
llm = create_llm(settings)
judge_llm = create_judge_llm(settings)

# Pass both to build_graph:
graph = build_graph(llm, mcp_client, judge_llm=judge_llm, checkpointer=checkpointer)
```

### `src/mcp_auditor/graph/builder.py`

**What changes:**
- `build_graph` accepts an optional `judge_llm: LLMPort | None` parameter. If `None`, falls back to the main `llm`.
- The judge LLM is passed to `make_judge_response` in the subgraph.

```python
def build_graph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
    judge_llm: LLMPort | None = None,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    effective_judge = judge_llm or llm
    audit_subgraph = _build_audit_tool_subgraph(llm, mcp_client, effective_judge)
    ...
```

```python
def _build_audit_tool_subgraph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
    judge_llm: LLMPort,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    builder: StateGraph[Any, Any, Any, Any] = StateGraph(
        AuditToolState, input_schema=AuditToolInput
    )
    builder.add_node("generate_test_cases", make_generate_test_cases(llm))
    builder.add_node("execute_tool", make_execute_tool(mcp_client))
    builder.add_node("judge_response", make_judge_response(judge_llm))
    ...
```

The only change in `_build_audit_tool_subgraph` is that `make_judge_response` receives `judge_llm` instead of `llm`. `make_generate_test_cases` keeps using the main `llm`.

### `src/mcp_auditor/graph/nodes.py`

**No code changes.** `make_judge_response(llm)` already takes an `LLMPort` — it doesn't care which model instance it receives. The split happens in `builder.py` where different LLM instances are wired to different factory functions.

### `evals/run_evals.py`

**What changes:**
- Import and use `load_settings()`.
- Pass `settings` to `create_llm(settings)`.
- After each eval run, post feedback scores to LangSmith (if tracing is enabled).

```python
# At top of run_evals():
settings = load_settings()

# In run_single_audit():
async def run_single_audit(settings: Settings, budget: int) -> AuditReport:
    llm = create_llm(settings)
    judge_llm = create_judge_llm(settings)
    async with StdioMCPClient.connect(HONEYPOT_COMMAND, HONEYPOT_ARGS) as mcp_client:
        graph = build_graph(llm, mcp_client, judge_llm=judge_llm)
        ...
```

**LangSmith feedback integration** — post eval scores as feedback on the trace:

```python
import os

def _post_langsmith_feedback(
    recall: float,
    precision: float,
    project_name: str,
) -> None:
    if not os.environ.get("LANGCHAIN_TRACING_V2"):
        return
    try:
        from langsmith import Client  # type: ignore[import-untyped]
        client = Client()
        runs = list(client.list_runs(
            project_name=project_name,
            limit=1,
        ))
        if not runs:
            return
        run_id = runs[0].id
        client.create_feedback(run_id, key="recall", score=recall)
        client.create_feedback(run_id, key="precision", score=precision)
    except Exception:
        pass  # Best-effort — don't fail evals because of LangSmith
```

This is best-effort: if LangSmith is not configured or the client fails, evals continue normally. The `langsmith` import is lazy (inside the function) to avoid making it a hard dependency.

### `pyproject.toml`

**What changes:**
- Add `pydantic-settings>=2.0` to `dependencies` (runtime — needed by `config.py`).
- Add `langsmith>=0.3` to `dev` dependency group (dev only — used in evals feedback).

```toml
dependencies = [
    # ... existing ...
    "pydantic-settings>=2.0",
]

[dependency-groups]
dev = [
    # ... existing ...
    "langsmith>=0.3",
]
```

## What stays unchanged

- **`domain/`** — no changes. Models, ports, rendering untouched.
- **`graph/nodes.py`** — no changes. `make_judge_response(llm)` already takes an `LLMPort` parameter — the split is wired in `builder.py`, not here.
- **`graph/prompts.py`**, **`graph/state.py`** — no changes.
- **`adapters/mcp_client.py`** — no changes. MCP client is not affected by config.
- **All existing tests** — no changes. Tests use fakes and don't depend on `Settings` or env vars.
- **Existing CLI behavior** — `mcp-auditor run` works exactly the same. `Settings` defaults match current hardcoded values.

## Edge cases

| Scenario | Behavior |
|---|---|
| No `.env` file | `pydantic-settings` loads from env vars only. Same as current behavior. |
| `MCP_AUDITOR_MODEL` set but `MCP_AUDITOR_PROVIDER` not set | Provider defaults to `"google"`, model override is used. |
| `MCP_AUDITOR_JUDGE_MODEL` not set | Falls back to main model via `resolve_judge_model()`. Judge uses the same LLM as test case generation. |
| `MCP_AUDITOR_JUDGE_MODEL` set | `build_graph` receives two distinct LLM instances — one for generation, one for judging. |
| LangSmith env vars not set | Tracing is disabled. No LangSmith calls. Zero overhead. |
| `langsmith` package not installed (prod) | `_post_langsmith_feedback` catches `ImportError` silently. Evals run normally. |
| LangGraph Studio opens the project | Graph structure is visible. LLM nodes work if API keys are in `.env`. MCP nodes raise `NotImplementedError` with a helpful message. |
| Unknown provider in `MCP_AUDITOR_PROVIDER` | `ValueError` raised in `_default_model()`, caught by CLI's existing error handler. |

## Test scenarios

### Unit tests for `config.py`

New file: `tests/unit/test_config.py`

| Test | Input | Expected |
|---|---|---|
| `test_default_settings` | No env vars | `provider="google"`, `resolve_model()="gemini-3.1-flash-lite-preview"` |
| `test_anthropic_provider_defaults` | `MCP_AUDITOR_PROVIDER=anthropic` | `resolve_model()="claude-haiku-4-5-20251001"` |
| `test_model_override` | `MCP_AUDITOR_PROVIDER=google`, `MCP_AUDITOR_MODEL=gemini-pro` | `resolve_model()="gemini-pro"` |
| `test_judge_model_fallback` | `MCP_AUDITOR_MODEL=gemini-pro`, no `JUDGE_MODEL` | `resolve_judge_model()="gemini-pro"` |
| `test_judge_model_override` | `MCP_AUDITOR_MODEL=flash`, `MCP_AUDITOR_JUDGE_MODEL=pro` | `resolve_judge_model()="pro"` |
| `test_unknown_provider` | `MCP_AUDITOR_PROVIDER=openai` | `ValueError` |

These tests use `monkeypatch.setenv()` to set env vars — no `.env` file needed.

### Existing tests

All existing unit and integration tests must continue to pass unchanged. `create_llm` and `build_graph` signatures change, but tests use `FakeLLM` directly and pass `llm` positionally — the new `judge_llm` parameter defaults to `None` so existing call sites are unaffected.

## Verification

```bash
# All existing tests pass
uv run pytest

# New config tests pass
uv run pytest tests/unit/test_config.py

# Type check passes
uv run pyright

# Lint passes
uv run ruff check .

# LangGraph Studio can load the graph
# (manual — open project in Studio desktop app)
```

## Implementation steps

### Step 1: Settings class, dependency, tests, and wiring into adapters/CLI/evals

**Files** (create):
- `tests/unit/test_config.py` — unit tests for the Settings class
- `src/mcp_auditor/config.py` — central Settings class
- `.env.example` — env var template
- `src/mcp_auditor/py.typed` — PEP 561 marker (empty file)

**Files** (modify):
- `pyproject.toml` — add `pydantic-settings>=2.0` to dependencies, `langsmith>=0.3` to dev group
- `src/mcp_auditor/adapters/llm.py` — `create_llm()` takes `Settings` parameter, remove `os.environ` usage, remove default model strings from constructors, add `create_judge_llm()`
- `src/mcp_auditor/graph/builder.py` — `build_graph` accepts optional `judge_llm` parameter, passes it to `make_judge_response` in subgraph
- `src/mcp_auditor/cli.py` — import `load_settings()`, create both LLMs, pass to `build_graph`, add `metadata` dict to graph invocation config
- `evals/run_evals.py` — import `load_settings()`, create both LLMs, pass to `build_graph`, add `_post_langsmith_feedback()` helper

**Do**:

1. Write `tests/unit/test_config.py` first with these tests (use `monkeypatch.setenv` / `monkeypatch.delenv` to control env vars, construct `Settings()` directly in each test -- no given/then extraction needed since these are simple one-liner asserts):
   - `test_default_settings` — no env vars set, assert `provider == "google"` and `resolve_model() == "gemini-3.1-flash-lite-preview"`
   - `test_anthropic_provider_defaults` — set `MCP_AUDITOR_PROVIDER=anthropic`, assert `resolve_model() == "claude-haiku-4-5-20251001"`
   - `test_model_override` — set `MCP_AUDITOR_PROVIDER=google` and `MCP_AUDITOR_MODEL=gemini-pro`, assert `resolve_model() == "gemini-pro"`
   - `test_judge_model_fallback` — set `MCP_AUDITOR_MODEL=gemini-pro`, no `JUDGE_MODEL`, assert `resolve_judge_model() == "gemini-pro"`
   - `test_judge_model_override` — set `MCP_AUDITOR_MODEL=flash` and `MCP_AUDITOR_JUDGE_MODEL=pro`, assert `resolve_judge_model() == "pro"`
   - `test_unknown_provider` — set `MCP_AUDITOR_PROVIDER=openai`, call `resolve_model()`, assert `ValueError`

2. Create `src/mcp_auditor/config.py` with `Settings(BaseSettings)` class exactly as specified in the plan: `env_prefix = "MCP_AUDITOR_"`, fields `provider`, `model`, `judge_model`, `langsmith_project`, methods `resolve_model()` and `resolve_judge_model()`, helper `_default_model()`, and `load_settings()` factory.

3. Create `.env.example` with the template from the plan.

4. Create `src/mcp_auditor/py.typed` as an empty file.

5. Update `pyproject.toml`: add `"pydantic-settings>=2.0"` to `dependencies` list, add `"langsmith>=0.3"` to `dev` dependency group.

6. Update `src/mcp_auditor/adapters/llm.py`:
   - Remove `import os`.
   - Add `from mcp_auditor.config import Settings` import.
   - Change `create_llm()` signature to `create_llm(settings: Settings)`.
   - Inside `create_llm`, use `settings.resolve_model()` for the model name and `settings.provider` for the provider check.
   - Remove default values from `AnthropicLLM.__init__(model=...)` and `GoogleLLM.__init__(model=...)` — make `model` a required `str` parameter (no default).
   - Add `create_judge_llm(settings: Settings)` — same as `create_llm` but uses `settings.resolve_judge_model()`.

7. Update `src/mcp_auditor/graph/builder.py`:
   - Add `judge_llm: LLMPort | None = None` parameter to `build_graph()`.
   - Compute `effective_judge = judge_llm or llm`.
   - Pass `effective_judge` to `_build_audit_tool_subgraph()` which passes it to `make_judge_response()`.
   - Add `judge_llm: LLMPort` parameter to `_build_audit_tool_subgraph()` — `make_judge_response` receives `judge_llm`, `make_generate_test_cases` keeps `llm`.

8. Update `src/mcp_auditor/cli.py`:
   - Add `from mcp_auditor.config import load_settings` and `from mcp_auditor.adapters.llm import create_judge_llm` imports.
   - In `_run_audit()`, call `settings = load_settings()`, then `llm = create_llm(settings)` and `judge_llm = create_judge_llm(settings)`.
   - Pass `judge_llm` to `build_graph(llm, mcp_client, judge_llm=judge_llm, checkpointer=checkpointer)`.
   - In `_run_full_audit()`, change the `config` dict to include a `"metadata"` key with `target`, `budget`, `provider`, and `model` values (for LangSmith tracing). The metadata is added alongside the existing `"configurable"` key.

9. Update `evals/run_evals.py`:
   - Add `import os` and `from mcp_auditor.config import load_settings`.
   - In `run_evals()`, call `settings = load_settings()` and pass it through to `run_single_audit(settings, budget)`.
   - In `run_single_audit()`, accept `settings` parameter, call `create_llm(settings)` and `create_judge_llm(settings)`, pass both to `build_graph`.
   - Add `_post_langsmith_feedback(recall, precision, project_name)` function as specified in the plan (lazy import of `langsmith`, best-effort, catches all exceptions).
   - Call `_post_langsmith_feedback` after computing recall/precision in the eval loop, passing `settings.langsmith_project` as project name.

10. Run `uv sync` to install the new dependency.

**Test**: The 6 test cases listed above covering default settings, provider selection, model override, judge model fallback/override, and unknown provider error.

**Verify**:
```bash
uv run pytest tests/unit/test_config.py -v
uv run pytest tests/unit -v
uv run pytest tests/integration -v
uv run ruff check .
uv run ruff format --check .
uv run pyright
```
All tests pass (including all existing tests). Lint, format, and type check pass.

### Step 2: LangGraph Studio entry point

**Files** (create):
- `src/mcp_auditor/studio.py` — Studio factory function with placeholder MCP client
- `langgraph.json` — Studio project config

**Do**:

1. Create `src/mcp_auditor/studio.py` with:
   - `create_graph()` function — calls `load_settings()`, `create_llm(settings)`, `create_judge_llm(settings)`, returns `build_graph(llm, mcp_client=_placeholder_mcp_client(), judge_llm=judge_llm)`.
   - `_StudioMCPPlaceholder` class implementing `list_tools()` and `call_tool()` that both raise `NotImplementedError` with helpful messages directing users to the CLI.
   - `_placeholder_mcp_client()` helper returning the placeholder instance (with `# type: ignore[return-value]` since it doesn't formally implement the Protocol).
   - Imports: `from typing import Any`, domain models/ports, `load_settings`, `create_llm`, `build_graph`.

2. Create `langgraph.json` with the exact content from the plan: `dependencies: ["."]`, `graphs.audit` pointing to `./src/mcp_auditor/studio.py:create_graph`, `env: ".env"`.

**Test**: No automated tests for Studio integration (manual verification via Studio desktop app). Existing tests must still pass.

**Verify**:
```bash
uv run pytest tests/unit -v
uv run ruff check .
uv run ruff format --check .
uv run pyright
```
All checks pass.

## Next steps (out of scope)

The current eval strategy (end-to-end runs against a single honeypot, averaged over 3 runs) is a solid foundation but has known gaps. These are natural follow-ups once LangSmith tracing and the judge model split are in place.

### 1. Evaluate the judge in isolation

The current evals conflate generator quality and judge quality. If recall drops, it's unclear whether the generator stopped producing the right payloads or the judge misclassified a response. Next step: create a **LangSmith Dataset** of (tool response, expected verdict) pairs extracted from successful runs, then evaluate the judge prompt alone against that dataset. This enables prompt iteration on the judge without running the full audit pipeline.

### 2. Expand the honeypot corpus

`dummy_server.py` is a single fixture with 3 tools. The evals measure performance on this specific server, not on MCP servers in general. Risk: the LLM overfits to the honeypot's patterns. Next step: add 2-3 honeypot variants with different vulnerability profiles (e.g., a server with subtle info leakage but solid input validation, a server with complex nested tool schemas). This also tests distribution coverage under more realistic conditions.

### 3. Increase statistical power

3 runs produces wide confidence intervals. A recall of 0.93 averaged over 3 runs could be anywhere from 0.80 to 1.00 in reality. Next step: either increase to 5-10 runs, or compute and report confidence intervals instead of bare averages. The eval report should say "recall: 0.93 ± 0.07 (95% CI)", not just "recall: 0.93".

### 4. Fix or recalibrate the precision threshold

Precision threshold is 1.00 but both evaluated models score 0.56-0.61. A threshold that never passes is not actionable. Two paths: (a) investigate the false positives (likely a judge prompt issue on `list_items` / `input_validation`), fix the prompt, and keep 1.00; or (b) lower the threshold to a realistic target (e.g., 0.85) and iterate upward. Either way, the threshold should be something the system can actually reach.

### 5. LangSmith Experiments for prompt iteration

Once the judge dataset exists (step 1), use LangSmith Experiments to compare prompt variants side by side: same dataset, different prompts, metrics computed automatically. This replaces the manual workflow of editing a prompt → running evals → comparing JSON reports.
