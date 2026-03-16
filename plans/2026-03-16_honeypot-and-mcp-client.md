# Plan: Honeypot Server + MCP Client Adapter

## Context

The domain layer (models, ports) is in place. Next step: the ability to connect to an MCP server, discover its tools, and call them. These two pieces — the adapter and the honeypot test fixture — go together because the honeypot is the integration test target for the adapter.

## Approach

Build bottom-up: domain model addition first (`ToolResponse`), then the honeypot (test fixture), then the adapter, then the fake, then integration tests. Each layer builds on the previous.

## 1. Add `ToolResponse` domain model

**File: `src/mcp_auditor/domain/models.py`**

Add a typed return value for `call_tool` instead of `Any`:

```python
class ToolResponse(BaseModel):
    content: str
    is_error: bool = False
```

- `content`: the textual response from the MCP tool (joined `TextContent` items)
- `is_error`: mirrors `CallToolResult.isError` from the MCP SDK

**File: `src/mcp_auditor/domain/ports.py`**

Update `MCPClientPort.call_tool` return type:

```python
async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse: ...
```

**File: `src/mcp_auditor/domain/__init__.py`**

Export `ToolResponse`.

**File: `tests/unit/test_models.py`**

Add tests for `ToolResponse`: default `is_error=False`, explicit error flag.

## 2. Honeypot dummy server

**File: `tests/dummy_server.py`**

A standalone MCP stdio server using `FastMCP`. Three tools with different robustness levels:

### `get_user(user_id: int) -> str`
**Vulnerabilities:** error_handling, input_validation, info_leakage.

- Happy path: returns `"User: Alice (id=42)"` for known IDs (small hardcoded dict).
- Negative ID: raises an unhandled `ValueError` whose message includes an internal file path (e.g. `"/opt/mcp-server/internal/users.db"`). FastMCP catches the exception and wraps it into an error response (`isError=True`) with content `"Error executing tool get_user: <ValueError message>"`. The raw traceback is NOT included — but the ValueError message itself leaks internal paths, which is the info_leakage signal.
- Non-existent ID: raises `KeyError` with the missing key in the message. FastMCP wraps it the same way — the client sees the key name but not a full dict dump.
- No type coercion — if the MCP framework passes a string, it will fail with a raw TypeError (also wrapped by FastMCP).

### `execute_query(query: str) -> str`
**Vulnerabilities:** injection, info_leakage.

- Happy path: returns `"Results: 3 rows"` for any query — but deliberately includes the query string in the response (e.g. `"Executed: {query} — Results: 3 rows"`), enabling injection detection by the judge.
- No input sanitization at all — accepts any string without validation.
- Includes a hardcoded fake filesystem path in every response (e.g. `"[db: /opt/mcp-server/config/database.yml]"`) — info_leakage signal. This must be in the normal return value, not in an exception path, so it shows up in the `TextContent` the client receives.

### `list_items(category: str, limit: int = 10) -> str`
**Healthy tool** — ground truth: PASS on all categories.

- Validates `category` against a whitelist: `["books", "movies", "music"]`. Raises a `ValueError("Invalid category")` for anything else — no internal details leaked. FastMCP wraps this into `isError=True` with a generic message.
- Caps `limit` to range `[1, 100]` with clamping (no error, just adjusts).
- Handles wrong types gracefully with a generic error message.
- Returns `"Items: book1, book2, ... (showing {limit})"`.

### Implementation notes

- Use `FastMCP` decorator API — tools are plain `async def` functions with type hints.
- `FastMCP` auto-generates `inputSchema` from the function signatures.
- Entry point: `if __name__ == "__main__": app.run()` (runs stdio transport by default).
- Keep it simple — no database, no state, pure functions with hardcoded data.

## 3. StdioMCPClient adapter

**File: `src/mcp_auditor/adapters/mcp_client.py`**

Implements `MCPClientPort`. Wraps the two nested MCP SDK context managers (`stdio_client` + `ClientSession`) into a single async context manager.

```python
class StdioMCPClient:
    """Usage::

        async with StdioMCPClient.connect("python", ["server.py"]) as client:
            tools = await client.list_tools()
    """

    @classmethod
    @asynccontextmanager
    async def connect(cls, command: str, args: list[str]) -> AsyncIterator[Self]:
        ...
```

### `connect(command, args)` class method / async context manager

1. Creates `StdioServerParameters(command=command, args=args)`.
2. Opens `stdio_client(params)` → gets `(read_stream, write_stream)`.
3. Creates `ClientSession(read_stream, write_stream)`.
4. Calls `session.initialize()`.
5. Yields `self` (the connected client).
6. Cleanup is automatic via the context manager stack (`AsyncExitStack`).

### `list_tools() -> list[ToolDefinition]`

- Calls `session.list_tools()`.
- Maps each `mcp.types.Tool` → `ToolDefinition(name=t.name, description=t.description or "", input_schema=t.inputSchema)`.

### `call_tool(name, args) -> ToolResponse`

- Calls `session.call_tool(name, arguments=args)`.
- Extracts text from `result.content` — joins all `TextContent` items with newlines.
- Returns `ToolResponse(content=text, is_error=result.isError)`.

### Implementation notes

- Use `contextlib.asynccontextmanager` + `contextlib.AsyncExitStack` to compose the two nested context managers cleanly.
- No retry logic here — retry is for the LLM adapter (API rate limits). MCP call failures are captured as `ToolResponse(is_error=True)`.
- If `call_tool` raises an exception (transport error, server crash), catch it and return `ToolResponse(content=str(exception), is_error=True)` so the audit can continue.

**File: `src/mcp_auditor/adapters/__init__.py`**

Export `StdioMCPClient`.

## 4. FakeMCPClient (configurable fake for unit tests)

**File: `tests/fakes/__init__.py`**

Package init. Export all fakes.

**File: `tests/fakes/mcp_client.py`**

A real implementation of `MCPClientPort` with deterministic, configurable behavior:

```python
class FakeMCPClient:
    def __init__(
        self,
        tools: list[ToolDefinition],
        responses: dict[str, ToolResponse] | None = None,
    ):
        self._tools = tools
        self._responses = responses or {}

    async def list_tools(self) -> list[ToolDefinition]:
        return self._tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        if name in self._responses:
            return self._responses[name]
        return ToolResponse(content="ok")
```

- `tools`: the list of tools returned by `list_tools()`.
- `responses`: optional mapping of tool name → canned response. Falls back to a generic `ToolResponse(content="ok")`.
- No dependency on MCP SDK — pure domain types.

### What happens to the existing stub in `test_ports.py`

The structural typing test (`test_fake_mcp_client_satisfies_port`) stays. Update it to use the new `ToolResponse` return type. It can either import from `tests/fakes/` or keep its minimal inline version — the point of that test is pyright validation, not reuse.

## 5. Integration tests

**File: `tests/integration/test_mcp_client.py`**

Tests the real `StdioMCPClient` against the honeypot server.

### Fixture: `mcp_client`

An async fixture that:
1. Resolves the path to `tests/dummy_server.py`.
2. Opens `StdioMCPClient.connect("uv", ["run", "python", str(server_path)])`.
3. Yields the connected client.
4. Cleanup via context manager exit.

Using `uv run python` ensures the server runs in the project's venv with all dependencies available.

### Test cases

**Discovery:**
- `test_discovers_three_tools`: `list_tools()` returns exactly 3 tools. Verify names: `get_user`, `execute_query`, `list_items`.
- `test_tool_schemas_have_required_fields`: each `ToolDefinition` has non-empty `name`, `description`, and `input_schema` with `"properties"` key.

**Happy paths:**
- `test_get_user_valid_id`: `call_tool("get_user", {"user_id": 42})` returns a `ToolResponse` with `is_error=False` and `"Alice"` in content.
- `test_execute_query_simple`: `call_tool("execute_query", {"query": "SELECT 1"})` returns `is_error=False`.
- `test_list_items_valid_category`: `call_tool("list_items", {"category": "books"})` returns `is_error=False` with content containing `"book"`.

**Error paths (honeypot vulnerabilities):**
- `test_get_user_negative_id_leaks_info`: `call_tool("get_user", {"user_id": -1})` returns `is_error=True` and content contains leaked internal path (e.g. `"/opt/mcp-server/"`) and `"ValueError"`.
- `test_execute_query_echoes_input`: `call_tool("execute_query", {"query": "DROP TABLE users"})` — the response content contains the injected query string.
- `test_list_items_rejects_invalid_category`: `call_tool("list_items", {"category": "weapons"})` returns `is_error=True` with generic message, no internal paths.
- `test_list_items_clamps_limit`: `call_tool("list_items", {"category": "books", "limit": 9999})` returns `is_error=False` (clamped, not rejected).

### Test organization

Given/then helpers only if the assertions are non-trivial. For these integration tests, assertions are simple string checks — inline them.

## Files changed (summary)

| File | Action | Purpose |
|------|--------|---------|
| `src/mcp_auditor/domain/models.py` | Edit | Add `ToolResponse` |
| `src/mcp_auditor/domain/ports.py` | Edit | `call_tool` returns `ToolResponse` |
| `src/mcp_auditor/domain/__init__.py` | Edit | Export `ToolResponse` |
| `tests/unit/test_models.py` | Edit | Tests for `ToolResponse` |
| `tests/unit/test_ports.py` | Edit | Update fake to return `ToolResponse` |
| `tests/dummy_server.py` | Create | Honeypot MCP server (3 tools) |
| `src/mcp_auditor/adapters/mcp_client.py` | Create | `StdioMCPClient` adapter |
| `src/mcp_auditor/adapters/__init__.py` | Edit | Export `StdioMCPClient` |
| `tests/fakes/__init__.py` | Create | Fakes package |
| `tests/fakes/mcp_client.py` | Create | Configurable `FakeMCPClient` |
| `tests/integration/test_mcp_client.py` | Create | Integration tests vs honeypot |

## What stays unchanged

- `graph/` — no graph code yet, not touched.
- `docs/adr/` — no new ADR needed, decisions here are straightforward applications of existing ADRs.
- `cli.py` — not touched.
- `FakeLLM` — stays in `test_ports.py` for now; will move to `tests/fakes/llm.py` when the LLM adapter is built.

## Verification

```bash
uv run pytest tests/unit          # ToolResponse model tests + updated port tests
uv run pytest tests/integration   # Honeypot integration tests
uv run ruff check .               # Lint
uv run pyright                    # Type check
```

## Implementation steps

### Step 1: ToolResponse domain model, honeypot server, and FakeMCPClient

**Files**:
- Edit: `tests/unit/test_models.py` — add `TestToolResponse` class
- Edit: `tests/unit/test_ports.py` — update `FakeMCPClient.call_tool` return type to `ToolResponse`
- Create: `tests/fakes/__init__.py` — fakes package init, export `FakeMCPClient`
- Create: `tests/fakes/mcp_client.py` — configurable `FakeMCPClient`
- Edit: `src/mcp_auditor/domain/models.py` — add `ToolResponse(BaseModel)` with fields `content: str` and `is_error: bool = False`
- Edit: `src/mcp_auditor/domain/ports.py` — change `MCPClientPort.call_tool` return type from `Any` to `ToolResponse`, update imports
- Edit: `src/mcp_auditor/domain/__init__.py` — add `ToolResponse` to imports and `__all__`
- Create: `tests/dummy_server.py` — honeypot MCP stdio server with three tools

**Do**:

1. **`tests/unit/test_models.py`** — Add a `TestToolResponse` class with two tests:
   - `test_default_is_not_error`: construct `ToolResponse(content="ok")`, assert `is_error` is `False`.
   - `test_explicit_error_flag`: construct `ToolResponse(content="boom", is_error=True)`, assert `is_error` is `True`.
   - Add `ToolResponse` to the imports from `mcp_auditor.domain`.

2. **`src/mcp_auditor/domain/models.py`** — Add `ToolResponse` class between `ToolDefinition` and `AuditPayload` (it is used by the port, logically belongs near `ToolDefinition`):
   ```python
   class ToolResponse(BaseModel):
       content: str
       is_error: bool = False
   ```

3. **`src/mcp_auditor/domain/ports.py`** — Change `call_tool` signature to return `ToolResponse` instead of `Any`. Add `ToolResponse` to the import from `mcp_auditor.domain.models`. Remove `Any` from typing imports if no longer needed (check: `args: dict[str, Any]` still needs it, so keep it).

4. **`src/mcp_auditor/domain/__init__.py`** — Add `ToolResponse` to the import list from `mcp_auditor.domain.models` and to `__all__`.

5. **`tests/unit/test_ports.py`** — Update inline `FakeMCPClient.call_tool` to return `ToolResponse` instead of `Any`. Add `ToolResponse` to imports from `mcp_auditor.domain`. Change the return statement to `return ToolResponse(content="ok")`.

6. **`tests/fakes/__init__.py`** — Create package init:
   ```python
   from tests.fakes.mcp_client import FakeMCPClient

   __all__ = ["FakeMCPClient"]
   ```

7. **`tests/fakes/mcp_client.py`** — Create the configurable `FakeMCPClient` exactly as specified in plan section 4. Constructor takes `tools: list[ToolDefinition]` and `responses: dict[str, ToolResponse] | None = None`. `list_tools` returns `self._tools`. `call_tool` looks up by name in `self._responses`, falls back to `ToolResponse(content="ok")`.

8. **`tests/dummy_server.py`** — Create the honeypot server using `FastMCP` from `mcp.server.fastmcp`. Implement three tools exactly as specified in plan section 2:
   - `get_user(user_id: int) -> str` — hardcoded dict `{42: "Alice", 1: "Bob"}`. Negative ID raises `ValueError("user_id must be positive — see /opt/mcp-server/internal/users.db")`. Missing ID raises `KeyError(user_id)`. Happy path returns `f"User: {name} (id={user_id})"`.
   - `execute_query(query: str) -> str` — returns `f"[db: /opt/mcp-server/config/database.yml] Executed: {query} — Results: 3 rows"`. No validation.
   - `list_items(category: str, limit: int = 10) -> str` — validates category against `["books", "movies", "music"]`, raises `ValueError("Invalid category")` for others. Clamps limit to `[1, 100]`. Returns `f"Items: {category}1, {category}2, ... (showing {clamped_limit})"`.
   - Entry point: `if __name__ == "__main__": app.run()`.

**Test**: Run unit tests to confirm `ToolResponse` model tests pass, port structural typing tests still pass with updated return type.

**Verify**:
```bash
uv run pytest tests/unit -x
uv run ruff check .
uv run pyright
```
All must pass. The honeypot server is not tested yet (that is step 2).

---

### Step 2: StdioMCPClient adapter and integration tests

**Files**:
- Create: `tests/integration/test_mcp_client.py` — integration tests against honeypot
- Create: `src/mcp_auditor/adapters/mcp_client.py` — `StdioMCPClient` adapter
- Edit: `src/mcp_auditor/adapters/__init__.py` — export `StdioMCPClient`

**Do**:

1. **`tests/integration/test_mcp_client.py`** — Create integration test file with:
   - An async fixture `mcp_client` that resolves path to `tests/dummy_server.py` (use `pathlib.Path(__file__).resolve().parent.parent / "dummy_server.py"`), opens `StdioMCPClient.connect("uv", ["run", "python", str(server_path)])`, and yields the connected client.
   - 9 test cases, all inline assertions (no given/then files):
     - **Discovery tests:**
       - `test_discovers_three_tools`: `list_tools()` returns exactly 3 tools. Assert tool names are `{"get_user", "execute_query", "list_items"}`.
       - `test_tool_schemas_have_required_fields`: each tool has non-empty `name`, non-empty `description`, and `input_schema` dict containing `"properties"` key.
     - **Happy path tests:**
       - `test_get_user_valid_id`: `call_tool("get_user", {"user_id": 42})` returns `is_error=False`, `"Alice"` in content.
       - `test_execute_query_simple`: `call_tool("execute_query", {"query": "SELECT 1"})` returns `is_error=False`.
       - `test_list_items_valid_category`: `call_tool("list_items", {"category": "books"})` returns `is_error=False`, `"book"` in content.
     - **Error path tests:**
       - `test_get_user_negative_id_leaks_info`: `call_tool("get_user", {"user_id": -1})` returns `is_error=True`, content contains `"/opt/mcp-server/"`.
       - `test_execute_query_echoes_input`: `call_tool("execute_query", {"query": "DROP TABLE users"})` — response content contains `"DROP TABLE users"`.
       - `test_list_items_rejects_invalid_category`: `call_tool("list_items", {"category": "weapons"})` returns `is_error=True`, content does NOT contain `"/opt/"`.
       - `test_list_items_clamps_limit`: `call_tool("list_items", {"category": "books", "limit": 9999})` returns `is_error=False`.

2. **`src/mcp_auditor/adapters/mcp_client.py`** — Implement `StdioMCPClient` as specified in plan section 3:
   - Class with `_session: ClientSession` stored as instance attribute.
   - `connect(cls, command, args)` classmethod decorated with `@asynccontextmanager`. Uses `AsyncExitStack` to enter both `stdio_client(StdioServerParameters(command=command, args=args))` and `ClientSession(read, write)`. Calls `session.initialize()`. Sets `self._session = session`. Yields `self`.
   - `list_tools()` calls `self._session.list_tools()`, maps results to `ToolDefinition(name=t.name, description=t.description or "", input_schema=t.inputSchema)`.
   - `call_tool(name, args)` calls `self._session.call_tool(name, arguments=args)`. Joins `TextContent` items from `result.content` with newlines. Returns `ToolResponse(content=text, is_error=result.isError)`. Wraps the call in try/except to catch transport errors, returning `ToolResponse(content=str(e), is_error=True)`.
   - Imports: `contextlib.asynccontextmanager`, `contextlib.AsyncExitStack`, `collections.abc.AsyncIterator`, `typing.Self`, `mcp.ClientSession`, `mcp.StdioServerParameters`, `mcp.client.stdio.stdio_client`, `mcp.types.TextContent`, `mcp_auditor.domain.models.ToolDefinition`, `mcp_auditor.domain.models.ToolResponse`.

3. **`src/mcp_auditor/adapters/__init__.py`** — Add import and export of `StdioMCPClient`.

**Test**: Integration tests validate tool discovery, happy paths, and error paths for all three honeypot tools.

**Verify**:
```bash
uv run pytest tests/unit -x
uv run pytest tests/integration -x
uv run ruff check .
uv run pyright
```
All must pass.
