# Plan: LangGraph Orchestration (Graph Layer)

## Context

Previous work delivered the hexagonal foundation: domain models, ports, adapters (AnthropicLLM, StdioMCPClient), and fakes (FakeLLM, FakeMCPClient). The graph layer is the orchestration core — it wires everything together into an auditable, testable pipeline.

The MCP client lifecycle (connect/disconnect) is already managed by the adapter's context manager. The CLI will manage that lifecycle. Graph nodes receive an already-connected client.

Report rendering (Markdown console output, JSON file I/O) is deferred to the CLI layer. This plan produces the structured data (`AuditReport` model) that the CLI will format.

Checkpointing (`AsyncSqliteSaver`, `--resume`) is also deferred to the CLI layer.

## Approach

**Subgraph composition** as designed in init.md. The inner audit loop (generate → execute → judge → route) is a separate `audit_tool` subgraph with its own state type (`AuditToolState`). This isolates the per-tool audit logic and makes it independently testable. The main graph loops over discovered tools, delegating each to the subgraph.

**State mapping**: The subgraph defines an `AuditToolInput` (just `current_tool` + `test_budget`) as its input schema. Shared keys between parent and child state enable automatic LangGraph state mapping. A `finalize_tool_audit` node in the parent reads the subgraph output and accumulates `ToolReport`s.

**No mutable index**: The main graph has no `current_tool_index` counter. Instead, the current position is derived from `len(tool_reports)` — the number of completed audits *is* the index of the next tool. This eliminates a mutable field, removes temporal coupling between nodes, and makes the state tell a domain story: "I've audited N tools, M remain."

**Dependency injection** via factory functions (closures) as established in ADR 002. Nodes close over ports (`LLMPort`, `MCPClientPort`), never access them from serializable state.

## New domain models

Add to `domain/models.py`:

```python
class ToolReport(BaseModel):
    tool: ToolDefinition
    results: list[EvalResult]

class AuditReport(BaseModel):
    tool_reports: list[ToolReport]
    token_usage: TokenUsage
```

Export both from `domain/__init__.py`.

## Graph state types

File: `graph/state.py`

```python
from typing import Annotated, TypedDict
import operator
from mcp_auditor.domain import ToolDefinition, TestCase, EvalResult, ToolReport, AuditReport

class AuditToolState(TypedDict):
    current_tool: ToolDefinition
    test_budget: int
    pending_cases: list[TestCase]
    current_case: TestCase | None
    tool_results: list[EvalResult]

class AuditToolInput(TypedDict):
    current_tool: ToolDefinition
    test_budget: int

class GraphState(TypedDict):
    discovered_tools: list[ToolDefinition]
    test_budget: int
    # Subgraph interface (shared keys)
    current_tool: ToolDefinition
    tool_results: list[EvalResult]
    # Accumulated across tools
    tool_reports: Annotated[list[ToolReport], operator.add]
    audit_report: AuditReport | None
```

**No `current_tool_index`**: The current position is derived from `len(tool_reports)`. After `finalize_tool_audit` appends a report, the next iteration of `prepare_tool` reads `discovered_tools[len(tool_reports)]`. This eliminates a mutable counter and the temporal coupling it created.

**Why `tool_reports` uses an `operator.add` reducer**: each `finalize_tool_audit` invocation appends one `ToolReport`. Without a reducer, LangGraph would overwrite instead of accumulate.

**Why `tool_results` has no reducer**: it's overwritten per-tool by the subgraph, then read by `finalize_tool_audit`. No accumulation needed — `tool_reports` accumulates.

## Prompts

File: `graph/prompts.py`

Two pure functions. These are first-draft prompts — evals will iterate on them against ground truth.

### `build_attack_generation_prompt`

```python
def build_attack_generation_prompt(
    tool_name: str,
    tool_description: str,
    input_schema: dict[str, Any],
    budget: int,
    categories: list[AuditCategory],
) -> str:
```

The prompt instructs the LLM to:
- Act as a security auditor testing an MCP tool
- Generate exactly `budget` test cases distributed across `categories` (at least 1 per category if budget allows)
- Consider the `input_schema` to craft relevant payloads (e.g. string params get injection tests, int params get boundary tests)
- Each test case needs: tool_name, category, description of what it verifies, arguments dict matching the schema
- Focus on MCP-specific risks, not generic OWASP

### `build_judge_prompt`

```python
def build_judge_prompt(
    tool_name: str,
    tool_description: str,
    test_case: TestCase,
) -> str:
```

The prompt instructs the LLM to:
- Act as a security evaluator judging an MCP tool's response to a specific attack
- Given: the tool definition, the attack payload (category + description + arguments), and the actual response (or error)
- Decide: PASS (the tool handled the attack properly) or FAIL (the tool is vulnerable)
- Provide: justification (why this verdict), severity (low/medium/high/critical)
- Be strict about info leakage (any internal path, stack trace = FAIL)
- Be strict about injection (if the tool echoes unsanitized input = FAIL)

## Nodes

File: `graph/nodes.py`

All nodes are factory functions returning `async (state) -> dict` callables.

### `make_discover_tools(mcp_client: MCPClientPort)`

Returns a node that calls `mcp_client.list_tools()`, populates `discovered_tools`.

### `make_prepare_tool()`

No port dependency. Returns a node that derives the current index from `len(tool_reports)`, reads `discovered_tools[len(tool_reports)]`, and sets `current_tool`.

### `make_generate_test_cases(llm: LLMPort)`

Returns a node that:
1. Reads `current_tool` and `test_budget` from `AuditToolState`
2. Calls `build_attack_generation_prompt(...)` with all 5 categories
3. Calls `llm.generate_structured(prompt, TestCaseBatch)`
4. Wraps each `AuditPayload` into a `TestCase`
5. Returns `{"pending_cases": [...], "tool_results": []}`

### `make_execute_tool(mcp_client: MCPClientPort)`

Returns a node that:
1. Pops first from `pending_cases`
2. Calls `mcp_client.call_tool(payload.tool_name, payload.arguments)`
3. If `tool_response.is_error` is `False`: sets `response` on the `TestCase` to `tool_response.content`
4. If `tool_response.is_error` is `True`: sets `error` on the `TestCase` to `tool_response.content`
5. Returns `{"current_case": updated_case, "pending_cases": remaining}`

Note: `call_tool` does not raise exceptions for tool errors — it returns `ToolResponse(is_error=True)`. The node checks `is_error` to decide which `TestCase` field to populate.

### `make_judge_response(llm: LLMPort)`

Returns a node that:
1. Reads `current_case` and `current_tool` from `AuditToolState`
2. Calls `build_judge_prompt(...)` with the test case (including its response/error)
3. Calls `llm.generate_structured(prompt, EvalResult)`
4. Returns `{"tool_results": [*state["tool_results"], eval_result], "current_case": None}`

### `make_finalize_tool_audit()`

No port dependency. Returns a node that:
1. Reads `current_tool` and `tool_results` from `GraphState`
2. Creates a `ToolReport(tool=current_tool, results=tool_results)`
3. Returns `{"tool_reports": [tool_report]}` (the reducer appends)

### `make_generate_report(llm: LLMPort)`

Returns a node that:
1. Reads `tool_reports` from `GraphState`
2. Reads `llm.usage_stats` for token totals
3. Returns `{"audit_report": AuditReport(tool_reports=..., token_usage=...)}`

Wait — `audit_report` is not in `GraphState`. Two options:
- Add it to `GraphState`
- Return the `AuditReport` as the graph's output schema

**Decision**: Add `audit_report: AuditReport | None` to `GraphState` (initialized to `None`). The CLI reads it from the final state. Simpler than a separate output schema.

## Routing functions

File: `graph/nodes.py` (same file — they're small)

### `route_after_discovery(state: GraphState) -> str`

Returns `"prepare_tool"` if `discovered_tools` is non-empty, else `"generate_report"`. Handles the empty tool list edge case — without this, `prepare_tool` would crash on `discovered_tools[0]`.

### `route_test_cases(state: AuditToolState) -> str`

Returns `"execute_tool"` if `pending_cases` is non-empty, else `END`.

### `route_tools(state: GraphState) -> str`

Compares `len(tool_reports)` to `len(discovered_tools)`. Returns `"prepare_tool"` if more tools remain, else `"generate_report"`. Pure read — no mutation, no temporal coupling.

## Graph builder

File: `graph/builder.py`

```python
def build_audit_tool_subgraph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
) -> CompiledStateGraph:
    builder = StateGraph(AuditToolState, input=AuditToolInput)
    builder.add_node("generate_test_cases", make_generate_test_cases(llm))
    builder.add_node("execute_tool", make_execute_tool(mcp_client))
    builder.add_node("judge_response", make_judge_response(llm))
    builder.add_edge(START, "generate_test_cases")
    builder.add_edge("generate_test_cases", "execute_tool")
    builder.add_edge("execute_tool", "judge_response")
    builder.add_conditional_edges("judge_response", route_test_cases)
    return builder.compile()


def build_graph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
) -> CompiledStateGraph:
    audit_subgraph = build_audit_tool_subgraph(llm, mcp_client)

    builder = StateGraph(GraphState)
    builder.add_node("discover_tools", make_discover_tools(mcp_client))
    builder.add_node("prepare_tool", make_prepare_tool())
    builder.add_node("audit_tool", audit_subgraph)
    builder.add_node("finalize_tool_audit", make_finalize_tool_audit())
    builder.add_node("generate_report", make_generate_report(llm))
    builder.add_edge(START, "discover_tools")
    builder.add_conditional_edges("discover_tools", route_after_discovery)
    builder.add_edge("prepare_tool", "audit_tool")
    builder.add_edge("audit_tool", "finalize_tool_audit")
    builder.add_conditional_edges("finalize_tool_audit", route_tools)
    return builder.compile()
```

## Files to create/modify

### Create

| File | Purpose |
|------|---------|
| `src/mcp_auditor/graph/state.py` | `GraphState`, `AuditToolState`, `AuditToolInput` |
| `src/mcp_auditor/graph/prompts.py` | `build_attack_generation_prompt`, `build_judge_prompt` |
| `src/mcp_auditor/graph/nodes.py` | All node factories + routing functions |
| `src/mcp_auditor/graph/builder.py` | `build_audit_tool_subgraph`, `build_graph` |
| `tests/unit/test_prompts.py` | Prompt content verification |
| `tests/unit/test_nodes.py` | Individual node tests with fakes |
| `tests/unit/test_nodes_given.py` | Test setup helpers for node tests |
| `tests/unit/test_nodes_then.py` | Assertion helpers for node tests |
| `tests/unit/test_graph.py` | Full graph orchestration test |
| `tests/unit/test_graph_given.py` | Test setup helpers for graph tests |
| `tests/unit/test_graph_then.py` | Assertion helpers for graph tests |

### Modify

| File | Change |
|------|--------|
| `src/mcp_auditor/domain/models.py` | Add `ToolReport`, `AuditReport` |
| `src/mcp_auditor/domain/__init__.py` | Export `ToolReport`, `AuditReport` |
| `src/mcp_auditor/graph/__init__.py` | Export `build_graph`, `GraphState`, `AuditReport` |

## What stays unchanged

- `domain/ports.py` — no changes to port interfaces
- `adapters/` — no changes to any adapter
- `tests/fakes/` — FakeLLM and FakeMCPClient are sufficient as-is
- `tests/integration/` — no new integration tests (graph tests are unit tests with fakes)
- `tests/dummy_server.py` — unchanged
- `cli.py` — remains `NotImplementedError` (deferred to CLI layer)
- All ADRs — immutable

## Edge cases

- **Empty tool list**: `discover_tools` returns 0 tools → `route_after_discovery` skips directly to `generate_report` → report has empty `tool_reports`. Without this routing function, `prepare_tool` would crash with an IndexError on `discovered_tools[0]`.
- **LLM returns wrong number of test cases**: Log a warning but continue. Don't re-generate (too expensive). The evals measure distribution quality.
- **LLM returns test case with wrong tool_name**: The `execute_tool` node uses the payload's `tool_name` as-is. If the LLM hallucinates a tool name, `call_tool` will return an error. The judge evaluates that error. No crash.
- **MCP call_tool raises exception**: Already handled by `FakeMCPClient` and `StdioMCPClient` — both return `ToolResponse(content=error_msg, is_error=True)`. The `execute_tool` node sets `error` on the TestCase.
- **All test cases fail/pass**: Valid outcomes. The report reflects reality.

## Test scenarios

### Prompt tests (`test_prompts.py`)

No given/then needed — assertions are simple string checks.

- `test_attack_prompt_includes_tool_name`: prompt contains the tool name
- `test_attack_prompt_includes_schema`: prompt contains serialized input_schema
- `test_attack_prompt_includes_all_categories`: prompt mentions all 5 category values
- `test_attack_prompt_includes_budget`: prompt mentions the budget number
- `test_judge_prompt_includes_response`: prompt contains the tool's response content
- `test_judge_prompt_includes_error_when_present`: prompt contains the error message when TestCase has an error
- `test_judge_prompt_includes_payload_description`: prompt contains what the test verifies

### Node tests (`test_nodes.py`)

Uses given/then — setup involves constructing state dicts and configuring fakes.

- `test_discover_tools_populates_state`: FakeMCPClient with 2 tools → state has 2 `discovered_tools`
- `test_prepare_tool_extracts_current`: state with 3 tools and 1 existing tool_report → `current_tool` is tools[1] (derived from `len(tool_reports)`)
- `test_generate_produces_pending_cases`: FakeLLM returns a TestCaseBatch with 3 cases → `pending_cases` has 3 TestCases
- `test_execute_tool_success`: FakeMCPClient returns a ToolResponse → `current_case` has response, no error
- `test_execute_tool_error`: FakeMCPClient returns `ToolResponse(is_error=True)` → `current_case` has `error` set, `response` is `None`
- `test_judge_produces_eval_result`: FakeLLM returns an EvalResult → `tool_results` has 1 result
- `test_finalize_tool_audit_creates_report`: state with 2 results → `tool_reports` has 1 ToolReport with 2 results
- `test_route_after_discovery_continues`: discovered_tools non-empty → returns "prepare_tool"
- `test_route_after_discovery_skips_when_empty`: discovered_tools empty → returns "generate_report"
- `test_route_test_cases_continues`: pending_cases non-empty → returns "execute_tool"
- `test_route_test_cases_ends`: pending_cases empty → returns END
- `test_route_tools_continues`: `len(tool_reports)` < `len(discovered_tools)` → returns "prepare_tool"
- `test_route_tools_ends`: `len(tool_reports)` == `len(discovered_tools)` → returns "generate_report"

### Graph tests (`test_graph.py`)

Uses given/then — setup involves building a complete graph with fakes.

- `test_single_tool_single_test_case`: 1 tool, FakeLLM returns 1 test case + 1 eval → report has 1 ToolReport with 1 result
- `test_two_tools_two_cases_each`: 2 tools, FakeLLM configured for 2 batches of 2 + 4 evals → report has 2 ToolReports, 2 results each
- `test_empty_tool_list`: 0 tools → report has 0 ToolReports (no crash)
- `test_token_usage_accumulated`: after full run → report.token_usage reflects all LLM calls

## Verification

```bash
uv run pytest tests/unit/test_prompts.py -v
uv run pytest tests/unit/test_nodes.py -v
uv run pytest tests/unit/test_graph.py -v
uv run pytest tests/unit/ -v        # all unit tests still pass
uv run pytest tests/integration/ -v  # integration tests unaffected
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

## Implementation steps

### Step 1: Domain models, state types, and prompts with tests

**Files**:
- `tests/unit/test_prompts.py` (create)
- `src/mcp_auditor/domain/models.py` (modify — add `ToolReport`, `AuditReport`)
- `src/mcp_auditor/domain/__init__.py` (modify — export `ToolReport`, `AuditReport`)
- `src/mcp_auditor/graph/state.py` (create)
- `src/mcp_auditor/graph/prompts.py` (create)

**Do**:

1. Add `ToolReport` and `AuditReport` to `src/mcp_auditor/domain/models.py`, after the existing `TokenUsage` class:
   - `ToolReport(BaseModel)` with fields: `tool: ToolDefinition`, `results: list[EvalResult]`
   - `AuditReport(BaseModel)` with fields: `tool_reports: list[ToolReport]`, `token_usage: TokenUsage`

2. Export both from `src/mcp_auditor/domain/__init__.py` (add to imports and `__all__`).

3. Create `src/mcp_auditor/graph/state.py` with three TypedDict classes exactly as specified in the plan:
   - `AuditToolState` — keys: `current_tool`, `test_budget`, `pending_cases`, `current_case`, `tool_results`
   - `AuditToolInput` — keys: `current_tool`, `test_budget`
   - `GraphState` — keys: `discovered_tools`, `test_budget`, `current_tool`, `tool_results`, `tool_reports` (with `Annotated[list[ToolReport], operator.add]` reducer), `audit_report`. No `current_tool_index` — derived from `len(tool_reports)`.

4. Create `src/mcp_auditor/graph/prompts.py` with two pure functions:
   - `build_attack_generation_prompt(tool_name, tool_description, input_schema, budget, categories) -> str` — instructs the LLM to act as a security auditor, generate exactly `budget` test cases distributed across `categories`, consider the `input_schema` for relevant payloads, each test case with tool_name/category/description/arguments, focus on MCP-specific risks. Include serialized `input_schema` (via `json.dumps`) and all category values in the prompt text.
   - `build_judge_prompt(tool_name, tool_description, test_case) -> str` — instructs the LLM to act as a security evaluator, given tool definition + attack payload + response/error, decide PASS/FAIL, provide justification and severity. Include the test case's `response` or `error` content, and the payload `description`. Be strict about info leakage and injection.

5. Create `tests/unit/test_prompts.py` with 7 tests (no given/then extraction needed — assertions are simple string checks):
   - `test_attack_prompt_includes_tool_name`: call `build_attack_generation_prompt` with `tool_name="get_user"`, assert `"get_user"` in result
   - `test_attack_prompt_includes_schema`: pass `input_schema={"type": "object", "properties": {"id": {"type": "integer"}}}`, assert `"integer"` in result (proves schema was serialized)
   - `test_attack_prompt_includes_all_categories`: pass all 5 `AuditCategory` values, assert each `.value` string appears in the prompt
   - `test_attack_prompt_includes_budget`: pass `budget=10`, assert `"10"` in result
   - `test_judge_prompt_includes_response`: create a `TestCase` with `response="tool output here"`, assert `"tool output here"` in result
   - `test_judge_prompt_includes_error_when_present`: create a `TestCase` with `error="connection refused"`, assert `"connection refused"` in result
   - `test_judge_prompt_includes_payload_description`: create a `TestCase` with `payload.description="SQL injection via id param"`, assert that description string in result

**Test**: All 7 prompt tests verify that constructed prompt strings contain the expected substrings for each input parameter.

**Verify**:
```bash
uv run pytest tests/unit/test_prompts.py -v
uv run pytest tests/unit/ -v
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

### Step 2: Node factories, routing functions, and node tests

**Files**:
- `tests/unit/test_nodes_given.py` (create)
- `tests/unit/test_nodes_then.py` (create)
- `tests/unit/test_nodes.py` (create)
- `src/mcp_auditor/graph/nodes.py` (create)

**Do**:

1. Create `tests/unit/test_nodes_given.py` with helper functions for constructing test state dicts and configuring fakes:
   - `a_tool(name="test_tool", ...)` -> `ToolDefinition` with sensible defaults
   - `a_payload(tool_name="test_tool", ...)` -> `AuditPayload` with sensible defaults
   - `a_test_case(...)` -> `TestCase` wrapping a payload
   - `an_eval_result(tool_name="test_tool", ...)` -> `EvalResult` with sensible defaults
   - `a_fake_llm_returning(*responses)` -> `FakeLLM`
   - `a_fake_mcp_client(tools, responses=None)` -> `FakeMCPClient`

2. Create `tests/unit/test_nodes_then.py` with assertion helpers:
   - `discovered_tools_count(result, expected)` — asserts `len(result["discovered_tools"]) == expected`
   - `current_tool_is(result, expected_tool)` — asserts `result["current_tool"] == expected_tool`
   - `pending_cases_count(result, expected)` — asserts `len(result["pending_cases"]) == expected`
   - `current_case_has_response(result, expected_content)` — asserts `result["current_case"].response == expected_content`
   - `current_case_has_error(result, expected_error)` — asserts `result["current_case"].error == expected_error` and `result["current_case"].response is None`
   - `tool_results_count(result, expected)` — asserts `len(result["tool_results"]) == expected`
   - `tool_report_has_results(result, expected_count)` — asserts `len(result["tool_reports"][0].results) == expected_count`

   Note: no assertion for `current_tool_index` — the field no longer exists. Index is derived from `len(tool_reports)`.

3. Create `tests/unit/test_nodes.py` with 13 tests using given/then:
   - `test_discover_tools_populates_state`: build node via `make_discover_tools(fake_mcp_client)` with 2 tools, call it with empty state, assert 2 discovered tools
   - `test_prepare_tool_extracts_current`: build node via `make_prepare_tool()`, call with state containing 3 tools and 1 existing `tool_report` in `tool_reports`, assert `current_tool` is `tools[1]` (index derived from `len(tool_reports)`)
   - `test_generate_produces_pending_cases`: configure `FakeLLM` to return a `TestCaseBatch` with 3 `AuditPayload`s, build node via `make_generate_test_cases(fake_llm)`, call with `AuditToolState` containing `current_tool` and `test_budget=3`, assert 3 pending cases and empty `tool_results`
   - `test_execute_tool_success`: configure `FakeMCPClient` to return `ToolResponse(content="result data")` for tool name, build node via `make_execute_tool(fake_mcp_client)`, call with state containing 1 pending case, assert `current_case` has response="result data" and no error
   - `test_execute_tool_error`: configure `FakeMCPClient` to return `ToolResponse(content="not found", is_error=True)`, assert `current_case` has error="not found" and response is None
   - `test_judge_produces_eval_result`: configure `FakeLLM` to return an `EvalResult`, build node via `make_judge_response(fake_llm)`, call with state containing a `current_case` with response, assert `tool_results` has 1 item
   - `test_finalize_tool_audit_creates_report`: build node via `make_finalize_tool_audit()`, call with state containing `current_tool` and 2 `tool_results`, assert returned `tool_reports` has 1 `ToolReport` with 2 results
   - `test_route_after_discovery_continues`: call `route_after_discovery` with non-empty `discovered_tools` -> `"prepare_tool"`
   - `test_route_after_discovery_skips_when_empty`: call with empty `discovered_tools` -> `"generate_report"`
   - `test_route_test_cases_continues`: call `route_test_cases` with non-empty `pending_cases` -> `"execute_tool"`
   - `test_route_test_cases_ends`: call with empty `pending_cases` -> `END` (import from `langgraph.graph`)
   - `test_route_tools_continues`: call `route_tools` with `tool_reports` of length 1 and `discovered_tools` of length 3 -> `"prepare_tool"`
   - `test_route_tools_ends`: call with `tool_reports` of length 2 and `discovered_tools` of length 2 -> `"generate_report"`

4. Create `src/mcp_auditor/graph/nodes.py` with all 7 factory functions and 3 routing functions as specified in the plan:
   - `make_discover_tools(mcp_client)` -> async node that returns `{"discovered_tools": tools}`
   - `make_prepare_tool()` -> async node that derives index from `len(tool_reports)`, returns `{"current_tool": discovered_tools[len(tool_reports)]}`
   - `make_generate_test_cases(llm)` -> async node that builds prompt, calls `llm.generate_structured(prompt, TestCaseBatch)`, wraps payloads into `TestCase` objects, returns `{"pending_cases": cases, "tool_results": []}`
   - `make_execute_tool(mcp_client)` -> async node that pops first pending case, calls `mcp_client.call_tool`, sets response or error on the test case, returns `{"current_case": updated_case, "pending_cases": remaining}`
   - `make_judge_response(llm)` -> async node that builds judge prompt, calls `llm.generate_structured(prompt, EvalResult)`, returns `{"tool_results": [*existing, eval_result], "current_case": None}`
   - `make_finalize_tool_audit()` -> async node that creates `ToolReport`, returns `{"tool_reports": [report]}`
   - `make_generate_report(llm)` -> async node that reads `tool_reports` and `llm.usage_stats`, returns `{"audit_report": AuditReport(...)}`
   - `route_after_discovery(state) -> str` — returns `"prepare_tool"` or `"generate_report"`
   - `route_test_cases(state) -> str` — returns `"execute_tool"` or `END`
   - `route_tools(state) -> str` — returns `"prepare_tool"` or `"generate_report"`

**Test**: 13 node tests covering each factory function's behavior and each routing function's branching logic.

**Verify**:
```bash
uv run pytest tests/unit/test_nodes.py -v
uv run pytest tests/unit/ -v
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

### Step 3: Graph builder, full graph tests, and exports

**Files**:
- `tests/unit/test_graph_given.py` (create)
- `tests/unit/test_graph_then.py` (create)
- `tests/unit/test_graph.py` (create)
- `src/mcp_auditor/graph/builder.py` (create)
- `src/mcp_auditor/graph/__init__.py` (modify — add exports)

**Do**:

1. Create `tests/unit/test_graph_given.py` with helper functions for building a complete graph with fakes:
   - `a_tool(name, ...)` -> `ToolDefinition` (can reuse pattern from nodes_given or import)
   - `a_fake_llm_for_single_tool_audit(num_cases)` -> `FakeLLM` configured with a `TestCaseBatch` response (with `num_cases` payloads) followed by `num_cases` `EvalResult` responses, plus any responses needed for `generate_report` (none — it reads `llm.usage_stats`, not `generate_structured`)
   - `a_fake_llm_for_multi_tool_audit(tool_configs)` -> `FakeLLM` configured with interleaved `TestCaseBatch` + `EvalResult` responses for multiple tools
   - `a_graph(fake_llm, fake_mcp_client)` -> calls `build_graph(fake_llm, fake_mcp_client)` and returns the compiled graph
   - `an_initial_state(test_budget=5)` -> returns a `GraphState`-compatible dict with sensible defaults for all required keys
   - `invoke_graph(graph, state)` -> `await graph.ainvoke(state)` and returns the result

2. Create `tests/unit/test_graph_then.py` with assertion helpers:
   - `has_tool_reports(result, expected_count)` — asserts `len(result["audit_report"].tool_reports) == expected_count`
   - `tool_report_at(result, index)` -> returns `result["audit_report"].tool_reports[index]` for chaining
   - `report_has_results(report, expected_count)` — asserts `len(report.results) == expected_count`
   - `report_is_for_tool(report, tool_name)` — asserts `report.tool.name == tool_name`
   - `token_usage_is_nonzero(result)` — asserts both `input_tokens > 0` and `output_tokens > 0` on `result["audit_report"].token_usage`

3. Create `tests/unit/test_graph.py` with 4 tests using given/then:
   - `test_single_tool_single_test_case`: 1 tool in FakeMCPClient, FakeLLM returns 1 test case batch + 1 eval result. Invoke graph. Assert report has 1 ToolReport with 1 result.
   - `test_two_tools_two_cases_each`: 2 tools in FakeMCPClient, FakeLLM returns 2 batches of 2 cases + 4 eval results. Invoke graph. Assert report has 2 ToolReports, each with 2 results, and correct tool names.
   - `test_empty_tool_list`: 0 tools in FakeMCPClient, FakeLLM has no responses queued. Invoke graph. Assert report has 0 ToolReports, no crash.
   - `test_token_usage_accumulated`: after a full single-tool run with 2 test cases (3 LLM calls: 1 generate + 2 judge), assert `token_usage.input_tokens == 30` and `token_usage.output_tokens == 15` (FakeLLM adds 10/5 per call).

4. Create `src/mcp_auditor/graph/builder.py` with two functions:
   - `build_audit_tool_subgraph(llm, mcp_client) -> CompiledStateGraph` — builds the inner subgraph with `StateGraph(AuditToolState, input=AuditToolInput)`, nodes: generate_test_cases -> execute_tool -> judge_response, conditional edge from judge_response via `route_test_cases`
   - `build_graph(llm, mcp_client) -> CompiledStateGraph` — builds the main graph with `StateGraph(GraphState)`, nodes: discover_tools, prepare_tool, audit_tool (the compiled subgraph), finalize_tool_audit, generate_report. Edges: START -> discover_tools, conditional to prepare_tool or generate_report, prepare_tool -> audit_tool -> finalize_tool_audit, conditional to prepare_tool or generate_report.

5. Update `src/mcp_auditor/graph/__init__.py` to export `build_graph`, `GraphState`, and `AuditReport`:
   ```python
   from mcp_auditor.domain import AuditReport
   from mcp_auditor.graph.builder import build_graph
   from mcp_auditor.graph.state import GraphState

   __all__ = ["AuditReport", "GraphState", "build_graph"]
   ```

**Test**: 4 end-to-end graph tests verifying complete orchestration with fakes — single tool, multi-tool, empty tool list, and token accumulation.

**Verify**:
```bash
uv run pytest tests/unit/test_graph.py -v
uv run pytest tests/unit/ -v
uv run pytest tests/integration/ -v
uv run ruff check .
uv run ruff format --check .
uv run pyright
```
