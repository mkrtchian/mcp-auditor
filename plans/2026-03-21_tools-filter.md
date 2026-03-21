# `--tools` filter flag

## Context

The CLI currently audits all tools discovered on the MCP server. With 14 tools on the filesystem server, an audit takes ~3 minutes. There's no way to target specific tools. This is needed for:
- Demo recordings (target 3-4 tools that produce findings for a short GIF)
- Focused audits on specific tools of interest
- Faster iteration during development

## Approach

Add a `--tools` CLI option that accepts a comma-separated list of tool names. Filter the discovered tools in the `discover_tools` graph node. Error if any requested tool name doesn't exist on the server (tools are deterministic, not LLM-generated). The filter also applies in `--dry-run` mode.

## Files to modify

### `src/mcp_auditor/cli.py`

- Add `--tools` option to the `run` command:
  ```python
  @click.option("--tools", type=str, default=None, help="Comma-separated tool names to audit.")
  ```
- Add `tools_filter: frozenset[str] | None` field to `AuditOptions`
- Parse the comma-separated string into a `frozenset[str]` when constructing `AuditOptions`. Handle empty string (`""`) explicitly — `"".split(",")` produces `[""]`, not `[]`, so treat empty/whitespace-only input as `None` (no filter)
- Pass `tools_filter` to `build_graph()` and `_run_dry_run()`
- In `_run_dry_run()`: apply the filter after `mcp_client.list_tools()`, same validation logic as the graph node. Extract the shared filter+validate logic into a pure function (e.g. `filter_tools(tools, tools_filter)` in `graph/nodes.py` or `domain/`) to avoid duplicating the validation between `_run_dry_run` and `make_discover_tools`

### `src/mcp_auditor/graph/nodes.py`

- `make_discover_tools(mcp_client, tools_filter)`: accept optional `frozenset[str] | None`
- After `list_tools()`, if filter is set:
  1. Check all requested names exist in discovered tools. If any don't, raise `ValueError` listing the unknown names.
  2. Filter the list, preserving server order.

### `src/mcp_auditor/graph/builder.py`

- `build_graph()`: accept `tools_filter: frozenset[str] | None = None` parameter
- Pass it to `make_discover_tools(mcp_client, tools_filter)`

### `README.md`

- Add `--tools` row to the CLI options table:
  ```
  | `--tools`  | all        | Comma-separated tool names to audit               |
  ```

### `src/mcp_auditor/graph/state.py`

No changes. The filter is injected via the factory function closure, not through graph state.

## What stays unchanged

- Graph structure, routing, all other nodes
- Domain models
- Adapters
- Console/display
- Integration tests, evals

## Edge cases

| Scenario | Expected behavior |
|---|---|
| `--tools read_file,write_file` | Only audit those 2 tools |
| `--tools nonexistent_tool` | Error with message listing unknown tool names |
| `--tools read_file,nonexistent` | Error (partial match is still an error) |
| `--tools` not provided | Audit all tools (current behavior) |
| `--tools` with `--dry-run` | Dry run only on filtered tools |
| `--tools ""` (empty string) | Treated as no filter (audit all) |

## Test scenarios

### Unit tests (`tests/unit/test_nodes.py` + `tests/unit/fixtures/test_nodes_given.py` / `tests/unit/fixtures/test_nodes_then.py`)

**TestDiscoverTools:**

1. `test_filters_tools_by_name`: 3 tools discovered, filter on 2 names → returns 2 tools
2. `test_raises_on_unknown_tool_name`: 2 tools discovered, filter includes unknown name → `ValueError`
3. `test_no_filter_returns_all`: no filter (None) → returns all tools (existing test, verify it still passes)

### Unit tests (`tests/unit/test_cli.py` or inline)

Note: `tests/unit/test_cli.py` does not exist yet — create it or add these as inline tests in `test_nodes.py`.

4. Verify comma-separated parsing: `"a,b,c"` → `frozenset({"a", "b", "c"})`
5. Verify `None` when option not provided
6. Verify `""` (empty string) → `None` (no filter)

## Verification

```bash
uv run pytest tests/unit/test_nodes.py -v
uv run ruff check .
uv run pyright
```

## Implementation steps

### Step 1: Add `--tools` filter flag with pure filter function, CLI wiring, and tests

**Files** (test files first, then production code, then docs):

- `tests/unit/test_nodes.py` -- add tests to `TestDiscoverTools` and a new `TestFilterTools` class
- `tests/unit/fixtures/test_nodes_given.py` -- no changes expected (existing `a_tool` and `a_fake_mcp_client` suffice)
- `tests/unit/fixtures/test_nodes_then.py` -- add `discovered_tools_are` assertion if useful
- `src/mcp_auditor/graph/nodes.py` -- add `filter_tools(tools, tools_filter)` pure function; update `make_discover_tools` to accept and use `tools_filter: frozenset[str] | None`
- `src/mcp_auditor/graph/builder.py` -- add `tools_filter: frozenset[str] | None = None` param to `build_graph()`, pass to `make_discover_tools`
- `src/mcp_auditor/cli.py` -- add `--tools` click option, add `tools_filter` field to `AuditOptions`, parse comma-separated string into `frozenset[str] | None` (empty/whitespace string becomes `None`), pass `tools_filter` through to `build_graph()` and `_run_dry_run()`, apply `filter_tools` in `_run_dry_run`
- `README.md` -- add `--tools` row to the CLI options table

**Do:**

1. Write a pure function `filter_tools(tools: list[ToolDefinition], tools_filter: frozenset[str] | None) -> list[ToolDefinition]` in `src/mcp_auditor/graph/nodes.py`. When `tools_filter` is `None`, return all tools. Otherwise, validate that every name in `tools_filter` exists in the discovered tools list; raise `ValueError` listing unknown names if not. Return the filtered list preserving server order.

2. Write a pure function `parse_tools_filter(raw: str | None) -> frozenset[str] | None` in `src/mcp_auditor/cli.py`. Returns `None` if `raw` is `None` or empty/whitespace-only. Otherwise splits on commas, strips each name, and returns a `frozenset[str]`.

3. Update `make_discover_tools(mcp_client, tools_filter=None)` to call `filter_tools` after `list_tools()`.

4. Update `build_graph()` signature to accept `tools_filter: frozenset[str] | None = None` and forward it to `make_discover_tools`.

5. Add `tools_filter: frozenset[str] | None = None` field to `AuditOptions`.

6. Add `@click.option("--tools", type=str, default=None, help="Comma-separated tool names to audit.")` to the `run` command. Parse via `parse_tools_filter`. Pass `tools_filter` to `build_graph()` and `_run_dry_run()`.

7. In `_run_dry_run()`, accept `tools_filter` parameter and call `filter_tools(tools, tools_filter)` after `mcp_client.list_tools()`.

8. Add `| --tools | all | Comma-separated tool names to audit |` row to README CLI options table (after `--budget`).

**Test** (in `tests/unit/test_nodes.py`):

- `TestFilterTools.test_filters_tools_by_name`: create 3 tools (a, b, c), filter on `frozenset({"a", "c"})`, assert returns [a, c] in server order.
- `TestFilterTools.test_raises_on_unknown_tool_name`: create 2 tools (a, b), filter includes "unknown", assert `ValueError` raised with "unknown" in the message.
- `TestFilterTools.test_no_filter_returns_all`: pass `None` as filter, assert all tools returned.
- `TestFilterTools.test_preserves_server_order`: create tools [c, a, b], filter on `frozenset({"b", "c"})`, assert returns [c, b].
- `TestParseToolsFilter.test_parses_comma_separated`: `"a,b,c"` returns `frozenset({"a", "b", "c"})`.
- `TestParseToolsFilter.test_none_when_not_provided`: `None` returns `None`.
- `TestParseToolsFilter.test_none_for_empty_string`: `""` returns `None`.
- `TestParseToolsFilter.test_strips_whitespace`: `" a , b "` returns `frozenset({"a", "b"})`.
- `TestDiscoverTools.test_filters_tools_by_name` (integration with node): 3 tools on fake client, filter on 2 names, assert result has 2 discovered tools.

**Verify:**

```bash
uv run pytest tests/unit/test_nodes.py -v   # all tests pass
uv run ruff check .                          # no lint errors
uv run ruff format .                         # properly formatted
uv run pyright                               # no type errors
uv run pytest tests/unit -v                  # full unit suite still passes
```
