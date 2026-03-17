# Plan: CLI, Streaming, Checkpointing & Report Rendering

## Context

The engine is complete: domain models, graph orchestration, adapters, all tested. The missing piece is the user-facing layer — the CLI that wires everything together, streams progress, renders reports, and supports resume after interruption.

## Approach

Four concerns, each in its own module:

1. **Report rendering** — pure functions `AuditReport -> str`. Testable independently.
2. **Console output** — `rich`-based streaming display during audit execution.
3. **CLI wiring** — `click` commands that parse args, create adapters, invoke graph, write output.
4. **Checkpointing** — `AsyncSqliteSaver` passed to graph compilation, `--resume` flag.

### Why click

`argparse` works but requires boilerplate for subcommands, type validation, and help formatting. `click` is the modern standard for Python CLIs: decorator-based, composable subcommands, built-in type conversion, better error messages. Used by pip, Flask, and most professional Python tools.

### Why rich

Professional terminal output: progress bars, colored tables, panels. The streaming audit display (tool-by-tool, test-by-test with verdicts) benefits from `rich.live.Live` for in-place updates. Adds polish that signals production quality without custom ANSI code.

## New dependencies

Add to `[project.dependencies]` in `pyproject.toml`:

```
"click>=8.1",
"rich>=13.0",
```

## Files to create

### `src/mcp_auditor/domain/rendering.py`

Pure functions that format an `AuditReport` for output. No I/O, no `rich` — just string generation. Lives in `domain/` because the structure of a security audit report (sections, groupings, what to highlight) is domain knowledge, not infrastructure — same reasoning as prompts.

```python
def render_summary(report: AuditReport) -> str: ...

def render_json(report: AuditReport) -> str: ...

def render_markdown(report: AuditReport) -> str: ...
```

`render_markdown` structure:

```markdown
# MCP Audit Report

## Summary
- **Target:** `python tests/dummy_server.py`
- **Tools audited:** 3
- **Test cases:** 30
- **Findings:** 12 (3 critical, 5 high, 4 medium)
- **Token usage:** 15,234 input / 8,421 output

## get_user

### FAIL — input_validation (high)
**Payload:** `{"user_id": -1}`
**Justification:** Server returned unhandled exception with full stack trace...

### PASS — error_handling (-)
...

## execute_query
...
```

`render_json` uses `report.model_dump(mode="json")` — Pydantic handles enum serialization.

### `src/mcp_auditor/console.py`

Rich-based display for streaming audit progress. Encapsulates all `rich` usage in one module.

```python
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

class AuditDisplay:

    def __init__(self, console: Console | None = None):
        self._console = console or Console()

    def print_header(self, target_command: str) -> None: ...

    def print_discovery(self, tool_count: int, tool_names: list[str]) -> None: ...

    def print_tool_start(self, tool_index: int, tool_count: int, tool_name: str, case_count: int) -> None: ...

    def print_verdict(self, case_index: int, case_count: int, category: str, description: str, verdict: str, severity: str) -> None: ...

    def print_tool_done(self, tool_name: str, pass_count: int, fail_count: int) -> None: ...

    def print_summary_table(self, report: AuditReport) -> None: ...

    def print_cost(self, usage: TokenUsage) -> None: ...

    def print_dry_run_payloads(self, tool_name: str, cases: list[AuditPayload]) -> None: ...

    def print_report_path(self, path: str) -> None: ...
```

This is NOT a port — it's presentation infrastructure, only used by the CLI. The graph doesn't know about it.

### `src/mcp_auditor/cli.py` (rewrite)

```python
import asyncio
import hashlib
from pathlib import Path

import click
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver  # type: ignore[import-untyped]

from mcp_auditor.adapters.llm import AnthropicLLM
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.console import AuditDisplay
from mcp_auditor.graph.builder import build_graph
from mcp_auditor.domain.rendering import render_json, render_markdown


@click.group()
@click.version_option()
def cli() -> None:
    """Agentic QA & fuzzing for MCP servers."""


@cli.command()
@click.argument("target", nargs=-1, required=True)
@click.option("--budget", default=10, type=click.IntRange(min=1), help="Test cases per tool.", show_default=True)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write JSON report to file.")
@click.option("--markdown", "-m", type=click.Path(), default=None, help="Write Markdown report to file.")
@click.option("--resume", is_flag=True, help="Resume interrupted audit.")
@click.option("--dry-run", is_flag=True, help="Generate payloads without executing.")
def run(target: tuple[str, ...], budget: int, output: str | None, markdown: str | None, resume: bool, dry_run: bool) -> None:
    """Audit an MCP server.

    TARGET is the command to start the MCP server.

    Examples:

        mcp-auditor run -- python my_server.py

        mcp-auditor run --budget 5 -- npx some-mcp-server
    """
    asyncio.run(_run_audit(target, budget, output, markdown, resume, dry_run))


async def _run_audit(...) -> None:
    command, args = target[0], list(target[1:])
    display = AuditDisplay()
    target_str = f"{command} {' '.join(args)}"
    display.print_header(target_str)

    llm = AnthropicLLM()

    checkpoint_path = Path.home() / ".mcp-auditor" / "checkpoints.db"
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

    async with AsyncSqliteSaver.from_conn_string(str(checkpoint_path)) as checkpointer:
      async with StdioMCPClient.connect(command, args) as mcp_client:
        if dry_run:
            await _run_dry_run(llm, mcp_client, budget, display)
            return

        graph = build_graph(llm, mcp_client, checkpointer=checkpointer)
        thread_id = _compute_thread_id(command, args)
        config = {"configurable": {"thread_id": thread_id}}

        if not resume:
            # Clear previous checkpoint for this thread so we start fresh
            pass  # implementation: clear thread checkpoint

        initial_state = {"test_budget": budget}

        # Stream graph execution
        async for event in graph.astream(initial_state, config, stream_mode="updates"):
            _handle_stream_event(event, display, ...)

        # Get final state
        final = await graph.aget_state(config)
        report = final.values["audit_report"]

        display.print_summary_table(report)
        display.print_cost(report.token_usage)
        _write_reports(report, output, markdown, display)


async def _run_dry_run(llm: LLMPort, mcp_client: MCPClientPort, budget: int, display: AuditDisplay) -> None:
    tools = await mcp_client.list_tools()
    display.print_discovery(len(tools), [t.name for t in tools])
    for tool in tools:
        prompt = build_attack_generation_prompt(
            tool_name=tool.name,
            tool_description=tool.description,
            input_schema=tool.input_schema,
            budget=budget,
            categories=list(AuditCategory),
        )
        batch = await llm.generate_structured(prompt, TestCaseBatch)
        display.print_dry_run_payloads(tool.name, batch.cases)


def _compute_thread_id(command: str, args: list[str]) -> str:
    """Deterministic thread ID from the target command. Allows --resume to find previous state."""
    raw = f"{command} {' '.join(args)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _handle_stream_event(event: dict, display: AuditDisplay, ...) -> None:
    # Parent nodes produce {str: state_update}. Subgraph nodes (inside audit_tool)
    # produce {tuple: state_update} with keys like ("audit_tool", "generate_test_cases").
    # - "discover_tools" -> display.print_discovery(...)
    # - ("audit_tool", "generate_test_cases") -> display.print_tool_start(...)
    # - ("audit_tool", "judge_response") -> display.print_verdict(...)
    # - "finalize_tool_audit" -> display.print_tool_done(...)


def _write_reports(report: AuditReport, json_path: str | None, md_path: str | None, display: AuditDisplay) -> None:
    if json_path:
        Path(json_path).write_text(render_json(report))
        display.print_report_path(json_path)
    if md_path:
        Path(md_path).write_text(render_markdown(report))
        display.print_report_path(md_path)


def main() -> None:
    cli()
```

**Entry point**: `main()` calls `cli()` (the click group). `pyproject.toml` already points to `mcp_auditor.cli:main`.

**Target parsing**: `ARGUMENT("target", nargs=-1)` captures everything after `--`. First element is command, rest are args. Example: `mcp-auditor run -- python tests/dummy_server.py` → `target = ("python", "tests/dummy_server.py")`.

### `tests/unit/test_rendering.py` + `test_rendering_given.py` + `test_rendering_then.py`

Tests for rendering functions with known `AuditReport` fixtures:

- `test_json_serializes_full_report` — round-trip: render → parse → assert structure matches.
- `test_json_contains_all_tool_reports` — verify all tools present in output.
- `test_markdown_contains_tool_sections` — each tool has a `## tool_name` heading.
- `test_markdown_contains_findings` — FAIL results appear with severity and justification.
- `test_markdown_summary_counts` — summary section has correct counts (tools, findings, per-severity).
- `test_markdown_pass_results_included` — PASS results appear but without severity.
- `test_summary_line` — `render_summary` produces a compact one-liner.
- `test_empty_report` — no tools, no findings → graceful output, not an error.

### `tests/unit/test_console.py`

Tests for `AuditDisplay` with a captured `Console(file=StringIO())`:

- `test_header_shows_target` — banner includes target command.
- `test_verdict_shows_pass_fail` — FAIL verdicts are distinguishable from PASS.
- `test_summary_table_has_all_tools` — summary table includes all tool names.
- `test_dry_run_shows_payloads` — payloads are displayed with arguments.

## Files to modify

### `src/mcp_auditor/graph/builder.py`

Add optional `checkpointer` parameter to `build_graph`:

```python
from langgraph.checkpoint.base import BaseCheckpointSaver  # type: ignore[import-untyped]

def build_graph(
    llm: LLMPort,
    mcp_client: MCPClientPort,
    checkpointer: BaseCheckpointSaver | None = None,
) -> CompiledStateGraph:
    ...
    return builder.compile(checkpointer=checkpointer)
```

The subgraph compilation remains without checkpointer (LangGraph checkpoints at the parent graph level).

### `pyproject.toml`

Add `click` and `rich` to dependencies:

```toml
dependencies = [
    "langgraph>=1.0",
    "langchain-anthropic>=1.0",
    "langchain-core>=1.0",
    "mcp>=1.0.0",
    "pydantic>=2.0",
    "langgraph-checkpoint-sqlite>=3.0",
    "click>=8.1",
    "rich>=13.0",
]
```

## Files to modify (domain)

### `src/mcp_auditor/domain/models.py`

Add `target: str` to `AuditReport`:

```python
class AuditReport(BaseModel):
    target: str
    tool_reports: list[ToolReport]
    token_usage: TokenUsage
```

The target command is part of the audit's identity — a report without it is incomplete. This eliminates the need to pass `target` as a separate parameter to rendering functions and through the CLI wiring.

### `src/mcp_auditor/graph/nodes.py`

Update `make_generate_report` to include `target` in the `AuditReport`. The target command is available in the graph state — add `target: str` to `GraphState` (set by the CLI as initial state).

### `src/mcp_auditor/graph/state.py`

Add `target: str` to `GraphState`:

```python
class GraphState(TypedDict):
    target: str
    discovered_tools: list[ToolDefinition]
    ...
```

### Existing tests

Update `test_graph_given.py` to include `target` in `an_initial_state()`. Update `test_graph_then.py` / `test_graph.py` as needed for the new `AuditReport.target` field.

## What stays unchanged

- `domain/ports.py` — no new ports. Console display is not a port (it's presentation, not a domain abstraction).
- `graph/nodes.py` — nodes are unaware of CLI, streaming, or checkpointing.
- `graph/state.py` — state types unchanged.
- `graph/prompts.py` — prompts unchanged.
- `adapters/llm.py` — adapter unchanged.
- `adapters/mcp_client.py` — adapter unchanged.
- All existing tests — no changes.

## Checkpointing details

**Creation**: The CLI creates `AsyncSqliteSaver` as an async context manager, passes it to `build_graph`.

```python
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

checkpoint_path = Path.home() / ".mcp-auditor" / "checkpoints.db"
checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

async with AsyncSqliteSaver.from_conn_string(str(checkpoint_path)) as checkpointer:
    graph = build_graph(llm, mcp_client, checkpointer=checkpointer)
    ...
```

**Thread ID**: `sha256(command + args)[:16]`. Same target command → same thread → resumable.

**`--resume` behavior**:
- Without `--resume`: always start fresh (new invocation, graph starts from START).
- With `--resume`: invoke the graph with the same thread_id + config. LangGraph picks up from the last checkpointed node.
- If no checkpoint exists for the thread_id, `--resume` starts from scratch (no error).

**Checkpoint location**: `~/.mcp-auditor/checkpoints.db`. Not in the project directory (the auditor may be run from anywhere).

**Without `--resume`**: still use a checkpointer (for crash recovery), but generate a fresh thread_id with a random suffix so it never conflicts with previous runs. This way, if the process crashes mid-audit, the user can re-run with `--resume` to pick up.

Actually, simpler: always use the deterministic thread_id. Without `--resume`, clear the thread's checkpoint before starting. With `--resume`, keep it. This way the user doesn't need to know about thread IDs.

## Dry-run mode

`--dry-run` bypasses the graph entirely:
1. Connect to MCP server.
2. Discover tools.
3. For each tool, call `build_attack_generation_prompt` + `llm.generate_structured(prompt, TestCaseBatch)`.
4. Display each payload (tool name, category, description, arguments) in a rich table.
5. Exit.

No execution, no judging, no report file. Token cost is shown (generation only).

This lets users review attack payloads before running them against servers with real side effects.

## Stream event handling

`graph.astream(state, config, stream_mode="updates")` yields dicts of `{node_name: state_update}` after each node completes.

Event routing:

Parent graph nodes emit events keyed by node name. Subgraph nodes (inside `audit_tool`) emit events with **tuple keys** like `("audit_tool", "generate_test_cases")`. The event handler must check for both string and tuple keys.

| Event key | Graph level | Display action |
|---|---|---|
| `"discover_tools"` | parent | `print_discovery(len(tools), names)` |
| `"prepare_tool"` | parent | (no display -- internal routing) |
| `("audit_tool", "generate_test_cases")` | subgraph | `print_tool_start(index, count, name, len(cases))` |
| `("audit_tool", "execute_tool")` | subgraph | (no display -- wait for verdict) |
| `("audit_tool", "judge_response")` | subgraph | `print_verdict(case_index, count, category, desc, verdict, severity)` |
| `"finalize_tool_audit"` | parent | `print_tool_done(name, pass_count, fail_count)` |
| `"generate_report"` | parent | (handled after stream ends) |

The exact subgraph event format depends on the LangGraph version. The implementation should use `stream_mode="updates"` with `subgraphs=True` to receive subgraph events, and normalize event keys (tuples vs flat strings) defensively. Test against real `astream` output to confirm.

## Edge cases

- **No tools discovered**: graph routes to `generate_report` with empty tool_reports. Display shows "No tools found" warning. Report files are still written (empty report).
- **Target command fails to start**: `StdioMCPClient.connect()` raises. CLI catches the error, prints a clear message ("Failed to connect to MCP server: ..."), exits with code 1.
- **LLM API key missing**: `AnthropicLLM` creation fails. CLI catches and suggests setting `ANTHROPIC_API_KEY`.
- **KeyboardInterrupt during audit**: checkpoint preserves progress. User can `--resume`.
- **`--output` path not writable**: click validates path type, but we should catch `OSError` on write.
- **Budget < 1**: validate in click (`type=click.IntRange(min=1)`).

## Test scenarios

### `test_rendering.py`

| Test | Given | Then |
|---|---|---|
| `test_json_round_trip` | report with 2 tools, 5 results | JSON parses back to equivalent dict |
| `test_json_enum_values` | report with FAIL/PASS verdicts | JSON has string values "pass"/"fail" |
| `test_markdown_tool_sections` | report with tools "get_user", "list_items" | markdown contains `## get_user` and `## list_items` |
| `test_markdown_contains_target` | report with target "python dummy_server.py" | markdown contains the target string |
| `test_markdown_finding_details` | report with FAIL result (high severity) | markdown contains severity, category, justification |
| `test_markdown_summary_stats` | report with known counts | summary contains "2" tools, correct finding counts |
| `test_markdown_empty_report` | report with no tools | valid markdown, no crash |
| `test_summary_one_liner` | report with findings | compact string with counts |

### `test_console.py`

| Test | Given | Then |
|---|---|---|
| `test_header_contains_target` | `print_header("python server.py")` | captured output contains "python server.py" |
| `test_verdict_fail_colored` | `print_verdict(... verdict="fail", severity="high")` | output contains "FAIL" and "high" |
| `test_discovery_shows_count` | `print_discovery(3, ["a","b","c"])` | output contains "3" and tool names |
| `test_dry_run_shows_arguments` | payloads with specific args | output contains the argument values |

## Verification

```bash
# Unit tests pass
uv run pytest tests/unit -v

# Type check
uv run pyright

# Lint
uv run ruff check .

# CLI help works
uv run mcp-auditor --help
uv run mcp-auditor run --help

# Dry run against honeypot (requires ANTHROPIC_API_KEY)
uv run mcp-auditor run --dry-run --budget 3 -- python tests/dummy_server.py

# Full E2E (requires ANTHROPIC_API_KEY)
uv run mcp-auditor run --budget 3 -o report.json -m report.md -- python tests/dummy_server.py

# Resume after Ctrl+C
uv run mcp-auditor run --resume --budget 3 -- python tests/dummy_server.py
```

## Implementation steps

### Step 1: Domain model update + report rendering module with tests

**Files**:
- `pyproject.toml` (modify)
- `src/mcp_auditor/domain/models.py` (modify — add `target` to `AuditReport`)
- `src/mcp_auditor/graph/state.py` (modify — add `target` to `GraphState`)
- `src/mcp_auditor/graph/nodes.py` (modify — pass `target` in `make_generate_report`)
- `tests/unit/test_graph_given.py` (modify — add `target` to initial state)
- `tests/unit/test_rendering_given.py` (create)
- `tests/unit/test_rendering_then.py` (create)
- `tests/unit/test_rendering.py` (create)
- `src/mcp_auditor/domain/rendering.py` (create)

**Do**:

1. Add `"click>=8.1"` and `"rich>=13.0"` to `[project.dependencies]` in `pyproject.toml`, then run `uv sync` to install them.

2. Update `src/mcp_auditor/domain/models.py`: add `target: str` field to `AuditReport` (before `tool_reports`).

3. Update `src/mcp_auditor/graph/state.py`: add `target: str` field to `GraphState`.

4. Update `src/mcp_auditor/graph/nodes.py`: in `make_generate_report`, read `state["target"]` and pass it to `AuditReport(target=..., ...)`.

5. Update `tests/unit/test_graph_given.py`: add `"target": "python dummy_server.py"` to `an_initial_state()`. Run `uv run pytest tests/unit` to verify all existing tests still pass.

6. Create `tests/unit/test_rendering_given.py` with factory functions for test fixtures:
   - `a_tool_definition(name, description)` -> `ToolDefinition`
   - `a_pass_result(tool_name, category)` -> `EvalResult` with verdict=PASS, severity=LOW
   - `a_fail_result(tool_name, category, severity, justification)` -> `EvalResult` with verdict=FAIL
   - `a_tool_report(tool_name, results)` -> `ToolReport` wrapping a `ToolDefinition` and results list
   - `a_report(target, tool_reports, input_tokens, output_tokens)` -> `AuditReport` with given target, `ToolReport` list and `TokenUsage`
   - `an_empty_report()` -> `AuditReport` with target `"python dummy_server.py"`, empty `tool_reports` and zero `TokenUsage`
   - `a_two_tool_report()` -> builds a full report with target `"python dummy_server.py"`, tools "get_user" (2 FAIL results: high input_validation, critical injection) and "list_items" (1 PASS result: error_handling), token usage 15234/8421. This is the primary fixture for most tests.

7. Create `tests/unit/test_rendering_then.py` with assertion helpers:
   - `json_round_trips(json_str, expected_tool_count)` -> parses JSON string, asserts `tool_reports` list has `expected_tool_count` entries, asserts `token_usage` key exists
   - `json_has_enum_strings(json_str)` -> parses JSON, walks all `verdict` and `severity` fields, asserts they are lowercase strings (not enum repr)
   - `markdown_contains_tool_headings(md, tool_names)` -> asserts `## <name>` present for each tool
   - `markdown_contains_finding(md, category, severity, justification_fragment)` -> asserts all three strings appear in the markdown
   - `markdown_summary_has_counts(md, tools, findings, per_severity_dict)` -> asserts the summary section contains the expected numeric counts
   - `markdown_includes_pass_without_severity(md)` -> asserts "PASS" appears, and the line containing "PASS" does not contain a severity word

8. Create `tests/unit/test_rendering.py` with these test functions (all sync, no async needed):
   - `test_json_round_trip` -- uses `a_two_tool_report()`, calls `render_json`, asserts via `json_round_trips(result, 2)`
   - `test_json_enum_values` -- same fixture, calls `render_json`, asserts via `json_has_enum_strings(result)`
   - `test_markdown_tool_sections` -- calls `render_markdown(report)`, asserts via `markdown_contains_tool_headings(result, ["get_user", "list_items"])`
   - `test_markdown_finding_details` -- asserts via `markdown_contains_finding(result, "input_validation", "high", ...)` using the justification text from the fixture
   - `test_markdown_summary_stats` -- asserts via `markdown_summary_has_counts(result, tools=2, findings=2, per_severity={"high": 1, "critical": 1})`
   - `test_markdown_pass_results_included` -- asserts via `markdown_includes_pass_without_severity(result)`
   - `test_markdown_empty_report` -- uses `an_empty_report()`, calls `render_markdown`, asserts no crash and result contains "0" for tools/findings
   - `test_summary_one_liner` -- calls `render_summary(report)`, asserts it is a single line containing tool count and finding count

9. Create `src/mcp_auditor/domain/rendering.py` with three public functions:
   - `render_summary(report: AuditReport) -> str` -- returns a single-line string like `"python dummy_server.py: 2 tools, 2 findings (1 critical, 1 high)"`. Uses `report.target`. Count findings = results where verdict is FAIL. Group by severity. If no findings, say "no findings".
   - `render_json(report: AuditReport) -> str` -- calls `report.model_dump(mode="json")` and returns `json.dumps(data, indent=2)`.
   - `render_markdown(report: AuditReport) -> str` -- builds the markdown template from the plan: header, summary section (target from `report.target`, tools audited, test cases, findings with per-severity breakdown, token usage), then a `## tool_name` section per tool with each result as `### VERDICT -- category (severity)` with payload and justification. For PASS verdicts, omit severity (show `-` instead). Extract private helpers: `_render_summary_section`, `_render_tool_section`, `_render_result_section`. Keep each under 20 lines.

**Test**: Run `uv run pytest tests/unit/test_rendering.py -v`. All 8 tests pass.

**Verify**:
```bash
uv run pytest tests/unit -v
uv run ruff check src/mcp_auditor/domain/rendering.py tests/unit/test_rendering*.py
uv run pyright src/mcp_auditor/domain/rendering.py tests/unit/test_rendering*.py
```

---

### Step 2: Console display, graph checkpointer support, and CLI wiring

**Files**:
- `tests/unit/test_console.py` (create)
- `src/mcp_auditor/console.py` (create)
- `src/mcp_auditor/graph/builder.py` (modify)
- `src/mcp_auditor/cli.py` (rewrite)

**Do**:

1. Create `tests/unit/test_console.py` with tests that capture output via `Console(file=StringIO(), force_terminal=True)`:
   - `test_header_contains_target` -- calls `display.print_header("python server.py")`, asserts captured output contains "python server.py"
   - `test_verdict_fail_shows_severity` -- calls `display.print_verdict(1, 5, "injection", "SQL injection test", "fail", "high")`, asserts output contains "FAIL" and "high"
   - `test_verdict_pass_displayed` -- calls `display.print_verdict(...)` with verdict="pass", asserts output contains "PASS"
   - `test_discovery_shows_count_and_names` -- calls `display.print_discovery(3, ["a", "b", "c"])`, asserts output contains "3" and each tool name
   - `test_summary_table_has_tool_names` -- builds an `AuditReport` with two tool reports (use inline construction, not given.py -- simple enough), calls `display.print_summary_table(report)`, asserts both tool names in output
   - `test_dry_run_shows_arguments` -- builds a list of `AuditPayload` objects with specific arguments, calls `display.print_dry_run_payloads("get_user", payloads)`, asserts argument values appear in output
   - No given/then extraction needed -- the test file is simple enough to inline everything. Each test is a few lines of setup + one call + one string-contains assertion on `StringIO.getvalue()`.

2. Create `src/mcp_auditor/console.py` implementing `AuditDisplay` exactly as specified in the plan:
   - Constructor takes optional `Console`. Default creates a new one.
   - `print_header(target_command)` -- prints a `Panel` with title "MCP Auditor" containing the target command.
   - `print_discovery(tool_count, tool_names)` -- prints count and comma-separated tool names.
   - `print_tool_start(tool_index, tool_count, tool_name, case_count)` -- prints e.g. `"[2/5] get_user (10 test cases)"`.
   - `print_verdict(case_index, case_count, category, description, verdict, severity)` -- prints a line with PASS (green) or FAIL (red) with severity and category. Use `rich.text.Text` for coloring.
   - `print_tool_done(tool_name, pass_count, fail_count)` -- prints summary line for the tool.
   - `print_summary_table(report: AuditReport)` -- builds a `Table` with columns: Tool, Tests, Pass, Fail, and rows per tool_report. Uses green/red styling for pass/fail counts.
   - `print_cost(usage: TokenUsage)` -- prints formatted token counts.
   - `print_dry_run_payloads(tool_name, cases: list[AuditPayload])` -- builds a `Table` with columns: Category, Description, Arguments. One row per case.
   - `print_report_path(path: str)` -- prints the path where report was written.

3. Modify `src/mcp_auditor/graph/builder.py`:
   - Add import: `from langgraph.checkpoint.base import BaseCheckpointSaver`
   - Add optional `checkpointer: BaseCheckpointSaver | None = None` parameter to `build_graph`.
   - Pass `checkpointer=checkpointer` to `builder.compile()` at the end.
   - The subgraph compilation remains unchanged (no checkpointer).
   - Update the pyright suppression comment at the top if needed to include the new import.

4. Rewrite `src/mcp_auditor/cli.py` with the full click-based CLI as specified in the plan:
   - `cli()` -- click group with `@click.version_option()`.
   - `run()` command with options: `target` (nargs=-1), `--budget` (default 10, IntRange min=1), `--output/-o`, `--markdown/-m`, `--resume`, `--dry-run`. Calls `asyncio.run(_run_audit(...))`.
   - `_run_audit(target, budget, output, markdown, resume, dry_run)` -- async function:
     - Parses command/args from target tuple.
     - Creates `AuditDisplay`, prints header.
     - Creates `AnthropicLLM`.
     - Sets up `AsyncSqliteSaver` at `~/.mcp-auditor/checkpoints.db`.
     - Connects `StdioMCPClient`.
     - If `dry_run`, calls `_run_dry_run` and returns.
     - Otherwise: builds graph with checkpointer, computes thread_id, streams execution via `graph.astream(initial_state, config, stream_mode="updates", subgraphs=True)`.
     - Calls `_handle_stream_event` for each event.
     - After stream: gets final state, extracts report, prints summary table and cost, writes report files.
   - `_run_dry_run(llm, mcp_client, budget, display)` -- discovers tools, generates test cases per tool, displays payloads.
   - `_compute_thread_id(command, args)` -- SHA256 hash of command string, truncated to 16 chars.
   - `_handle_stream_event(event, display, state_tracker)` -- routes events by key (string or tuple) to appropriate display methods. Uses a simple mutable dict/object to track tool_index, case_index, etc. across events.
   - `_write_reports(report, json_path, md_path, display)` -- writes JSON and/or markdown files. Target is in `report.target`, no need to pass separately.
   - `main()` -- calls `cli()`.
   - Wrap the `_run_audit` body in a try/except for `ConnectionError` (MCP server fails), `KeyError`/`ValueError` for missing API key, and `OSError` for file write failures. Print clear error messages via `click.echo` and `raise SystemExit(1)`.

**Test**: Run full unit test suite. All existing tests still pass. New console tests pass.

**Verify**:
```bash
uv run pytest tests/unit -v
uv run ruff check src/mcp_auditor/console.py src/mcp_auditor/cli.py src/mcp_auditor/graph/builder.py
uv run pyright src/mcp_auditor/console.py src/mcp_auditor/cli.py src/mcp_auditor/graph/builder.py
uv run mcp-auditor --help
uv run mcp-auditor run --help
```
