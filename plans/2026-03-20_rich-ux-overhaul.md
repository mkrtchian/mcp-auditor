# Plan: Rich UX Overhaul

## Context

The CLI output is functional but rudimentary. Every verdict prints a full line (100 cases = 100 lines of noise), there are no spinners during LLM calls, no progress bars, and the eval runners use raw `print()`. The tool already depends on `rich>=13.0` but barely uses its capabilities.

This plan refactors the console output layer (`console.py`), the CLI event handling (`cli.py`), and the eval runners (`run_evals.py`, `run_judge_eval.py`) to provide a polished, informative UX using Rich Live, Progress, Status, and Tables.

The graph, domain models, adapters, ports, prompts, and rendering are **not touched**.

## Approach

### Audit CLI (`console.py` + `cli.py`)

Replace the current line-by-line output with a Rich Live display:

- **Header**: Rich Panel (unchanged)
- **Discovery**: spinner while connecting, then tool list
- **Per-tool progress**: Rich Progress bar that advances as cases are judged. Only FAIL verdicts print below the bar (with category, severity, description). PASS verdicts are silent — they just advance the bar.
- **Per-tool summary**: compact one-liner after progress completes (e.g. `✓ all passed` or `✗ 2 failed (1 high, 1 medium)`)
- **Final summary**: Rich Table inside a Panel, with a score line and token usage
- **Errors**: Rich Console `print` with `[red]` markup instead of `click.echo`

Target output:

```
╭─ MCP Auditor ─────────────────────────────────╮
│ python my_server.py                            │
╰────────────────────────────────────────────────╯

Discovering tools...  ⠋
Found 3 tools: get_user, create_post, delete_item

[1/3] get_user ━━━━━━━━━━━━━━━━━━━━ 10/10
  ✗ injection (high): SQL injection via user_id
  ✗ input_validation (medium): Negative ID accepted

[2/3] create_post ━━━━━━━━━━━━━━━━━ 10/10  ✓ all passed

[3/3] delete_item ━━━━━━━━━━━━━━━━━ 10/10
  ✗ resource_abuse (high): No rate limiting on bulk delete

╭─ Results ──────────────────────────────────────╮
│                                                │
│  Tool           Tests   Pass   Fail            │
│  get_user         10      8      2             │
│  create_post      10     10      0             │
│  delete_item      10      7      3             │
│                                                │
│  Score: 25/30 (83%)                            │
│  Tokens: 12,450 in / 3,200 out                │
│                                                │
╰────────────────────────────────────────────────╯

Report written to: report.json
```

### Dry-run CLI

Same header/discovery, then per-tool tables with a spinner during generation.

### Eval runners (`run_evals.py`, `run_judge_eval.py`)

Replace raw `print()` with Rich:

- Progress bar for runs and individual judge calls
- Colored metrics table with PASS/FAIL per threshold
- Confusion matrix as a small Rich Table

### Key design decisions

**Rich Live vs Rich Progress**: Use `rich.progress.Progress` for the per-tool case tracking. Progress handles the bar rendering and integrates well with printing below it via `progress.console.print()`. No need for `rich.live.Live` — Progress already provides live-updating display. This avoids the complexity of managing a Live layout manually.

**No port for display**: `AuditDisplay` stays as presentation infrastructure in `console.py`, not a domain port. The graph doesn't know about it.

**Testability**: `AuditDisplay` accepts an optional `Console`. Tests inject `Console(file=StringIO(), force_terminal=True)` to capture output. For Progress-based methods, tests verify the *final* console output (what was printed), not internal Progress state.

## Files to modify

### `src/mcp_auditor/console.py` (rewrite)

Current `AuditDisplay` class is replaced with a new implementation. Same public interface philosophy (display object with methods), but the internals change significantly.

```python
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, MofNCompleteColumn
from rich.status import Status
from rich.table import Table
from rich.text import Text

from mcp_auditor.domain.models import AuditPayload, AuditReport, EvalResult, TokenUsage


class AuditDisplay:
    def __init__(self, console: Console | None = None):
        self._console = console or Console()

    def print_header(self, target_command: str) -> None:
        """Panel with target command."""

    def print_discovery(self, tool_count: int, tool_names: list[str]) -> None:
        """'Found N tools: a, b, c'"""

    def create_tool_progress(self, tool_index: int, tool_count: int, tool_name: str, case_count: int) -> "ToolProgress":
        """Returns a ToolProgress context manager for tracking cases."""

    def print_summary(self, report: AuditReport) -> None:
        """Final results panel with table, score, and token usage."""

    def print_dry_run_payloads(self, tool_name: str, cases: list[AuditPayload]) -> None:
        """Table of generated payloads for dry-run mode."""

    def print_report_path(self, path: str) -> None:
        """'Report written to: path'"""

    def print_error(self, message: str) -> None:
        """Red error message. Replaces click.echo(..., err=True)."""

    def status(self, message: str) -> Status:
        """Returns a Rich Status context manager for spinner display."""
```

Pure functions for tool progress formatting (in same module, above `ToolProgress`):

```python
def format_failure_line(result: EvalResult) -> str:
    """'  ✗ injection (high): SQL injection via user_id'"""

def format_tool_summary(fail_count: int, pass_count: int, failures: list[EvalResult]) -> str:
    """'✓ all passed' or '✗ 2 failed (1 high, 1 medium)'"""
```

These are pure `(data) -> str` functions — no Rich dependency, trivially testable.

New `ToolProgress` class (in same module):

```python
class ToolProgress:
    """Context manager that wraps Rich Progress for a single tool's test cases."""

    def __init__(self, console: Console, tool_label: str, case_count: int):
        ...

    def __enter__(self) -> "ToolProgress":
        """Starts the progress bar."""

    def __exit__(self, *args) -> None:
        """Stops progress, prints formatted summary via format_tool_summary()."""

    def advance(self, result: EvalResult) -> None:
        """Advance bar by 1. If FAIL, print format_failure_line(result) below the bar."""
```

Key behaviors:
- `ToolProgress.__exit__` prints `format_tool_summary(self._fail_count, self._pass_count, self._failures)` — the formatting logic is in the pure function, the class just calls `console.print()` with the result
- `ToolProgress.advance` on FAIL prints `format_failure_line(result)` below the progress bar using `self._progress.console.print()`
- Progress bar format: `[1/3] tool_name ━━━━━━━━━━━━ 7/10`

### `src/mcp_auditor/cli.py` (modify)

Changes:
1. Replace `click.echo(..., err=True)` with `display.print_error(...)` (4 occurrences)
2. Refactor `_handle_subgraph_event` to use `ToolProgress` instead of individual `print_verdict` / `print_tool_start` calls
3. Add `display.status("Discovering tools...")` spinner: in `_run_dry_run`, wrap the `list_tools()` call with a `with` block. In `_run_full_audit`, start the spinner before the `astream` loop and stop it inside `_handle_parent_event` when the `discover_tools` event arrives (manual `__enter__`/`__exit__`, same pattern as ToolProgress). Store the active status in the tracker.
4. Add `display.status("Generating test cases...")` spinner in the subgraph event handler (between `generate_test_cases` completing and the first `judge_response`)
5. Replace `display.print_summary_table(report)` + `display.print_cost(usage)` with single `display.print_summary(report)`
6. Remove `print_tool_done` calls (replaced by `ToolProgress.__exit__`)

The tracker dict needs a new key to hold the active `ToolProgress` instance:

```python
tracker: dict[str, Any] = {
    "tool_index": 0,
    "tool_count": 0,
    "active_progress": None,  # ToolProgress | None
}
```

Event flow changes:
- `generate_test_cases` event (subgraph, in `_handle_subgraph_event`) → create `ToolProgress` via `display.create_tool_progress(...)`, store in tracker, enter context
- `judge_response` event (subgraph, in `_handle_subgraph_event`) → call `tracker["active_progress"].advance(result)`
- `finalize_tool_audit` event (parent, in `_handle_parent_event`) → exit `ToolProgress` context (prints summary), set tracker to None

**Important**: Rich Progress uses a Live display internally. The Progress context manager must be entered/exited correctly across stream events. Since events arrive one at a time in the async for loop, we manually manage `__enter__`/`__exit__` on `ToolProgress` rather than using `with` blocks. This is the standard pattern for long-lived progress tracking across event-driven code.

### `evals/run_evals.py` (modify)

Changes:
1. Add `from rich.console import Console` and `from rich.progress import Progress` and `from rich.table import Table`
2. Replace `print(f"\nRunning eval {i + 1}/{num_runs}...")` with Rich Progress bar over runs
3. Replace `_print_run_result` with Rich-formatted per-run output (compact, with colors)
4. Replace `_print_summary` with a Rich Table showing metrics vs thresholds with PASS/FAIL coloring
5. Replace `_print_metric_line` with table rows
6. Replace `print("\nAll thresholds met.")` / `"Some thresholds not met."` with colored Panel

Target output for `_print_summary`:

```
╭─ Eval Results ─────────────────────────────────╮
│                                                │
│  Metric         Value   Threshold   Status     │
│  Recall          0.87      0.80     PASS       │
│  Precision       0.92      0.85     PASS       │
│  Consistency     0.78      0.70     PASS       │
│  Distribution    0.85      0.80     PASS       │
│                                                │
╰────────────────────────────────────────────────╯
```

### `evals/run_judge_eval.py` (modify)

Changes:
1. Replace `print(f"Running judge eval ({len(loaded_cases)} cases)...")` with spinner
2. Replace `print(f"  [{i}/{len(cases)}] ...")` in `_judge_all_cases` with Rich Progress bar
3. Replace `_print_summary` with Rich Table for metrics + confusion matrix

Target output for `_print_summary`:

```
╭─ Judge Eval Results ───────────────────────────╮
│                                                │
│  F1: 0.93 (threshold: 0.90) PASS              │
│  Precision: 0.95  Recall: 0.91                │
│                                                │
│  Confusion Matrix:                             │
│    TP: 21  FP: 1                               │
│    FN: 2   TN: 6                               │
│                                                │
│  Per-category:                                 │
│    injection          P=1.00 R=0.90 F1=0.95   │
│    input_validation   P=0.88 R=1.00 F1=0.93   │
│    ...                                         │
│                                                │
╰────────────────────────────────────────────────╯
```

## What stays unchanged

- `domain/models.py` — no model changes
- `domain/ports.py` — no new ports
- `domain/rendering.py` — JSON/Markdown rendering unchanged
- `graph/` — all graph logic, nodes, state, prompts, builder unchanged
- `adapters/` — LLM and MCP client adapters unchanged
- `evals/metrics.py`, `evals/judge_metrics.py`, `evals/ground_truth.py`, `evals/export.py` — eval logic unchanged
- `tests/integration/` — integration tests unchanged
- `tests/unit/` — all tests except `test_console.py` unchanged

## Edge cases

- **Console without terminal** (piped output, CI): Rich detects non-interactive terminals and disables animations. Progress bars render as static lines. No special handling needed — Rich's auto-detection handles it.
- **Very long tool names**: Progress bar format truncates gracefully (Rich handles this).
- **Zero test cases for a tool**: `ToolProgress` with case_count=0 should skip the progress bar and print a "no cases" message.
- **All passes**: `ToolProgress.__exit__` prints green `✓ all passed` instead of listing nothing.
- **Keyboard interrupt during progress**: `ToolProgress.__exit__` is called, progress bar stops cleanly. Rich handles SIGINT gracefully.

## Testing approach

### `tests/unit/test_console.py` (rewrite)

The existing tests verify behavior (content of output), not implementation details. The new tests follow the same philosophy but adapt to the new API.

Two categories of tests:

**1. Pure formatting functions** — `format_failure_line` and `format_tool_summary` are `(data) -> str`, no Rich dependency. These are tested exhaustively because the logic is interesting (severity breakdown, edge cases).

**2. AuditDisplay methods** — only test methods that use simple `console.print()`. **Do not test `ToolProgress`**: Rich Progress uses `Live` internally, which writes terminal control sequences into the buffer. `ToolProgress` is a thin wrapper that delegates formatting to the pure functions and rendering to Rich — verified manually. Per testing standards: "maintainability beats coverage — delete a fragile test rather than keep it."

```python
# Pure function tests — stable, no Rich dependency
def test_format_failure_line_includes_category_severity_justification():
    result = _a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "SQL injection via user_id")
    line = format_failure_line(result)
    assert "injection" in line
    assert "high" in line
    assert "SQL injection via user_id" in line

def test_format_tool_summary_all_passed():
    assert "passed" in format_tool_summary(fail_count=0, pass_count=5, failures=[]).lower()

def test_format_tool_summary_with_failures():
    failures = [
        _a_fail_result("t", AuditCategory.INJECTION, Severity.HIGH, "x"),
        _a_fail_result("t", AuditCategory.INPUT_VALIDATION, Severity.MEDIUM, "y"),
    ]
    summary = format_tool_summary(fail_count=2, pass_count=3, failures=failures)
    assert "2" in summary
    assert "high" in summary
    assert "medium" in summary

def test_format_tool_summary_zero_cases():
    summary = format_tool_summary(fail_count=0, pass_count=0, failures=[])
    assert "passed" in summary.lower() or "no cases" in summary.lower()

# AuditDisplay tests — simple console.print() output
def test_header_contains_target():
    display, buffer = _make_display()
    display.print_header("python server.py")
    assert "python server.py" in buffer.getvalue()

def test_discovery_shows_count_and_names():
    display, buffer = _make_display()
    display.print_discovery(3, ["a", "b", "c"])
    output = buffer.getvalue()
    assert "3" in output
    assert "a" in output

def test_summary_contains_score_and_tools():
    display, buffer = _make_display()
    report = _a_report_with_two_tools()
    display.print_summary(report)
    output = buffer.getvalue()
    assert "get_user" in output
    assert "list_items" in output

def test_dry_run_shows_arguments():
    # Same as current test, adapted to print_dry_run_payloads
    ...

def test_error_message_displayed():
    display, buffer = _make_display()
    display.print_error("connection failed")
    assert "connection failed" in buffer.getvalue()
```

No given/then extraction — these tests are simple enough to inline. Helpers `_a_fail_result`, `_a_pass_result`, `_a_report_with_two_tools` stay in the test file as private helpers.

### Eval runner tests

The eval runners are **not unit tested** for their display output. They are scripts that orchestrate real LLM calls — testing their Rich output with fakes would be testing implementation, not behavior. The display changes are verified manually by running evals. This follows the testing standards: "maintainability beats coverage."

## Verification

```bash
# Unit tests
uv run pytest tests/unit -v

# Type check
uv run pyright

# Lint + format
uv run ruff check .
uv run ruff format .

# Manual verification: audit
uv run mcp-auditor run --budget 3 -- python tests/dummy_server.py

# Manual verification: dry-run
uv run mcp-auditor run --dry-run --budget 3 -- python tests/dummy_server.py

# Manual verification: evals (requires API key)
uv run python -m evals.run_judge_eval
uv run python -m evals.run_evals --runs 1 --budget 3
```

## Implementation steps

### Step 1: Rewrite console display, update CLI event handling, rewrite console tests

**Files**:
- `tests/unit/test_console.py` (rewrite)
- `src/mcp_auditor/console.py` (rewrite)
- `src/mcp_auditor/cli.py` (modify)

**Do**:

1. **`tests/unit/test_console.py`** -- Rewrite tests for the new API. Keep `_make_display()` helper. Add `_a_fail_result(tool_name, category, severity, justification)` and `_a_pass_result(tool_name, category)` helpers. Keep `_a_report_with_two_tools()`. Tests to write:

   Pure function tests (no Rich dependency, stable):
   - `test_format_failure_line_includes_category_severity_justification` -- assert category, severity, justification all present in output string.
   - `test_format_tool_summary_all_passed` -- 0 fails, 5 passes → "passed" in output.
   - `test_format_tool_summary_with_failures` -- 2 fails (high, medium) → counts and severities in output.
   - `test_format_tool_summary_zero_cases` -- 0/0 → no crash, reasonable message.

   AuditDisplay tests (simple console.print, no ToolProgress):
   - `test_header_contains_target` -- unchanged
   - `test_discovery_shows_count_and_names` -- unchanged
   - `test_summary_contains_score_and_tools` -- call `display.print_summary(report)`. Assert tool names, score info, and token usage appear.
   - `test_dry_run_shows_arguments` -- unchanged conceptually, same method `print_dry_run_payloads`.
   - `test_error_message_displayed` -- call `display.print_error("connection failed")`, assert "connection failed" in output.
   - `test_report_path_displayed` -- call `display.print_report_path("report.json")`, assert path in output.

2. **`src/mcp_auditor/console.py`** -- Full rewrite. Remove old methods (`print_tool_start`, `print_verdict`, `print_tool_done`, `print_summary_table`, `print_cost`). Add pure functions and new classes:

   Pure functions (no Rich dependency):
   - `format_failure_line(result: EvalResult) -> str` -- returns `"  ✗ {category} ({severity}): {justification}"`.
   - `format_tool_summary(fail_count: int, pass_count: int, failures: list[EvalResult]) -> str` -- returns `"✓ all passed"` if `fail_count == 0`, else `"✗ N failed (severity breakdown)"` with counts per severity.

   `ToolProgress` class (thin wrapper — delegates formatting to pure functions, rendering to Rich):
   - `__init__(self, console: Console, tool_label: str, case_count: int)` -- stores console, label, count. Creates `Progress` instance with `TextColumn("{task.description}")`, `BarColumn()`, `MofNCompleteColumn()`. Tracks `_fail_count`, `_pass_count`, `_failures` list.
   - `__enter__(self) -> ToolProgress` -- if `case_count == 0`, print "no cases" and return. Otherwise start Progress context (`self._progress.__enter__()`), add task with description = `tool_label`.
   - `__exit__(self, *args) -> None` -- if `case_count == 0`, return. Stop Progress (`self._progress.__exit__(*args)`). Print `format_tool_summary(...)` with green/red styling.
   - `advance(self, result: EvalResult) -> None` -- advance task by 1. If `result.verdict == FAIL`, print `format_failure_line(result)` below bar using `self._progress.console.print()`. Track counts.

   `AuditDisplay` class (updated):
   - `__init__`, `print_header`, `print_discovery` -- same as current.
   - `create_tool_progress(self, tool_index, tool_count, tool_name, case_count) -> ToolProgress` -- returns `ToolProgress(self._console, f"[{tool_index}/{tool_count}] {tool_name}", case_count)`.
   - `print_summary(self, report: AuditReport) -> None` -- builds a Rich Table (Tool/Tests/Pass/Fail columns) inside a Panel titled "Results". Adds score line (`X/Y (Z%)`) and token usage line below the table.
   - `print_dry_run_payloads` -- same as current.
   - `print_report_path` -- same as current.
   - `print_error(self, message: str) -> None` -- `self._console.print(f"[red]Error: {message}[/red]")`.
   - `status(self, message: str) -> Status` -- returns `self._console.status(message)`.

3. **`src/mcp_auditor/cli.py`** -- Modify:
   - Replace 4 `click.echo(..., err=True)` calls with `display.print_error(...)`. The error messages stay the same minus the "Error: " prefix (since `print_error` adds it). For the pre-display errors (LLM init), create `display = AuditDisplay()` before the try block (already done) and use it.
   - Update `tracker` dict: add `"active_progress": None` key.
   - In `_handle_parent_event` for `finalize_tool_audit`: replace `display.print_tool_done(...)` with exiting the active progress: `if tracker["active_progress"]: tracker["active_progress"].__exit__(None, None, None); tracker["active_progress"] = None`.
   - In `_handle_subgraph_event` for `generate_test_cases`: replace `display.print_tool_start(...)` with creating and entering `ToolProgress`: `progress = display.create_tool_progress(tool_index, tool_count, tool_name, case_count); progress.__enter__(); tracker["active_progress"] = progress`.
   - In `_handle_subgraph_event` for `judge_response`: replace `display.print_verdict(...)` with `tracker["active_progress"].advance(result)` (guard with `if tracker["active_progress"]`).
   - In `_run_full_audit`: replace `display.print_summary_table(report)` + `display.print_cost(report.token_usage)` with `display.print_summary(report)`.
   - In `_run_dry_run`: wrap `mcp_client.list_tools()` with `with display.status("Discovering tools...")`.
   - Remove unused imports if any (`click.echo` may still be needed for non-display uses -- check).

**Test**: The 10 test scenarios listed above. Key assertions:
- Pure functions: `format_failure_line` contains category/severity/justification, `format_tool_summary` handles all-pass, mixed, and zero-cases.
- AuditDisplay: tool names and token counts in summary, error text in error output.
- `ToolProgress` (thin Rich wrapper) verified manually via `mcp-auditor run --budget 3`.

**Verify**:
```bash
uv run pytest tests/unit/test_console.py -v
uv run pytest tests/unit -v
uv run pyright
uv run ruff check .
uv run ruff format .
```

---

### Step 2: Rich UX for eval runners

**Files**:
- `evals/run_evals.py` (modify)
- `evals/run_judge_eval.py` (modify)

**Do**:

1. **`evals/run_evals.py`** -- Replace print-based output with Rich:
   - Add imports: `from rich.console import Console`, `from rich.table import Table`, `from rich.panel import Panel`, `from rich.progress import Progress`.
   - Create module-level `console = Console()`.
   - `main()`: replace `print("\nAll thresholds met.")` / `"Some thresholds not met."` with `console.print(Panel(...))` using green/red styling.
   - `run_evals()`: replace `print(f"\nRunning eval {i + 1}/{num_runs}...")` with a Rich Progress bar over the runs loop. Use `with Progress() as progress:` wrapping the for loop, with a task for the runs. Inside the loop, advance after each run completes.
   - Replace `print(f"  Auditing {honeypot.name}...")` in `_run_one_eval` with `console.print(f"  Auditing [bold]{honeypot.name}[/bold]...")`.
   - `_print_summary()`: rewrite to build a Rich Table with columns (Metric, Value, Threshold, Status). Each row: metric name, formatted value, formatted threshold, PASS (green) or FAIL (red). Wrap in a Panel titled "Eval Results". Print report path below.
   - `_print_run_result()`: use `console.print()` with mild Rich markup (bold tool names).
   - Remove `_print_metric_line()` (folded into the table).

2. **`evals/run_judge_eval.py`** -- Replace print-based output with Rich:
   - Add imports: `from rich.console import Console`, `from rich.table import Table`, `from rich.panel import Panel`, `from rich.progress import Progress`.
   - Create module-level `console = Console()`.
   - `run_judge_eval()`: replace `print(f"Running judge eval ({len(loaded_cases)} cases)...")` with `console.status("Running judge eval...")` or a brief status message.
   - `_judge_all_cases()`: replace the `print(f"  [{i}/{len(cases)}] ...")` loop with Rich Progress bar. Use `with Progress() as progress:` wrapping the for loop.
   - `_print_summary()`: rewrite to build a Rich Panel containing: F1 line with threshold and PASS/FAIL status, Precision and Recall lines, confusion matrix as formatted text, per-category table with columns (Category, P, R, F1). Print report path below.

**Test**: No automated tests for eval runner display (per plan: "verified manually by running evals"). The eval logic (metrics computation, report building) is unchanged and covered by existing tests.

**Verify**:
```bash
uv run pyright
uv run ruff check .
uv run ruff format .
uv run pytest tests/unit -v
```
