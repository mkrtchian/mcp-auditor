# CLI UX Improvements

## Context

The CLI output is functional but lacks a consolidated view of findings after execution. Users must scroll back through execution output to understand *what* failed. The summary table shows pass/fail counts but no severity information. The score line has no visual signal.

These improvements serve both real usability and demo/showcase quality — the final output is what gets screenshotted and recorded in terminal demos.

## Approach

Five changes total. A small domain improvement (expose findings on `AuditReport`) followed by four display-layer improvements. The domain change eliminates duplication between `rendering.py` and `console.py`, both of which currently reconstruct the same findings list ad hoc.

0. **Domain: expose findings on `AuditReport`** — eliminate duplicated collection logic
1. **Findings recap panel** after the summary table
2. **Severity breakdown in the summary table** Fail column
3. **Colored score with progress bar**
4. **Columnar tool discovery** for many tools

## 0. Domain: Expose Findings on AuditReport

### What

Add a `findings` property to `AuditReport` that returns all failed `EvalResult`s. This concept already exists implicitly — `has_findings_at_or_above` iterates findings, `rendering.py` has a private `_collect_findings`, and `console.py` is about to need the same thing. Make it explicit and canonical.

### Files

- `src/mcp_auditor/domain/models.py`: Add a `@property` `findings` on `AuditReport` that returns `list[EvalResult]` — all cases with `eval_result.verdict == FAIL`. This is the single source of truth.
- `src/mcp_auditor/domain/models.py`: Refactor `has_findings_at_or_above` to use `self.findings` instead of duplicating the iteration.
- `src/mcp_auditor/domain/rendering.py`: Delete `_collect_findings`. Replace all calls with `report.findings`.
- `tests/unit/test_console.py` and `tests/unit/test_rendering.py`: No changes needed — they test through public APIs that still behave the same.

### Why

`_collect_findings` in `rendering.py` is a private function that reconstructs domain knowledge. The display layer (`console.py`) is about to need the same data. Rather than duplicate again, promote this to a domain property. Kent Beck: *"Three strikes and you refactor."* Eric Evans: *"Make implicit concepts explicit."*

## 1. Findings Recap Panel

### What

Add a `print_findings_recap(report)` method to `AuditDisplay` that prints a Rich Panel after the summary table, listing all failures grouped by severity (highest first).

### Output (interactive mode)

```
╭─────────────────────────────── Findings ────────────────────────────────────╮
│                                                                              │
│  MEDIUM                                                                      │
│    read_file > info_leakage — error message reveals absolute server path     │
│    move_file > error_handling — returned MCP -32602 instead of graceful...   │
│    move_file > error_handling — returned MCP error for "destination exists"  │
│                                                                              │
│  LOW                                                                         │
│    write_file > info_leakage — error reveals sandbox path                    │
│    write_file > info_leakage — error reveals absolute path                   │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

- Grouped by severity, ordered CRITICAL > HIGH > MEDIUM > LOW.
- Each line: `tool_name > category — justification` (truncated to fit).
- Panel title: "Findings".
- Skipped entirely if no findings (0 failures).

### Output (CI mode)

Plain text, no panel:

```
Findings:
  MEDIUM: read_file > info_leakage — error message reveals absolute server path
  MEDIUM: move_file > error_handling — returned MCP -32602 instead of graceful...
  LOW: write_file > info_leakage — error reveals sandbox path
```

### Files

- `src/mcp_auditor/console.py`: Add `print_findings_recap(report: AuditReport)` method to `AuditDisplay` (handles both interactive and CI mode via `self._ci_mode`, like `print_summary`). Uses `report.findings` directly — `EvalResult` already carries `severity`, `tool_name`, `category`, and `justification`. Sort by severity descending (CRITICAL first). No intermediate tuple or extra data structure needed — `EvalResult` *is* the domain concept.
- `src/mcp_auditor/cli.py`: Call `display.print_findings_recap(report)` in `_run_full_audit`, right after `display.print_summary(report)` (currently line 211). Note: the CI-mode summary path (`render_summary`) in `print_summary` does not include findings detail, so `print_findings_recap` will supplement it for both modes.

## 2. Severity Breakdown in Summary Table

### What

Replace the flat "Fail" column value (e.g., `2`) with a severity-aware breakdown (e.g., `2 (1 medium, 1 low)`). Color the breakdown text by highest severity.

### Output

```
┃ Tool           ┃ Tests ┃ Pass ┃ Fail                 ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ read_file      │    10 │    9 │ 1 (1 medium)         │
│ write_file     │    10 │    8 │ 2 (2 low)            │
│ directory_tree │    10 │   10 │ 0                    │
│ move_file      │    10 │    8 │ 2 (2 medium)         │
```

Severity coloring: critical = `bold red`, high = `red`, medium = `yellow`, low = `dim`.

### Files

- `src/mcp_auditor/console.py`: Modify `_build_summary_table` to compute a severity Counter per tool from failed `EvalResult.severity` values, and format the Fail cell as `{fails} ({breakdown})`. Add module-level `_severity_style(severity: Severity) -> str` helper that returns the Rich style string. Remove the static `style="red"` from the Fail column definition (line 89) — per-cell styling via Rich `Text` objects instead. Note: `_build_summary_table` is a module-level function, not a method.

## 3. Colored Score with Bar

### What

Replace the flat `Score: 35/40 (88%)` subtitle with a colored line that includes a small text-based bar.

### Output

```
Score: 35/40 ████████████████████░░ 88%  |  Tokens: 2,815 in / 2,986 out
```

- Bar width: 20 characters. Filled chars `█` + empty chars `░`.
- Color: green if ≥80%, yellow if ≥60%, red if <60%.
- Applied to the score portion only, tokens stay neutral.

### Files

- `src/mcp_auditor/console.py`: Extract module-level `_format_score_line(total_pass: int, total_judged: int) -> str` pure function. Returns the formatted score string with Rich markup (bar + percentage). Called from `print_summary` to build the panel subtitle. Note: `print_summary` currently computes `percentage` and `score_line` inline (lines 54-55) — this logic moves into `_format_score_line`.

## 4. Columnar Tool Discovery

### What

When more than 6 tools are discovered, display names in columns instead of a comma-separated list.

### Output (≤6 tools, unchanged)

```
Discovered 4 tools: read_file, write_file, directory_tree, move_file
```

### Output (>6 tools)

```
Discovered 14 tools:
  read_file         write_file        directory_tree    move_file
  search_files      get_info          list_files        create_dir
  ...
```

### Files

- `src/mcp_auditor/console.py`: Modify `print_discovery`. Use `rich.columns.Columns` when `tool_count > 6`. Import `Columns` from `rich.columns`.

## What stays unchanged

- **Domain models** (`domain/models.py`): One addition only — `findings` property on `AuditReport`. No new classes, no schema changes.
- **Rendering** (`domain/rendering.py`): One deletion only — `_collect_findings` replaced by `report.findings`. Output unchanged.
- **Graph logic** (`graph/`): No changes.
- **Adapters** (`adapters/`): No changes.
- **Inline failure display during execution**: The `✗ info_leakage (medium): ...` lines printed during progress are kept as-is — they provide live feedback. The recap consolidates them at the end.
- **CI mode behavior**: All improvements have CI-mode equivalents (plain text, no color). Exit code logic unchanged.

## Edge cases

- **Zero findings**: `print_findings_recap` is a no-op (no panel printed).
- **All tools pass**: Summary table shows `0` in Fail column, no breakdown. No findings panel.
- **Single severity**: Breakdown shows `2 (2 medium)` — no comma-separated list needed.
- **Very long justification**: Truncate at ~80 chars with `…` in the recap panel to avoid wrapping.
- **1 tool, 1 test**: Everything still works, just a single-row table.

## Test scenarios

All new logic is tested through the public `AuditDisplay` methods, matching the existing pattern where private helpers like `_build_summary_table` and `_format_token_usage` are tested indirectly through `print_summary`, not directly. Testing private functions by name couples tests to implementation.

### Findings recap (via `print_findings_recap`)

1. **Mixed severities**: Given report with failures at different severities → output lists them grouped by severity, highest first.
2. **No failures**: Given report with all passes → output is empty (no panel printed).
3. **CI mode**: Given report with failures → output is plain text, no Rich markup.

### Summary table severity breakdown (via `print_summary`)

4. **Failures with mixed severities**: Given report with mixed-severity failures → Fail column output contains severity breakdown (e.g., `1 medium, 1 low`).
5. **Zero failures**: Given report with no failures → Fail column shows `0` without breakdown.

### Colored score (via `print_summary`)

6. **High score**: Given 35/40 → output contains `88%` and bar characters.
7. **Low score**: Given 10/40 → output contains `25%`.
8. **Zero cases**: Given 0/0 → does not crash.

### Columnar discovery (via `print_discovery`)

9. **Many tools (>6)**: Given 8 tools → output uses columnar layout.
10. **Few tools (<=6)**: Given 4 tools → output is single-line comma-separated.

### Existing tests

All existing `test_console.py` tests must continue to pass. `test_summary_contains_score_and_tools` may need adjustment if score format changes.

## Verification

```bash
uv run pytest tests/unit/test_console.py -v     # All console tests pass
uv run ruff check src/mcp_auditor/console.py     # No lint issues
uv run ruff format --check .                     # Formatting OK
uv run pyright                                   # Type check passes
# Manual smoke test:
uv run mcp-auditor run --tools read_file,write_file,directory_tree,move_file -- npx @modelcontextprotocol/server-filesystem /tmp/sandbox
```

## Implementation steps

### Step 1: All five improvements (domain findings property, findings recap, severity breakdown, colored score bar, columnar discovery)

**Files**:
- `src/mcp_auditor/domain/models.py` (modify — add `findings` property on `AuditReport`, refactor `has_findings_at_or_above` to use it)
- `src/mcp_auditor/domain/rendering.py` (modify — delete `_collect_findings`, use `report.findings`)
- `tests/unit/test_console.py` (modify — add 10 new test cases, adjust 1 existing test)
- `src/mcp_auditor/console.py` (modify — add `print_findings_recap`, `_severity_style`, `_format_score_line`; modify `_build_summary_table`, `print_summary`, `print_discovery`)
- `src/mcp_auditor/cli.py` (modify — add `display.print_findings_recap(report)` call after `display.print_summary(report)`)

**Do**:

Write tests first in `tests/unit/test_console.py`, then implement.

**Tests to add** (using existing `_make_display`, `_make_ci_display`, `_a_fail_result`, `_a_report_with_two_tools` helpers — extend helpers as needed):

1. `test_findings_recap_groups_by_severity` — Build a report with failures at MEDIUM and LOW severity. Call `display.print_findings_recap(report)`. Assert output contains both severity labels, tool names, categories, and justifications. Assert MEDIUM appears before LOW in the output.
2. `test_findings_recap_empty_when_no_failures` — Build a report with all passes. Call `display.print_findings_recap(report)`. Assert output buffer is empty.
3. `test_findings_recap_ci_mode_plain_text` — Build a report with failures. Use CI display. Call `display.print_findings_recap(report)`. Assert output contains severity, tool, category, justification as plain text. Assert "Findings:" header present.
4. `test_summary_fail_column_shows_severity_breakdown` — Build a report where one tool has mixed-severity failures (e.g., 1 medium + 1 low). Call `display.print_summary(report)`. Assert the Fail column output contains the breakdown string (e.g., "medium" and "low").
5. `test_summary_fail_column_zero_shows_no_breakdown` — Build a report where a tool has 0 failures. Call `display.print_summary(report)`. Assert the tool's row contains "0" in the Fail column and does not contain severity labels for that tool.
6. `test_summary_score_line_high_score` — Build a report with 9/10 pass. Call `display.print_summary(report)`. Assert output contains "90%", filled bar char `\u2588`, and empty bar char `\u2591`.
7. `test_summary_score_line_low_score` — Build a report with 2/10 pass. Call `display.print_summary(report)`. Assert output contains "20%".
8. `test_summary_score_line_zero_cases` — Build a report with 0 cases. Call `display.print_summary(report)`. Assert no crash, output contains "0%".
9. `test_discovery_columnar_for_many_tools` — Call `display.print_discovery(8, [list of 8 tool names])`. Assert all 8 names appear in output. (Columnar layout is a visual property; just verify no crash and all names present.)
10. `test_discovery_inline_for_few_tools` — Call `display.print_discovery(4, [list of 4 tool names])`. Assert comma-separated format (all names on one logical line).

Adjust existing test `test_summary_contains_score_and_tools`: the score format changes from `(percentage%)` to `percentage%` with bar chars. Update assertion to match the new format — assert "100" and "50" (tokens) still present, and that tool names still appear.

**Add a helper** `_a_report_with_failures(failures_per_tool: dict[str, list[tuple[Severity, AuditCategory, str]]])` that builds an `AuditReport` with configurable failures across tools, to keep test setup concise for the new tests.

**Production code** in `src/mcp_auditor/domain/models.py`:

1. Add `@property findings(self) -> list[EvalResult]` on `AuditReport`: returns all `case.eval_result` where `verdict == FAIL`, iterating `tool_reports` and their `cases`.
2. Refactor `has_findings_at_or_above` to use `self.findings` — one-liner: `any(f.severity >= threshold for f in self.findings)`.

**Production code** in `src/mcp_auditor/domain/rendering.py`:

3. Delete `_collect_findings` function. Replace all usages (`render_summary`, `_render_summary_section`) with `report.findings`.

**Production code** in `src/mcp_auditor/console.py`:

4. Add `from rich.columns import Columns` and `from rich.text import Text` to imports.

5. Add module-level `_severity_style(severity: Severity) -> str` that maps: CRITICAL -> "bold red", HIGH -> "red", MEDIUM -> "yellow", LOW -> "dim".

6. Add module-level `_format_score_line(total_pass: int, total_judged: int) -> str` pure function. Computes percentage (0 if total_judged is 0). Builds a 20-char bar: filled `\u2588` + empty `\u2591`. Color: green if >=80%, yellow if >=60%, red if <60%. Returns Rich markup string like `[green]Score: 35/40 \u2588\u2588\u2588\u2588...\u2591\u2591 88%[/green]`.

7. Add `print_findings_recap(self, report: AuditReport) -> None` method to `AuditDisplay`. Uses `report.findings` directly, sorted by severity descending (`sorted(report.findings, key=lambda f: f.severity, reverse=True)`). If no findings, return immediately. In CI mode, print plain text: "Findings:" header, then each line as `"  {SEVERITY}: {tool} > {category} — {justification[:80]}"`. In interactive mode, build a Rich Panel with title "Findings", grouping lines by severity with severity labels, each finding as `"  {tool} > {category} — {justification[:80]}"`. Truncate justification at 80 chars with `…`. No intermediate data structure — `EvalResult` already carries everything needed.

8. Modify `_build_summary_table`: Remove `style="red"` from the Fail column definition. For each tool row, compute a `Counter` of severities from failed cases. Format Fail cell: if fails == 0, use plain "0". Otherwise, build a `Text` object with `"{fails} ({breakdown})"` where breakdown is comma-separated `"{count} {severity}"` pairs. Style the breakdown portion using `_severity_style` of the highest severity in that tool's failures.

9. Modify `print_summary`: Replace inline `percentage`/`score_line` computation with a call to `_format_score_line(total_pass, total_judged)`. Include in the panel subtitle.

10. Modify `print_discovery`: When `tool_count > 6`, print `"Discovered {tool_count} tools:"` as a header, then use `rich.columns.Columns` to display tool names. When `<= 6`, keep the existing comma-separated single-line format.

**Production code** in `src/mcp_auditor/cli.py`:

9. In `_run_full_audit`, add `display.print_findings_recap(report)` on the line immediately after `display.print_summary(report)` (after current line 211).

**Verify**:
```bash
uv run pytest tests/unit/test_console.py tests/unit/test_rendering.py -v  # All tests pass (old + new)
uv run ruff check .                              # No lint issues
uv run ruff format --check .                     # Formatting OK
uv run pyright                                   # Type check passes
```
