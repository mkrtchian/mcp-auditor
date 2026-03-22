# OWASP MCP Top 10 Mapping (§4 Pass 1)

## Context

mcp-auditor uses 5 internal audit categories (ADR 004). The OWASP MCP Top 10 is now a published project providing industry-standard threat classification for MCP servers. Mapping our findings to OWASP codes adds credibility and aligns reports with a recognized taxonomy — without changing any test logic.

This is pass 1: enrich rendering only. No new categories, no prompt changes, no model changes, no new test logic.

### Design decision: render-time mapping, not stored field

The OWASP code is a pure derivation of `AuditCategory` — `INJECTION` always maps to `MCP-05`, with no exceptions. Storing it on `EvalResult` would create a field that can be inconsistent with `category` and would require changes to the model, the node layer, and deserialization — all for zero semantic gain. Instead, renderers call `owasp_label_for(category)` at display time. The mapping is domain knowledge (lives in `domain/owasp.py`), the display is a presentation concern.

## Mapping

| AuditCategory      | OWASP MCP Code | OWASP Title                          |
|---------------------|----------------|--------------------------------------|
| `injection`         | MCP-05         | Command Injection & Execution        |
| `info_leakage`      | MCP-10         | Context Injection & Over-Sharing     |
| `resource_abuse`    | —              | No honest mapping                    |
| `input_validation`  | —              | No single OWASP mapping              |
| `error_handling`    | —              | No single OWASP mapping              |

`resource_abuse` (oversized payloads, unbounded consumption) does not map to MCP-02 (Privilege Escalation via Scope Creep) — these are different threats. Better to leave it unmapped than force a misleading correspondence.

`input_validation` and `error_handling` are cross-cutting concerns that can contribute to multiple OWASP categories depending on context. Pass 2 will introduce new categories with direct OWASP mappings.

## Approach

1. Add an OWASP mapping module in `domain/` — pure data + pure functions `category → label | None`
2. Update markdown rendering and console output to display OWASP labels when a mapping exists
3. Write ADR documenting the mapping rationale
4. Unit tests for the mapping and updated rendering

## Files to modify

### New file: `src/mcp_auditor/domain/owasp.py`

OWASP mapping as domain logic. Pure data + pure function.

```python
from dataclasses import dataclass

from mcp_auditor.domain.models import AuditCategory


@dataclass(frozen=True)
class OwaspMapping:
    code: str        # "MCP-05"
    title: str       # "Command Injection & Execution"


OWASP_BY_CATEGORY: dict[AuditCategory, OwaspMapping] = {
    AuditCategory.INJECTION: OwaspMapping(code="MCP-05", title="Command Injection & Execution"),
    AuditCategory.INFO_LEAKAGE: OwaspMapping(code="MCP-10", title="Context Injection & Over-Sharing"),
}


def owasp_id_for(category: AuditCategory) -> str | None:
    mapping = OWASP_BY_CATEGORY.get(category)
    return mapping.code if mapping else None


def owasp_label_for(category: AuditCategory) -> str | None:
    """Returns 'MCP-05: Command Injection & Execution' or None."""
    mapping = OWASP_BY_CATEGORY.get(category)
    if mapping is None:
        return None
    return f"{mapping.code}: {mapping.title}"
```

### Modify: `src/mcp_auditor/domain/rendering.py`

**`_render_result_section`** — include OWASP label in heading:

```python
from mcp_auditor.domain.owasp import owasp_label_for

owasp = owasp_label_for(result.category)
category_display = f"{result.category} / {owasp}" if owasp else str(result.category)

# FAIL: f"### FAIL -- {category_display} ({result.severity})"
# PASS: f"### PASS -- {category_display} (-)"
```

**No change to `render_json`** — OWASP code is not stored on the model, so JSON stays as-is (YAGNI — no consumers).

**No change to `render_summary`** — the one-liner doesn't show categories.

### Modify: `src/mcp_auditor/console.py`

Update finding display lines to include OWASP code. Import `owasp_id_for` from `domain/owasp`.

Console uses `owasp_id_for` (code only: `injection / MCP-05`) rather than `owasp_label_for` (full label) — console lines are space-constrained, the full title would make them too long. Markdown headings have room for the full label.

**`format_failure_line`:**
```python
owasp = owasp_id_for(result.category)
category_display = f"{result.category} / {owasp}" if owasp else str(result.category)
# f"  ✗ {category_display} ({result.severity}): {result.justification}"
```

**`_print_findings_recap_ci`:**
```python
owasp = owasp_id_for(f.category)
category_display = f"{f.category} / {owasp}" if owasp else str(f.category)
# f"  {f.severity.value.upper()}: {f.tool_name} > {category_display} — {justification}"
```

**`_print_findings_recap_rich`:** same pattern on line 100.

### New file: `docs/adr/008-owasp-mcp-mapping.md`

ADR documenting:
- The OWASP MCP Top 10 as the reference taxonomy
- The mapping table (which categories map, which don't, and why)
- Design decision: render-time derivation, not stored field (OWASP code is a pure function of category)
- `resource_abuse` intentionally left unmapped (not MCP-02)
- Pass 2 intent: new categories with direct OWASP mappings

### New file: `tests/unit/test_owasp.py`

Test the mapping module with inline assertions (no given/then — each is a one-liner):
- `owasp_id_for(INJECTION)` → `"MCP-05"`
- `owasp_id_for(INFO_LEAKAGE)` → `"MCP-10"`
- `owasp_id_for(INPUT_VALIDATION)` → `None`
- `owasp_id_for(ERROR_HANDLING)` → `None`
- `owasp_id_for(RESOURCE_ABUSE)` → `None`
- `owasp_label_for(INJECTION)` → `"MCP-05: Command Injection & Execution"`
- `owasp_label_for(INPUT_VALIDATION)` → `None`

### Modify: `tests/unit/test_rendering.py` (+ fixtures)

- Existing tests continue to pass unchanged (no model change, no visible difference for unmapped categories)
- New test: a finding with `category=INJECTION` renders heading containing `injection / MCP-05: Command Injection & Execution` in markdown
- New test: a finding with `category=INPUT_VALIDATION` renders heading with just `input_validation` (no slash)
- New test: a PASS result with a mapped category shows the OWASP label in the heading

### Modify: `tests/unit/fixtures/test_rendering_given.py`

Add a report factory that includes findings with mapped categories (injection) for the new rendering tests.

### Modify: `tests/unit/test_console.py`

- Existing `test_format_failure_line_includes_category_severity_justification` already uses `INJECTION` — after the console change it will assert `"injection"` appears in the line, which still passes (the OWASP code is appended, not replacing the category name). No change needed to this test.
- New test: `test_format_failure_line_includes_owasp_id_for_mapped_category` — call `format_failure_line` with a result of `category=INJECTION`, assert `"MCP-05"` appears in the line.
- New test: `test_format_failure_line_no_owasp_for_unmapped_category` — call with `category=INPUT_VALIDATION`, assert `"MCP-"` does NOT appear.
- No tests for `_print_findings_recap_ci` or `_print_findings_recap_rich` — these are private methods using the same pattern. Testing them would test implementation, not behavior. The public `format_failure_line` tests + the mapping unit tests provide sufficient coverage.

## What stays unchanged

- **`domain/models.py`**: no changes. `EvalResult` keeps its current fields.
- **`graph/nodes.py`**: no changes. OWASP is a rendering concern, not a graph concern.
- **Prompts** (`graph/prompts.py`): no changes.
- **AuditCategory enum**: no new values. Pass 2 will extend it.
- **Evals**: ground truth, judge eval, e2e eval — unchanged.
- **CLI**: no new flags. OWASP codes appear automatically in output.
- **Graph structure**: no new nodes or edges.
- **JSON output**: unchanged. OWASP codes appear in markdown and console only.

## Edge cases

- **Future categories**: when pass 2 adds new `AuditCategory` values, just add entries to `OWASP_BY_CATEGORY`. The mapping function handles missing keys by returning `None`.
- **All categories unmapped**: if no finding has a mapping, output looks exactly like today. No regressions.

## Test scenarios

| Scenario | Input | Expected |
|----------|-------|----------|
| Mapped category | `owasp_id_for(INJECTION)` | `"MCP-05"` |
| Unmapped category | `owasp_id_for(INPUT_VALIDATION)` | `None` |
| Label for mapped | `owasp_label_for(INJECTION)` | `"MCP-05: Command Injection & Execution"` |
| Label for unmapped | `owasp_label_for(ERROR_HANDLING)` | `None` |
| Markdown heading (mapped) | `_render_result_section(result with injection)` | Contains `injection / MCP-05: Command Injection & Execution` |
| Markdown heading (unmapped) | `_render_result_section(result with input_validation)` | Contains `input_validation` only (no slash) |
| PASS heading (mapped) | `_render_result_section(pass result with injection)` | Contains `injection / MCP-05: Command Injection & Execution` and `(-)` |
| `format_failure_line` (mapped) | result with `category=INJECTION` | Contains `injection / MCP-05` |
| `format_failure_line` (unmapped) | result with `category=INPUT_VALIDATION` | Does NOT contain `MCP-` |

## Verification

```bash
uv run pytest tests/unit           # All unit tests pass
uv run ruff check .                # No lint errors
uv run ruff format --check .       # Formatted
uv run pyright                     # Type checks pass
```

## Implementation steps

### Step 1: OWASP mapping module, rendering updates, console updates, tests, and ADR

This is a single cohesive step — the mapping module is tiny (2 functions, 1 dict) and only consumed by rendering/console code. No model or graph changes.

**Files**:
- Create `tests/unit/test_owasp.py`
- Create `src/mcp_auditor/domain/owasp.py`
- Modify `tests/unit/fixtures/test_rendering_given.py`
- Modify `tests/unit/test_rendering.py`
- Modify `src/mcp_auditor/domain/rendering.py`
- Modify `tests/unit/test_console.py`
- Modify `src/mcp_auditor/console.py`
- Create `docs/adr/008-owasp-mcp-mapping.md`

**Do**:

1. **Test file first** — `tests/unit/test_owasp.py`: Write unit tests for the mapping module with inline assertions. Test `owasp_id_for` for all 5 categories and `owasp_label_for` for one mapped and one unmapped category.

2. **Create `src/mcp_auditor/domain/owasp.py`**: Frozen dataclass `OwaspMapping` with `code` and `title`. Module-level dict `OWASP_BY_CATEGORY` with 2 mappings (injection→MCP-05, info_leakage→MCP-10). Two pure functions: `owasp_id_for` and `owasp_label_for`.

3. **Rendering tests** — extend `tests/unit/fixtures/test_rendering_given.py` with a report factory that includes an injection finding. Add tests in `test_rendering.py` for mapped and unmapped markdown headings (both FAIL and PASS).

4. **Update `src/mcp_auditor/domain/rendering.py`**: In `_render_result_section`, call `owasp_label_for(result.category)` to compute `category_display` for both FAIL and PASS headings.

5. **Console tests** — add two tests in `test_console.py`: `test_format_failure_line_includes_owasp_id_for_mapped_category` (INJECTION → line contains `MCP-05`) and `test_format_failure_line_no_owasp_for_unmapped_category` (INPUT_VALIDATION → line does NOT contain `MCP-`).

6. **Update `src/mcp_auditor/console.py`**: In `_print_findings_recap_ci`, `_print_findings_recap_rich`, and `format_failure_line`, call `owasp_id_for(category)` to compute `category_display`.

7. **Create `docs/adr/008-owasp-mcp-mapping.md`**: Follow the existing ADR format. Document the mapping table, the render-time derivation design, why `resource_abuse` is unmapped, and pass 2 intent.

**Verify**:
```bash
uv run pytest tests/unit -v         # All unit tests pass
uv run ruff check .                  # No lint errors
uv run ruff format --check .         # Formatted
uv run pyright                       # Type checks pass
```
