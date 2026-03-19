# Plan: Eval Improvements

**Date:** 2026-03-19

## Context

The eval infrastructure (ADR 003, `plans/2026-03-17_evals.md`) works but has structural gaps identified in ADR 005 and ADR 006:

- **Precision fails** on both models (Haiku 4.5: 0.56, Flash-Lite: 0.61) against a 1.00 threshold. The judge prompt confuses adjacent categories and misreads defensive responses as vulnerabilities.
- **No way to isolate the judge.** The end-to-end eval conflates generator and judge quality. When precision drops, we can't tell if the generator, the judge, or the ground truth is at fault.
- **Single honeypot.** All evals run against `tests/dummy_server.py` — 3 tools with "loud" vulnerabilities (SQL echo, path leak in errors, stack traces). The LLM could be overfitting to these patterns.

ADR 006 (Accepted) defines the judge isolation eval strategy. This plan implements it alongside a second honeypot and multi-honeypot e2e eval support.

## Approach

Four changes:

1. **Judge isolation eval** — dataset of fixed judge inputs + eval script + metrics. Enables fast prompt iteration (~20s vs 2-3 min for e2e).
2. **Second honeypot** — server with subtle vulnerability patterns that test different judge capabilities.
3. **Multi-honeypot e2e eval** — runner supports multiple honeypots per run, aggregates metrics across all.
4. **Precision threshold recalibration** — lower from 1.00 to 0.85 as an actionable iteration target.

## Files to create

### `evals/judge_metrics.py`

Pure functions for judge eval metrics. Operates on a flat list of `(predicted, expected)` pairs — simpler than the e2e metrics which work on `VerdictMap`.

```python
from dataclasses import dataclass

from mcp_auditor.domain.models import AuditCategory, EvalVerdict


@dataclass(frozen=True)
class ConfusionMatrix:
    tp: int
    fp: int
    tn: int
    fn: int


@dataclass(frozen=True)
class JudgeMetrics:
    precision: float
    recall: float
    f1: float
    confusion: ConfusionMatrix


CaseResult = tuple[EvalVerdict, EvalVerdict]  # (predicted, expected)


def compute_judge_metrics(results: list[CaseResult]) -> JudgeMetrics:
    tp = sum(1 for p, e in results if p == EvalVerdict.FAIL and e == EvalVerdict.FAIL)
    fp = sum(1 for p, e in results if p == EvalVerdict.FAIL and e == EvalVerdict.PASS)
    tn = sum(1 for p, e in results if p == EvalVerdict.PASS and e == EvalVerdict.PASS)
    fn = sum(1 for p, e in results if p == EvalVerdict.PASS and e == EvalVerdict.FAIL)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return JudgeMetrics(
        precision=precision, recall=recall, f1=f1,
        confusion=ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn),
    )


def compute_per_category_metrics(
    results: list[tuple[AuditCategory, CaseResult]],
) -> dict[AuditCategory, JudgeMetrics]:
    by_category: dict[AuditCategory, list[CaseResult]] = {}
    for category, case_result in results:
        by_category.setdefault(category, []).append(case_result)
    return {cat: compute_judge_metrics(cases) for cat, cases in by_category.items()}
```

Positive class is FAIL (a detected vulnerability). This aligns with the e2e eval where precision = "of predicted FAILs, how many are correct" and recall = "of expected FAILs, how many were detected".

### `evals/fixtures/judge_cases.json`

~20 cases covering the known false positive patterns, true positives/negatives for regression, and synthetic edge cases. Each case captures the exact inputs to `build_judge_prompt`:

```json
[
  {
    "tool_name": "execute_query",
    "tool_description": "Execute a SQL query against the database.",
    "category": "resource_abuse",
    "description": "Send very long SQL query to test resource handling",
    "arguments": {"query": "SELECT * FROM users WHERE id IN (1,2,3,...,10000)"},
    "response": "[db: /opt/mcp-server/config/database.yml] Executed: SELECT * FROM users WHERE id IN (1,2,3,...,10000) — Results: 3 rows",
    "error": null,
    "expected_verdict": "pass"
  }
]
```

The eval script fills `input_schema` with `{}` when constructing `ToolDefinition` — the judge prompt doesn't use it.

**Case inventory** (20 cases):

Observed false positives (5 cases — the known precision problems):

| # | Tool            | Category           | Payload summary                                   | Response/Error                                                         | Expected |
|:--|:----------------|:-------------------|:--------------------------------------------------|:-----------------------------------------------------------------------|:---------|
| 1 | `execute_query` | `resource_abuse`   | Long SQL query                                    | Response: echoes query with DB path                                    | PASS     |
| 2 | `execute_query` | `input_validation` | SQL injection payload `'; DROP TABLE users; --`   | Response: echoes payload with DB path                                  | PASS     |
| 3 | `list_items`    | `input_validation` | Path traversal `../../etc/passwd`                 | Error: `Invalid category`                                             | PASS     |
| 4 | `get_user`      | `resource_abuse`   | Very large user_id `999999999`                    | Error: `999999999` (KeyError)                                          | PASS     |
| 5 | `list_items`    | `info_leakage`     | Invalid category `<script>alert(1)</script>`      | Error: `Invalid category`                                             | PASS     |

Case 1: the tool is vulnerable to injection and info leakage, but resource abuse doesn't apply. Case 2: it's injection, not input validation. Case 3: the error is correct validation. Case 4: the crash is error handling, not resource abuse. Case 5: generic error, no leak.

Observed true positives (5 cases — regression guards for FAIL):

| # | Tool            | Category           | Payload summary                        | Response/Error                                                                    | Expected |
|:--|:----------------|:-------------------|:---------------------------------------|:----------------------------------------------------------------------------------|:---------|
| 6 | `get_user`      | `info_leakage`     | Negative user_id `-1`                  | Error: `user_id must be positive — see /opt/mcp-server/internal/users.db`         | FAIL     |
| 7 | `get_user`      | `error_handling`   | Unknown user_id `999`                  | Error: `999` (KeyError, no graceful handling)                                     | FAIL     |
| 8 | `get_user`      | `input_validation` | String-like edge `0`                   | Error: `0` (KeyError — no range validation)                                       | FAIL     |
| 9 | `execute_query` | `injection`        | SQL injection `'; DROP TABLE users;--` | Response: `[db: /opt/mcp-server/config/database.yml] Executed: '; DROP TABLE...`  | FAIL     |
| 10| `execute_query` | `info_leakage`     | Simple SELECT                          | Response: `[db: /opt/mcp-server/config/database.yml] Executed: SELECT 1 — ...`    | FAIL     |

Observed true negatives (5 cases — regression guards for PASS):

| # | Tool            | Category           | Payload summary                     | Response/Error                                     | Expected |
|:--|:----------------|:-------------------|:------------------------------------|:---------------------------------------------------|:---------|
| 11| `list_items`    | `injection`        | SQL injection in category           | Error: `Invalid category`                          | PASS     |
| 12| `list_items`    | `resource_abuse`   | Extreme limit `999999`              | Response: `Items: books1, books2, ... (showing 100)` | PASS     |
| 13| `get_user`      | `injection`        | user_id `42` (no injection surface) | Response: `User: Alice (id=42)`                    | PASS     |
| 14| `execute_query` | `error_handling`   | Malformed SQL                       | Response: echoes query (doesn't crash)             | PASS     |
| 15| `list_items`    | `error_handling`   | Valid category, normal use          | Response: `Items: books1, books2, ... (showing 10)` | PASS     |

Synthetic edge cases (5 cases — boundaries not covered by the honeypot):

| # | Tool          | Category           | Payload summary                      | Response/Error                                     | Expected |
|:--|:--------------|:-------------------|:-------------------------------------|:---------------------------------------------------|:---------|
| 16| (synthetic)   | `info_leakage`     | Trigger error with stack trace       | Error: `Traceback (most recent call last):\n  File "/app/server.py", line 42...\nValueError: invalid input` | FAIL     |
| 17| (synthetic)   | `info_leakage`     | Normal response mentions docs path   | Response: `See documentation at /help/api-guide`   | PASS     |
| 18| (synthetic)   | `input_validation` | Rejected with specific rule          | Error: `ID must be between 1 and 1000`             | PASS     |
| 19| (synthetic)   | `error_handling`   | Clean structured error               | Error: `Invalid request: missing required field "name"` | PASS     |
| 20| (synthetic)   | `injection`        | Command echoed in response           | Response: `Executed command: ls -la /tmp`           | FAIL     |

Synthetic cases use generic tool names/descriptions (e.g., `tool_name: "manage_data"`, `tool_description: "Manage application data"`).

### `evals/run_judge_eval.py`

Loads the dataset, runs `build_judge_prompt` + `llm.generate_structured` per case, compares verdicts, writes a report.

```python
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from evals.judge_metrics import CaseResult, compute_judge_metrics, compute_per_category_metrics
from mcp_auditor.adapters.llm import create_judge_llm
from mcp_auditor.config import load_settings
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    EvalResult,
    EvalVerdict,
    TestCase,
    ToolDefinition,
)
from mcp_auditor.graph.prompts import build_judge_prompt

FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures" / "judge_cases.json"
DEFAULT_REPORT_PATH = "evals/judge_eval_report.json"
F1_THRESHOLD = 0.90


def main() -> None:
    report = asyncio.run(run_judge_eval())
    Path(DEFAULT_REPORT_PATH).write_text(json.dumps(report, indent=2))
    _print_summary(report)


async def run_judge_eval() -> dict:
    settings = load_settings()
    llm = create_judge_llm(settings)
    cases = _load_cases()
    results: list[tuple[AuditCategory, CaseResult]] = []

    for case in cases:
        tool, test_case, expected, category = case
        prompt = build_judge_prompt(tool=tool, test_case=test_case)
        eval_result = await llm.generate_structured(prompt, EvalResult)
        predicted = eval_result.verdict
        results.append((category, (predicted, expected)))

    overall = compute_judge_metrics([cr for _, cr in results])
    per_category = compute_per_category_metrics(results)
    return _build_report(overall, per_category, results, cases)
```

`_load_cases` reads the JSON fixture and constructs `(ToolDefinition, TestCase, EvalVerdict, AuditCategory)` tuples. `_build_report` assembles a JSON-serializable dict with metrics, per-case results (including justifications for debugging), and threshold status.

Report output: `evals/judge_eval_report.json` (gitignored).

Console output:

```
Running judge eval (20 cases)...

--- Results ---
Precision:   0.83 (threshold: n/a)
Recall:      0.90 (threshold: n/a)
F1:          0.86 (threshold: 0.90) FAIL

Confusion matrix:
  TP: 9  FP: 2
  FN: 1  TN: 8

Per-category:
  input_validation: P=0.75 R=1.00 F1=0.86
  info_leakage:     P=0.80 R=1.00 F1=0.89
  ...

Report written to evals/judge_eval_report.json
```

### `tests/subtle_server.py`

Second honeypot with a different vulnerability profile. The original honeypot has "loud" vulnerabilities (SQL echo, paths in errors, stack traces). This server has "subtle" ones — vulnerabilities in normal responses and semantic validation gaps.

```python
from mcp.server.fastmcp import FastMCP

app = FastMCP("subtle-honeypot")

USERS_DB = {
    1: {"name": "Alice", "email": "alice@internal.corp", "role": "admin", "last_login": "2026-01-15"},
    2: {"name": "Bob", "email": "bob@internal.corp", "role": "user", "last_login": "2026-03-10"},
}

VALID_SERVICES = ["api", "database", "cache"]


@app.tool()
def search_users(query: str, limit: int = 10) -> str:
    """Search for users by name."""
    matches = [u for u in USERS_DB.values() if query.lower() in u["name"].lower()]
    clamped = max(1, min(limit, 100))
    results = matches[:clamped]
    if not results:
        return "No users found"
    # BUG: leaks internal fields (email, role, last_login) in normal responses
    return "\n".join(
        f"- {u['name']} (email={u['email']}, role={u['role']}, last_login={u['last_login']})"
        for u in results
    )


@app.tool()
def delete_record(record_id: int, confirm: bool = False) -> str:
    """Delete a record by ID."""
    # BUG: no semantic validation — accepts negative IDs, ignores confirm flag
    return f"Record {record_id} deleted successfully"


@app.tool()
def get_service_status(service: str) -> str:
    """Check the health status of a service."""
    if service not in VALID_SERVICES:
        raise ValueError("Unknown service")
    return f"{service}: healthy (uptime: 42h)"


if __name__ == "__main__":
    app.run()
```

**Vulnerability profile comparison:**

| Dimension              | Original (`dummy_server.py`)               | Subtle (`subtle_server.py`)                        |
|:-----------------------|:-------------------------------------------|:---------------------------------------------------|
| Info leakage           | Paths in error messages, DB config exposed | PII in normal responses (email, role, last_login)  |
| Input validation       | Missing type validation (crashes)          | Missing semantic validation (accepts nonsense IDs) |
| Error handling         | Unhandled KeyError, ValueError             | Clean errors, no crashes                           |
| Injection              | SQL echo (obvious)                         | No injection surface                               |
| Clean tool             | `list_items` (validates, clamps)           | `get_service_status` (validates, generic errors)   |

What this tests that the original doesn't:
- **Info leakage in content, not errors** — the judge must recognize PII exposure in successful responses, not just paths in stack traces.
- **Semantic validation failure without crashes** — `delete_record(-5)` succeeds silently. The judge must flag this as a validation problem even though the server didn't crash.
- **A clean tool with similar patterns** — `get_service_status` validates and returns generic errors, like `list_items` but with different structure.

### `tests/unit/test_judge_metrics.py`

Unit tests for `evals/judge_metrics.py`. Inline fixtures — no given/then extraction (simple one-liner asserts).

| Test | Input | Expected |
|:-----|:------|:---------|
| `test_all_correct` | 5 TP + 5 TN | precision=1.0, recall=1.0, f1=1.0 |
| `test_all_wrong` | 5 FP + 5 FN | precision=0.0, recall=0.0, f1=0.0 |
| `test_one_false_positive` | 4 TP + 1 FP + 5 TN | precision=0.8, recall=1.0 |
| `test_one_false_negative` | 4 TP + 1 FN + 5 TN | precision=1.0, recall=0.8 |
| `test_no_positives` | 10 TN | precision=1.0, recall=1.0 (no FAILs to miss) |
| `test_no_predictions` | 5 TN + 5 FN | precision=1.0, recall=0.0 |
| `test_per_category_separates` | 2 categories, different results | each category has independent metrics |
| `test_confusion_matrix_counts` | known mix | tp, fp, tn, fn counts match |

### `src/mcp_auditor/py.typed`

Already exists (created in previous plan). No change.

## Files to modify

### `evals/ground_truth.py`

Add `SUBTLE_GROUND_TRUTH` for the second honeypot:

```python
SUBTLE_GROUND_TRUTH: GroundTruth = {
    ("search_users", AuditCategory.INFO_LEAKAGE): EvalVerdict.FAIL,
    ("search_users", AuditCategory.INPUT_VALIDATION): EvalVerdict.PASS,
    ("search_users", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("search_users", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("search_users", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    ("delete_record", AuditCategory.INPUT_VALIDATION): EvalVerdict.FAIL,
    ("delete_record", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("delete_record", AuditCategory.INFO_LEAKAGE): EvalVerdict.PASS,
    ("delete_record", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("delete_record", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.INPUT_VALIDATION): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.ERROR_HANDLING): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.INFO_LEAKAGE): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.INJECTION): EvalVerdict.PASS,
    ("get_service_status", AuditCategory.RESOURCE_ABUSE): EvalVerdict.PASS,
}
```

2 expected FAILs across 15 pairs (vs. 5/15 in original). This server is "mostly secure" with subtle flaws — a harder test for the judge.

### `evals/run_evals.py`

**What changes:**
- Introduce `HoneypotConfig` frozen dataclass grouping server path, command, args, and ground truth reference.
- Replace module-level `HONEYPOT_*` constants with a `HONEYPOTS` list.
- `run_single_audit` becomes `_run_single_honeypot(settings, honeypot, budget)` — takes a `HoneypotConfig`.
- Each eval run iterates over all honeypots, merges verdicts and ground truths, then computes metrics on the merged set.
- Lower precision threshold from `1.0` to `0.85`.

```python
from dataclasses import dataclass
from evals.ground_truth import HONEYPOT_GROUND_TRUTH, SUBTLE_GROUND_TRUTH, GroundTruth

HONEYPOT_SERVER = Path(__file__).resolve().parent.parent / "tests" / "dummy_server.py"
SUBTLE_SERVER = Path(__file__).resolve().parent.parent / "tests" / "subtle_server.py"


@dataclass(frozen=True)
class HoneypotConfig:
    name: str
    command: str
    args: list[str]
    ground_truth: GroundTruth


HONEYPOTS = [
    HoneypotConfig(
        name="honeypot",
        command="uv",
        args=["run", "python", str(HONEYPOT_SERVER)],
        ground_truth=HONEYPOT_GROUND_TRUTH,
    ),
    HoneypotConfig(
        name="subtle",
        command="uv",
        args=["run", "python", str(SUBTLE_SERVER)],
        ground_truth=SUBTLE_GROUND_TRUTH,
    ),
]

THRESHOLDS: dict[str, float] = {
    "recall": 0.80,
    "precision": 0.85,  # was 1.0 — see "Precision threshold" section
    "consistency": 0.70,
    "distribution_coverage": 0.80,
}
```

The run loop becomes:

```python
async def _run_one_eval(settings: Settings, budget: int) -> tuple[VerdictMap, GroundTruth, AuditReport]:
    merged_verdicts: VerdictMap = {}
    merged_ground_truth: GroundTruth = {}
    all_tool_reports: list[ToolReport] = []
    total_usage = TokenUsage()

    for honeypot in HONEYPOTS:
        report = await _run_single_honeypot(settings, honeypot, budget)
        verdicts = aggregate_verdicts(report)
        merged_verdicts.update(verdicts)
        merged_ground_truth.update(honeypot.ground_truth)
        all_tool_reports.extend(report.tool_reports)
        total_usage = total_usage.add(report.token_usage)

    merged_report = AuditReport(
        target="evals", tool_reports=all_tool_reports, token_usage=total_usage,
    )
    return merged_verdicts, merged_ground_truth, merged_report


async def _run_single_honeypot(
    settings: Settings, honeypot: HoneypotConfig, budget: int,
) -> AuditReport:
    llm = create_llm(settings)
    judge_llm = create_judge_llm(settings)
    async with StdioMCPClient.connect(honeypot.command, honeypot.args) as mcp_client:
        graph = build_graph(llm, mcp_client, judge_llm=judge_llm)
        result = await graph.ainvoke(
            {"target": f"{honeypot.command} {' '.join(honeypot.args)}", "test_budget": budget}
        )
        return result["audit_report"]
```

Metric computation now uses merged verdicts and merged ground truth instead of the single `HONEYPOT_GROUND_TRUTH`.

### `.gitignore`

Add `evals/judge_eval_report.json`.

## What stays unchanged

- **`src/mcp_auditor/`** — no production code changes. `graph/prompts.py` is untouched — prompt iteration happens after this plan is implemented, using the judge isolation eval.
- **`tests/unit/`** and **`tests/integration/`** — existing tests unchanged.
- **`tests/dummy_server.py`** — original honeypot unchanged.
- **`evals/metrics.py`** — e2e metric functions unchanged.

## Precision threshold

The current threshold of 1.00 is unreachable (both models score 0.56-0.61). Keeping an unachievable threshold means `run_evals.py` always reports FAIL — the signal is lost.

Lowering to **0.85** makes the threshold actionable:
- It's above current performance (requires judge prompt improvement to pass).
- It allows a small number of false positives (realistic for LLM-as-judge classification).
- It's a stepping stone — raise to 0.90 or 0.95 after the judge prompt is tuned.

The prompt iteration workflow:
1. Run `evals/run_judge_eval.py` to measure judge accuracy on fixed cases (~20s).
2. Edit `graph/prompts.py` — `build_judge_prompt()`.
3. Re-run judge eval. Iterate until F1 ≥ 0.90.
4. Run `evals/run_evals.py` to confirm e2e precision improves.
5. If e2e precision ≥ 0.85, the eval suite passes. Raise threshold if desired.

## Edge cases

| Scenario | Behavior |
|:---|:---|
| Judge eval case has both `response` and `error` set | Both are included in the judge prompt (same as e2e — `_format_outcome` handles it) |
| Judge eval case has neither `response` nor `error` | Prompt says "The tool produced no response and no error." |
| Subtle server `delete_record` with valid ID | Returns success message — not a vulnerability. The vulnerability is accepting _invalid_ IDs (negative, zero). |
| `search_users` with no matches | Returns "No users found" — no PII leaked. The leak only happens when results exist. |
| One honeypot fails during e2e eval | The entire eval run fails (exception propagates from `_run_one_eval`). The outer retry loop in `run_evals` catches it and continues with remaining runs. |
| Tool names collide across honeypots | Not possible with current servers (different tool names). If added in future, `aggregate_verdicts` would merge them — design a naming convention. |

## Test scenarios

### Unit tests for `judge_metrics.py`

New file: `tests/unit/test_judge_metrics.py`

8 tests as described in the "Files to create" section. Use inline fixtures — create `CaseResult` tuples directly. No given/then extraction.

### Integration test for subtle server

New test class in `tests/integration/test_mcp_client.py` (or new file `tests/integration/test_subtle_server.py` — depends on whether it's cleaner to share the existing test structure):

| Test | Input | Expected |
|:-----|:------|:---------|
| `test_discovers_three_tools` | Connect to subtle server | 3 tools: `search_users`, `delete_record`, `get_service_status` |
| `test_search_users_leaks_pii` | `search_users(query="Alice")` | Response contains `email=`, `role=` |
| `test_delete_record_accepts_negative_id` | `delete_record(record_id=-5)` | `is_error=False`, no crash |
| `test_get_service_status_rejects_unknown` | `get_service_status(service="secret")` | `is_error=True`, generic error |
| `test_get_service_status_valid` | `get_service_status(service="api")` | `is_error=False`, contains "healthy" |

These validate that the server behaves as the ground truth expects.

## Verification

```bash
# Unit tests (including new judge_metrics tests)
uv run pytest tests/unit -v

# Integration tests (including subtle server tests)
uv run pytest tests/integration -v

# Type check
uv run pyright

# Lint + format
uv run ruff check .
uv run ruff format --check .

# Judge eval (requires API key, ~20s)
uv run python -m evals.run_judge_eval

# E2E eval (requires API key, ~5 min with 2 honeypots × 3 runs)
uv run python -m evals.run_evals --runs 3 --budget 10
```

## Implementation steps

### Step 1: Judge isolation eval (metrics, dataset, script)

**Files** (create):
- `tests/unit/test_judge_metrics.py`
- `evals/judge_metrics.py`
- `evals/fixtures/judge_cases.json`
- `evals/run_judge_eval.py`

**Files** (modify):
- `.gitignore` — add `evals/judge_eval_report.json`

**Do**:

1. Write `tests/unit/test_judge_metrics.py` with 8 tests from the "Unit tests for `judge_metrics.py`" section. Use inline fixtures -- `CaseResult` tuples directly (e.g., `(EvalVerdict.FAIL, EvalVerdict.FAIL)` for a true positive). Tests are sync. No given/then extraction since asserts are one-liners. Test cases:
   - `test_all_correct`: 5 TP + 5 TN -> precision=1.0, recall=1.0, f1=1.0
   - `test_all_wrong`: 5 FP + 5 FN -> precision=0.0, recall=0.0, f1=0.0
   - `test_one_false_positive`: 4 TP + 1 FP + 5 TN -> precision=0.8, recall=1.0
   - `test_one_false_negative`: 4 TP + 1 FN + 5 TN -> precision=1.0, recall=0.8
   - `test_no_positives`: 10 TN -> precision=1.0, recall=1.0 (no FAILs to miss)
   - `test_no_predictions`: 5 TN + 5 FN -> precision=1.0 (vacuously), recall=0.0
   - `test_per_category_separates`: 2 categories with different results -> each has independent metrics
   - `test_confusion_matrix_counts`: known mix -> tp, fp, tn, fn counts match

2. Run `uv run pytest tests/unit/test_judge_metrics.py -v` -- confirm all 8 fail (test-first).

3. Create `evals/judge_metrics.py` with `ConfusionMatrix` and `JudgeMetrics` frozen dataclasses, `CaseResult` type alias (`tuple[EvalVerdict, EvalVerdict]` where first is predicted, second is expected), `compute_judge_metrics(results: list[CaseResult]) -> JudgeMetrics` and `compute_per_category_metrics(results: list[tuple[AuditCategory, CaseResult]]) -> dict[AuditCategory, JudgeMetrics]`. Positive class is FAIL. Implementation is specified in the "Files to create" section of this plan.

4. Run `uv run pytest tests/unit/test_judge_metrics.py -v` -- all 8 pass.

5. Create `evals/fixtures/` directory and `evals/fixtures/judge_cases.json` with the 20 cases from the case inventory tables. Each case is a JSON object with fields: `tool_name`, `tool_description`, `category`, `description`, `arguments`, `response` (string or null), `error` (string or null), `expected_verdict` ("pass" or "fail"). Construct tool responses exactly as `tests/dummy_server.py` would return them. For cases 1-15, use the exact tool names and descriptions from `tests/dummy_server.py` (`get_user` / "Look up a user by their numeric ID.", `execute_query` / "Execute a SQL query against the database.", `list_items` / "List items in a given category with an optional limit."). For synthetic cases 16-20, use generic tool names like `manage_data` with `tool_description: "Manage application data"`.

6. Create `evals/run_judge_eval.py` with:
   - `main()` -- runs `asyncio.run(run_judge_eval())`, writes report to `DEFAULT_REPORT_PATH`, prints summary.
   - `run_judge_eval() -> dict` -- loads settings via `load_settings()`, creates judge LLM via `create_judge_llm(settings)`, loads cases via `_load_cases()`, iterates over cases calling `build_judge_prompt(tool, test_case)` then `llm.generate_structured(prompt, EvalResult)`, collects `(AuditCategory, CaseResult)` tuples, computes metrics via `compute_judge_metrics` and `compute_per_category_metrics`, returns report dict via `_build_report`.
   - `_load_cases() -> list[tuple[ToolDefinition, TestCase, EvalVerdict, AuditCategory]]` -- reads `FIXTURES_PATH` JSON, constructs domain objects. `ToolDefinition` gets `input_schema={}`. `AuditPayload` is built from `tool_name`, `category`, `description`, `arguments`. `TestCase` gets `payload`, `response`, and `error` from the case.
   - `_build_report(overall: JudgeMetrics, per_category: dict[AuditCategory, JudgeMetrics], results, cases) -> dict` -- JSON-serializable report with metrics, confusion matrix, per-category breakdown, per-case details (tool_name, category, expected, predicted, correct, justification from the `EvalResult`).
   - `_print_summary(report: dict) -> None` -- prints metrics, confusion matrix, per-category table, F1 threshold status. Console format shown in plan.
   - `F1_THRESHOLD = 0.90` constant.
   - `if __name__ == "__main__": main()`.

7. Add `evals/judge_eval_report.json` to `.gitignore` (under the `# mcp-auditor` section).

**Test**: 8 unit tests for `judge_metrics.py` as listed above. The eval script itself requires a real LLM -- no automated tests for it.

**Verify**:
```bash
uv run pytest tests/unit -v
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

### Step 2: Subtle honeypot, multi-honeypot e2e eval, precision threshold

**Files** (create):
- `tests/subtle_server.py`
- `tests/integration/test_subtle_server.py`

**Files** (modify):
- `evals/ground_truth.py` -- add `SUBTLE_GROUND_TRUTH`
- `evals/run_evals.py` -- multi-honeypot support + precision threshold

**Do**:

1. Create `tests/subtle_server.py` with 3 tools (`search_users`, `delete_record`, `get_service_status`) as specified in the plan. Follow the same structure as `tests/dummy_server.py` -- `FastMCP` app with `@app.tool()` decorators, `if __name__ == "__main__": app.run()`. The implementation is fully specified in the "Files to create" section of this plan with constants `USERS_DB`, `VALID_SERVICES`, and the three tool functions.

2. Write `tests/integration/test_subtle_server.py` with 5 integration tests. Follow the same pattern as `tests/integration/test_mcp_client.py` -- define `SERVER_PATH` and `CONNECT_ARGS` at module level pointing to `tests/subtle_server.py`, use `StdioMCPClient.connect(*CONNECT_ARGS)` in each test. Test cases:
   - `test_discovers_three_tools`: connect, `list_tools()`, assert 3 tools with names `{"search_users", "delete_record", "get_service_status"}`
   - `test_search_users_leaks_pii`: `call_tool("search_users", {"query": "Alice"})`, assert `is_error is False`, assert response contains `email=` and `role=`
   - `test_delete_record_accepts_negative_id`: `call_tool("delete_record", {"record_id": -5})`, assert `is_error is False` (no crash -- the bug is accepting invalid input silently)
   - `test_get_service_status_rejects_unknown`: `call_tool("get_service_status", {"service": "secret"})`, assert `is_error is True`
   - `test_get_service_status_valid`: `call_tool("get_service_status", {"service": "api"})`, assert `is_error is False`, assert `"healthy"` in response

3. Run `uv run pytest tests/integration/test_subtle_server.py -v` -- all 5 pass.

4. Add `SUBTLE_GROUND_TRUTH` to `evals/ground_truth.py` with 15 entries as specified in the plan. 2 FAILs: `("search_users", AuditCategory.INFO_LEAKAGE)` and `("delete_record", AuditCategory.INPUT_VALIDATION)`. 13 PASSes for all other tool/category combinations.

5. Modify `evals/run_evals.py` for multi-honeypot support:
   - Add imports: `from dataclasses import dataclass` and `from evals.ground_truth import SUBTLE_GROUND_TRUTH`.
   - Add `SUBTLE_SERVER` path constant (same pattern as `HONEYPOT_SERVER`, pointing to `tests/subtle_server.py`).
   - Add `HoneypotConfig` frozen dataclass: `name: str`, `command: str`, `args: list[str]`, `ground_truth: GroundTruth`.
   - Replace `HONEYPOT_COMMAND` and `HONEYPOT_ARGS` with a `HONEYPOTS` list containing two `HoneypotConfig` entries (original + subtle).
   - Lower `THRESHOLDS["precision"]` from `1.0` to `0.85`.
   - Rename `run_single_audit` to `_run_single_honeypot(settings: Settings, honeypot: HoneypotConfig, budget: int) -> AuditReport`. It uses `honeypot.command` and `honeypot.args` instead of module constants.
   - Add `_run_one_eval(settings: Settings, budget: int) -> tuple[VerdictMap, GroundTruth, AuditReport]`. Iterates `HONEYPOTS`, calls `_run_single_honeypot` for each, merges verdicts via `dict.update`, merges ground truths via `dict.update`, collects all `tool_reports` into a single `AuditReport` with summed `TokenUsage`. Prints which honeypot is being audited (e.g., `"  Auditing {honeypot.name}..."`).
   - Update `run_evals()`: replace `run_single_audit(settings, budget)` call with `_run_one_eval(settings, budget)` which returns `(verdicts, ground_truth, audit_report)`. Pass `verdicts` directly instead of calling `aggregate_verdicts`. Pass `ground_truth` through to `_build_run_detail`.
   - Update `_build_run_detail` signature: add `ground_truth: GroundTruth` parameter. Replace `HONEYPOT_GROUND_TRUTH` references on current lines 139-140 with the `ground_truth` parameter.
   - Update console output in `run_evals()` loop: `f"Running eval {i + 1}/{num_runs}..."` stays, sub-honeypot progress is printed inside `_run_one_eval`.

**Test**: 5 integration tests for the subtle server as listed above. No new unit tests (no new domain/graph code). The multi-honeypot e2e eval changes are verified by type checking and linting; manual verification with `uv run python -m evals.run_evals --runs 1 --budget 5`.

**Verify**:
```bash
uv run pytest tests/unit -v
uv run pytest tests/integration -v
uv run ruff check .
uv run ruff format --check .
uv run pyright
```
