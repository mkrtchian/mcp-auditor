# Honeypot fixture repair: the library's validation noise

## Context

The ground truth revision of 2026-09-24 (`docs/labeling-log.md`, first entry) left known disagreements in place under its clause R5: what the MCP library does is neither planted nor promised, so it creates no FAIL and removes no PASS, and a cell it exposes is listed. Two library behaviors are listed:

- **The validation message.** FastMCP validates a tool's arguments before the tool runs. A wrongly typed or missing argument returns `Error executing tool get_user: 1 validation error for get_userArguments ... For further information visit https://errors.pydantic.dev/2.12/v/int_parsing`. That text names an internal model and gives the pydantic minor version, which reads as an error_handling or info_leakage flaw on cells labelled PASS: error_handling of `execute_query`, `list_items`, `search_users`, `delete_record`, `get_service_status`, `project_manager` and `user_directory`, and info_leakage of `list_items`, `delete_record` and `get_service_status`. The creation plans of `list_items` and `get_service_status` promised a generic error.
- **Lax coercion.** `limit: int` accepts `true` as `1` and `"42"` as `42`, on `list_items` and `search_users`, two PASS controls whose creation writings describe a validated, clamped limit.

On those cells the fixture shows a flaw its label says is not planted, so a judge that reports what it sees is scored wrong. This plan makes the fixture carry out its written intent on those cells. It is an instrument change under R2, recorded in the labeling log. It changes no label, no prompt and no scoring code.

The justification holds with every mention of a measurement deleted: a fixture whose PASS cells exhibit an unplanted flaw does not test what its labels say it tests.

## Approach

Both fixes stay inside each honeypot server file, so the published tool schemas do not change.

- **Generic validation error.** Each server subclasses `FastMCP` and overrides `call_tool`. When the library's `ToolError` is caused by a pydantic `ValidationError`, the override raises a `ToolError` whose text is `Error executing tool <name>: Invalid arguments`. The prefix is the library's own prefix on every error a tool's run raises (`Unknown tool` has none), so only the pydantic detail disappears. Every other error passes through untouched, including the planted errors raised in tool bodies (`get_user`'s raw `KeyError`, its leaked path, `list_items`' `Invalid category`) and the library's `Unknown tool`.
- **Strict limits.** The `limit` argument of `list_items` and of `search_users` becomes `Annotated[int, Strict()]`. `true`, `"42"` and `1.5` are then rejected, and the rejection goes through the generic error. The published `inputSchema` is byte-identical (checked under the locked versions: `{"type": "integer"}` either way). No other argument becomes strict: `delete_record` carries a planted input_validation flaw, `get_user × input_validation` left the ground truth, and neither belongs to an R5 disagreement.

Why the code is repeated in the three files rather than shared: `fingerprint_source` (`evals/baseline.py`) hashes each honeypot server file, and the contamination test (`tests/unit/test_fixture_contamination.py`) reads the literals of those three files only. A shared module would change the fixture's behavior without moving either. Three copies of about ten lines are the cheaper side.

Why the override and not relaxed schemas (arguments published as `str`, validated in the tool body): the published schema is what the generator reads. Changing it would change an input of the system under test inside an instrument change, and the two effects would not be separable in the measurement that follows.

The mechanism relies on two facts of `mcp` 1.26.0: the low-level handler is registered as `self.call_tool` in `FastMCP._setup_handlers` (`server.py:308`, so a subclass override is used), and `Tool.run` raises `ToolError(...) from e`, so the pydantic error is the `__cause__`. Integration tests pin the observable result, so a library upgrade that breaks either fact fails a test rather than silently restoring the noise.

## Files to modify

### `tests/honeypot_server.py`, `tests/subtle_server.py`, `tests/chain_honeypot_server.py`

In each, before `app = ...`:

```python
from collections.abc import Sequence
from typing import Annotated, Any  # Annotated in honeypot_server and subtle_server only

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ContentBlock
from pydantic import Strict, ValidationError  # Strict only where a limit is strict


class GenericArgumentErrors(FastMCP):
    # Instrument repair, labeling log: the library's validation message names an internal
    # model and the pydantic version, a flaw no label planted.
    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> Sequence[ContentBlock] | dict[str, Any]:
        try:
            return await super().call_tool(name, arguments)
        except ToolError as error:
            if isinstance(error.__cause__, ValidationError):
                raise ToolError(f"Error executing tool {name}: Invalid arguments") from None
            raise


app = GenericArgumentErrors("honeypot")  # server name unchanged in each file
```

The class name, comment wording and imports are indicative: the return annotation must match the base method's so pyright accepts the override. If the contamination test flags a new literal or name from these lines (it reads string constants and function names of the three servers), rename in the honeypot, never in `src/`.

- `tests/honeypot_server.py`: `list_items(category: str, limit: Annotated[int, Strict()] = 10)`, with the existing PASS-control comment extended to say the limit is also type-checked strictly.
- `tests/subtle_server.py`: `search_users(query: str, limit: Annotated[int, Strict()] = 10)`, same comment treatment.
- `tests/chain_honeypot_server.py`: the two `# Deliberate PASS control: unreachable since f521cc5 typed action as a Literal.` comments stay true. The module docstring keeps its meaning.
- Module docstrings: one sentence each, saying the server returns a generic error on invalid arguments by design and pointing to the labeling log. Check the sentence against `test_fixture_contamination.py` (it compares three-word runs with `src/` constants, which is why `fe69924` wrote "on the (tool, category) pairs").

### `tests/integration/test_mcp_client.py`, `tests/integration/test_subtle_server.py`, `tests/integration/test_chain_honeypot.py`

New tests, written first and run red (see Test scenarios). They assert on the response text a client receives, in the style of the existing tests (`response.is_error`, `response.content`).

### `docs/labeling-log.md`

A new entry after the first one, `### <date of the commit>, fixture repair`. The first entry is not edited. The new entry says:

- **Ground truth.** Unchanged, 36 cells, 8 FAIL.
- **Instrument change (R2).** The three servers return `Error executing tool <name>: Invalid arguments` in place of the library's validation message, and the `limit` of `list_items` and `search_users` is strictly an integer. The published schemas are unchanged. The mechanism holds for mcp 1.26.0 and pydantic 2.12.5, as the first entry states for its facts. Commit: `<commit>`.
- **Disagreements resolved.** Both R5 bullets of the first entry, every cell they list.
- **Disagreements still in place.** The R6 bullet (`project_manager` resource_abuse) and the R1 bullet (`delete_record` error_handling).
- **What was known when the repair was decided.** Everything the first entry lists, plus its "Known after the revision" section: the per-cell verdicts of the four removed cells and of `delete_record × error_handling`, and the aggregates re-scored under both instruments. Not the per-cell verdicts of any R5 cell.
- **The four questions of ADR 016.** (1) The change lands in the instrument, the fixture. (2) The disagreements were found while writing the rubric, from the fixture's code and the library's behavior, with the eval report closed. (3) The target behavior is the creation writings' (a PASS control without a planted flaw, a generic error where a plan promised one), which predate every measurement. (4) The repair applies to every cell R5 lists, including PASS cells of tools that carry planted flaws in other categories. It works in both directions. On the PASS cells it lists, it removes an unplanted flaw, which can raise the measured precision. On four planted FAIL cells (`get_user` error_handling and info_leakage, info_leakage of `project_manager` and `user_directory`), it removes the library message a judge could have read as evidence, which can lower the measured recall. Both directions are stated here before any measurement.

### Living docs

No command, flag, env var or user-facing behavior changes. `README.md`, `CONTRIBUTING.md` and `CHANGELOG.md` stay as they are. `CLAUDE.md` Landmines already says the honeypots carry planted flaws, so it gets nothing.

## What stays unchanged

- Every planted flaw and every error a tool body raises, word for word.
- The published `inputSchema` of every tool, byte for byte, and each server's name.
- `evals/ground_truth.py`, every prompt in `src/`, the scoring code, `evals/fixtures/judge_cases.json` (its `get_user` case with `Error executing tool get_user: 0` is a body error and stays true).
- The first entry of `docs/labeling-log.md`.
- `plans/` and `docs/adr/`.

## Edge cases

- Missing required argument: a `ValidationError` too, so the generic error.
- Unknown tool name: `ToolError` without a pydantic cause, library message unchanged.
- Unknown `action` on the chain tools: rejected by the `Literal` in validation, so the generic error. The unreachable `Unknown action` branches stay as they are.
- A tool body raising its own `ValueError`: wrapped by the library in `ToolError` with a `ValueError` cause, passes through unchanged. That covers every planted error and every PASS-control error.
- Extra unknown arguments (`{"user_id": 1, "extra": 2}`): accepted and ignored today, unchanged.
- `limit` given as a float with no fractional part (`5.0`): rejected under strict, generic error.

## Test scenarios

Integration tests, against the real servers. Each new test is red before the change.

- `get_user` with `{"user_id": "abc"}`: `is_error` is true, content is exactly `Error executing tool get_user: Invalid arguments`, contains neither `validation error` nor `pydantic`.
- `get_user` with `{}`: the same generic error.
- `list_items` with `{"category": "books", "limit": True}` and with `"42"`: the generic error (today `true` succeeds with `showing 1`).
- `list_items` with `{"category": "books", "limit": 9999}`: still succeeds (existing `test_list_items_clamps_limit`, which asserts only `is_error is False`, stays green). Extend it to assert `showing 100` in the content, so the clamp is pinned under the strict type.
- `search_users` with `{"query": "Alice", "limit": True}`: the generic error.
- `delete_record` with `{"record_id": "abc"}`: the generic error, and `{"record_id": -5}` still succeeds (existing test).
- `project_manager` with `{"action": "delete"}`: the generic error.
- Planted body errors unchanged: `get_user` with `-1` still leaks `/opt/mcp-server/internal/users.db` (existing test), `get_user` with `0` still returns an error whose content is `Error executing tool get_user: 0`, `list_items` with an unknown category still returns `Invalid category`.
- Schema pin: `list_tools()` on `honeypot_server.py` returns for `list_items` an `input_schema` whose `limit` property is `{"default": 10, "title": "Limit", "type": "integer"}`. One test is enough, it guards the reason the approach was chosen.

No unit test: the change lives in the fixtures, which the integration level covers (ADR 003).

## Verification

- `uv run pytest tests/unit`, `uv run pytest tests/integration`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: all green.
- `git diff HEAD~1 -- evals/ src/` is empty for the repair commit.
- `grep -rn "errors.pydantic" tests/` returns nothing.

## Commit messages

1. `fix(tests): return a generic error on invalid honeypot arguments`: the two fixes, the integration tests, the labeling log entry with `<commit>` left as a placeholder. Body: the fixture showed an unplanted flaw on PASS cells (the library's validation message, lax coercion of two limits), the repair keeps the published schemas, it is an instrument change recorded in `docs/labeling-log.md`, which answers ADR 016's four questions.
2. `docs(evals): record the fixture repair commit`: fills `<commit>` with the short hash of commit 1.

## Bars written before measurement

Written here so the exploratory run cannot shape them.

- The run is `uv run python -m evals.run_evals --ungated --runs 3 --budget 10 --report output/eval_report_fixture-repair.json`, on the default models, at the commit that follows commit 2, on a clean tree. It is exploratory under ADR 016: reported, confirming nothing.
- Its reference is the 2026-09-23 report re-scored under the revised ground truth (labeling log, "Known after the revision"): recall 0.75, precision 0.67, consistency 0.96. The difference mixes the repair's effect with run-to-run noise. One cell in one run moves the mean recall by about 0.04 (8 expected positives, 3 runs) and the mean precision by about 0.04 at the reference's level. A delta under that is inconclusive.
- Either direction is possible (question 4 above): precision may rise on the repaired PASS cells, and recall may fall on the four planted FAIL cells whose tools emitted the library message. A recall drop beyond the resolution has two readings: a detection that rested on the library's noise and no longer does, or a planted flaw the repair damaged. They are told apart in the fixture's code (does the planted branch still behave as its comment says), never by a prompt or label change.
- Nothing in the tree reacts to the numbers: no prompt, label, threshold or floor changes because of this run. If precision stays under 0.85, the legacy gate stays red. If a metric falls under its floor of 0.50, a baseline recording will be refused, and lowering a floor needs a new ADR that this plan does not write.
- The aggregates and the per-server totals are not committed. This run is also the reference on this tree for comparing another model under the same conditions.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, read by later passes. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, on 2026-09-24, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `mcp 1.26.0` and `pydantic 2.12.5` are the locked and installed versions (verified against `uv.lock` and the project venv)
- SETTLED: `self._mcp_server.call_tool(validate_input=False)(self.call_tool)` at `mcp/server/fastmcp/server.py:308`, bound at setup so a subclass override is the handler (verified against the installed mcp 1.26.0 source, and by an in-process probe)
- SETTLED: `raise ToolError(f"Error executing tool {self.name}: {e}") from e` in `Tool.run` (verified against `mcp/server/fastmcp/tools/base.py`, mcp 1.26.0)
- SETTLED: `async def call_tool(self, name: str, arguments: dict[str, Any]) -> Sequence[ContentBlock] | dict[str, Any]` is the base signature the override must match (verified against the installed source)
- SETTLED: `Unknown tool: <name>` is raised as a `ToolError` without a cause, and reaches the client unchanged (verified by probe)
- SETTLED: `limit: Annotated[int, Strict()] = 10` publishes `{"default": 10, "title": "Limit", "type": "integer"}`, identical to `limit: int = 10` (verified by probe under the locked versions)
- SETTLED: under `Strict()`, `true`, `"42"` and `5.0` are rejected, `9999` still returns `showing 100`, and without it `true` returns `showing 1` (verified by probe)
- SETTLED: the override turns wrong-type and missing-argument errors into `Error executing tool <name>: Invalid arguments` and leaves `Invalid category` untouched (verified by probe)
- SETTLED: `--ungated`, `--runs`, `--budget`, `--report` exist on `evals.run_evals` (verified against `evals/run_evals.py`)
- OPEN (currency): `mcp>=1.0.0` in `pyproject.toml` lets a lock upgrade move past 1.26.0, where either mechanism fact may change. The plan's integration tests are the guard, not this record.

## Implementation steps

### Step 1: Generic validation error and strict limits in the three honeypots

- **Files**:
  - `tests/integration/test_mcp_client.py`, `tests/integration/test_subtle_server.py`, `tests/integration/test_chain_honeypot.py` (tests, written first)
  - `tests/honeypot_server.py`, `tests/subtle_server.py`, `tests/chain_honeypot_server.py`
  - `docs/labeling-log.md`
- **Do**:
  1. Write the new integration tests listed under Test below, in the existing style (one `async with StdioMCPClient.connect(LAUNCH) as client:` per test, assertions on `response.is_error` and `response.content`, grouped in the existing `TestDiscovery` / `TestErrorPaths` / `TestHappyPaths` classes or a new class where none fits). Run `uv run pytest tests/integration` and confirm each new test is red (the schema pin and the planted-body-error tests may already be green: they are guards, not red-first tests; say so in the report).
  2. In each of the three servers, add the `GenericArgumentErrors(FastMCP)` subclass from "Files to modify" before `app = ...`, and build `app` from it with the server name unchanged. The override catches `ToolError`, re-raises `ToolError(f"Error executing tool {name}: Invalid arguments") from None` only when `error.__cause__` is a pydantic `ValidationError`, and re-raises everything else untouched. Its signature must match `FastMCP.call_tool` exactly (`name: str, arguments: dict[str, Any]) -> Sequence[ContentBlock] | dict[str, Any]`) so pyright strict accepts it. Keep the non-obvious "why" comment (instrument repair, the library message is an unplanted flaw, see labeling log).
  3. `tests/honeypot_server.py`: `list_items(category: str, limit: Annotated[int, Strict()] = 10)`. Extend the `# Deliberate PASS control` comment to say the limit is also type-checked strictly.
  4. `tests/subtle_server.py`: `search_users(query: str, limit: Annotated[int, Strict()] = 10)`, same comment treatment.
  5. `tests/chain_honeypot_server.py`: override only, no strict argument. The two `# Deliberate PASS control: unreachable since f521cc5 ...` comments and the module docstring meaning stay.
  6. Add one sentence to each module docstring: the server returns a generic error on invalid arguments by design, see `docs/labeling-log.md`.
  7. Run `uv run pytest tests/unit/test_fixture_contamination.py`. If it flags a literal or function name introduced by these lines, rename in the honeypot (class name, comment, docstring wording), never in `src/`.
  8. `docs/labeling-log.md`: append a new entry `### 2026-09-24, fixture repair` after the first entry, without editing the first entry. Content exactly as specified in "Files to modify > docs/labeling-log.md" (Ground truth unchanged 36 cells 8 FAIL, instrument change R2 with versions mcp 1.26.0 and pydantic 2.12.5 and `Commit: <commit>` left as a literal placeholder, disagreements resolved, disagreements still in place, what was known, the four questions of ADR 016). Read the first entry to match its structure and tone (no em dashes, no semicolons).
  9. Do not touch `evals/`, `src/`, `plans/`, `docs/adr/`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `CLAUDE.md`. Every planted flaw and body error stays word for word.
- **Test** (integration, real servers):
  - `test_mcp_client.py`:
    - `get_user` with `{"user_id": "abc"}`: `is_error` true, content exactly `Error executing tool get_user: Invalid arguments`, contains neither `validation error` nor `pydantic`.
    - `get_user` with `{}`: the same generic error.
    - `list_items` with `{"category": "books", "limit": True}` and with `{"category": "books", "limit": "42"}`: the generic error (two tests or one parametrized test).
    - Extend `test_list_items_clamps_limit` to assert `"showing 100"` in the content.
    - `get_user` with `{"user_id": 0}`: error whose content is `Error executing tool get_user: 0` (planted body error unchanged). The existing `-1` path leak and `Invalid category` tests stay as they are.
    - Schema pin: `list_tools()`, the `list_items` tool's `input_schema["properties"]["limit"] == {"default": 10, "title": "Limit", "type": "integer"}`.
  - `test_subtle_server.py`:
    - `search_users` with `{"query": "Alice", "limit": True}`: the generic error for `search_users`.
    - `delete_record` with `{"record_id": "abc"}`: the generic error for `delete_record` (existing `-5` test stays green).
  - `test_chain_honeypot.py`:
    - `project_manager` with `{"action": "delete"}`: the generic error for `project_manager`.
- **Verify**:
  - `uv run pytest tests/integration`: all green (new tests went red before step 2 of Do).
  - `uv run pytest tests/unit`: all green, including `test_fixture_contamination.py`.
  - `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: clean.
  - `git diff -- evals/ src/` empty. `grep -rn "errors.pydantic" tests/` returns nothing.
- **Commit**: `fix(tests): return a generic error on invalid honeypot arguments`, body as in "Commit messages" item 1.

### Step 2: Record the repair commit in the labeling log

- **Files**: `docs/labeling-log.md`
- **Do**: Replace the `<commit>` placeholder of the fixture repair entry with the short hash of the step 1 commit (`git log -1 --format=%h` on that commit). Nothing else changes.
- **Test**: none (documentation only).
- **Verify**: `grep -n "<commit>" docs/labeling-log.md` returns nothing, `git diff` touches only that line.
- **Commit**: `docs(evals): record the fixture repair commit`.

The exploratory run of "Bars written before measurement" is not a step: the maintainer runs it after step 2 on a clean tree.
