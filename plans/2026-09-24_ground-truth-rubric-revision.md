co# Ground truth rubric revision

## Context

The honeypot e2e evals compare the judge's aggregated verdict on each (tool, category) cell to `evals/ground_truth.py`, 40 cells over three servers. ADR 016 makes the honeypots fixtures, where only deliberately planted flaws count, and requires that the ground truth be revised by rubric: a written clause, applied to every cell it reaches, recorded in `docs/labeling-log.md` before its effect on the metrics is computed. That file does not exist yet.

The written intent of the three servers was annotated in `b4f422d`. Comparing the current ground truth to the writings of each server's creation found four labels changed after creation, none of them on a criterion independent of the system under test:

- `597491d` (2026-03-31) moved `project_manager × injection` from PASS to FAIL, with no reason written.
- `fa52ad8` (2026-04-01) moved `project_manager × input_validation` and `user_directory × input_validation` from FAIL to PASS, with no reason written, and `delete_record × error_handling` from PASS to FAIL "matching the category guidance", the judge's own guidance. The same commit changed the metric aggregation and the chain planning prompt.

It also found cells whose written intent the fixture does not carry out, flaws filed under a category the auditor does not have, and fixture behavior no writing mentions. The maintainer decided a rubric for all of it, clause by clause, with the eval report closed. This plan writes that rubric down, applies it, and fixes the one piece of instrument code that would otherwise make a removed cell count as a false positive.

It lands before the first baseline is recorded, so no recorded baseline is invalidated. Under ADR 016 a revision taken after the recording would be one more change to justify under a red gate.

## Approach

Three commits, no eval run. Before the first of them, and before any command that could write to `output/`, copy the last exploratory report without opening it: `cp -p output/eval_report.json output/eval_report_2026-09-23.json` (the runners write only `output/eval_report.json` and `output/judge_eval_report.json`, so a file under another name survives any later run). Check with `ls -l` that the copy is dated 2026-09-23 14:17. If the source is missing or carries another date, stop and tell the maintainer: the `Failing` column cannot then be filled from that run.

1. `fix(evals)`, instrument: precision, its resolution and consistency count only the cells of the ground truth. Test-first. Today `compute_precision` (`evals/metrics.py:80-85`) counts a FAIL on a cell with no label as a false positive (`ground_truth.get(key)` is `None`), `_largest_precision_move` (`evals/gate.py:187-193`) counts every predicted FAIL, and `compute_consistency` (`evals/metrics.py:88-111`) averages over every cell observed. The justification holds with no measurement in it: a verdict on a cell that has no label is neither right nor wrong, and ADR 016's "its cell leaves the ground truth" means nothing if the cell is still scored. The gate itself (`observe`, `classify`, `compare`) already iterates on the ground truth and needs no change.
2. `fix(evals)`, ground truth: create `docs/labeling-log.md` with the rubric and the first entry, apply it to `evals/ground_truth.py`, update the honeypot comments that still describe a removed cell as planted, and update the living docs.
3. `docs(evals)`, completing the entry: fill in the hash of commit 2 and, for each removed cell, whether it was the one failing, read from the per-run verdicts of the last exploratory report (the copy `output/eval_report_2026-09-23.json` of the run of 2026-09-23 14:17, prompts of `4ccd538`, 3 runs, budget 10). This reading happens only after commit 2 exists, so the rubric is on record before any per-cell outcome is read. ADR 016 requires the answer ("its log entry records whether the removed cell was the one failing").

### No eval run, no recomputed metric

Nothing here calls an LLM. Step 3 reads four cells' verdicts from an existing report and nothing else from it: it does not recompute recall, precision or any metric of that run under the revised ground truth. Such a number would be exploratory and would confirm nothing, and it is not needed by anything that follows. The next measurement is the pair of baseline recordings, after the fixture repair and the reset ADR.

## The rubric and its effect, decided

Clauses in the order they apply, with the cells each reaches. The normative text is the one in `docs/labeling-log.md` below.

- **R0, fixture.** A PASS means no flaw is planted in that category. Reaches no label.
- **R1, sources.** The verdicts written in the commit that adds a server hold its intent (`17ab3b2` from `plans/2026-03-17_evals.md`, `012aac4`, `aba94be`). A later change stands only if the new label follows from a criterion independent of the system under test. Returns four cells to their creation label: `delete_record × error_handling` PASS, `project_manager × injection` PASS, `project_manager × input_validation` FAIL, `user_directory × input_validation` FAIL. The categories and their definitions (ADR 004, `AuditCategory` since `190ffb8`) predate every honeypot and have not changed.
- **R2, current fixture.** Labels are read against the honeypot source at HEAD and the locked mcp 1.26.0 and pydantic 2.12.5. Records `f521cc5` as an instrument change. Reaches no label.
- **R3, FAIL mechanism not produced.** Removes `get_user × input_validation`: the creation plans pair it with a missing type check that raises a raw `TypeError` on a string (`plans/2026-03-16_honeypot-and-mcp-client.md`, section 2, `plans/2026-03-17_evals.md`), and FastMCP validates the argument before the tool runs, since the first commit of the server (mcp unchanged since).
- **R4, unrecoverable category.** Removes `project_manager × input_validation` (its creation notes file the flaw as "data_exfiltration"), `user_directory × input_validation` (its notes file it as "authentication", which ADR 004 defers, and `plans/2026-03-30_multi_step_chains.md`, committed 22 minutes after the server, files the same kind of flaw under info_leakage alone) and, by the same clause, `project_manager × injection` (ADR 004 names path traversal under injection, and the PASS there rested on the same unrecoverable choice).
- **R5, library.** Reaches no label. Lists known disagreements.
- **R6, unwritten behavior.** Reaches no label. Lists known disagreements.

Result: 36 cells, 8 FAIL and 28 PASS. Every tool keeps at least one cell, so `TOOL_COUNT` (`evals/honeypots.py:49`) stays 8 and `distribution_coverage` is untouched.

An earlier version of R5 removed the PASS cells whose creation writing promises a protection the library overrides (`list_items` and `get_service_status` in error_handling and info_leakage). It was withdrawn: under R0 a PASS rests on nothing being planted, and which cells that version reached depended on the wording of each plan ("generic", "clean errors"), not on the fixture. Those cells stay PASS with the disagreement listed.

## Files to modify

### `evals/metrics.py` (commit 1)

- `compute_precision(aggregated, ground_truth)`: count only predicted FAILs on cells present in `ground_truth`. Same signature.

```python
def compute_precision(aggregated: VerdictMap, ground_truth: GroundTruth) -> float:
    predicted_fails = [
        key
        for key, verdict in aggregated.items()
        if verdict == EvalVerdict.FAIL and key in ground_truth
    ]
    if not predicted_fails:
        return 1.0
    correct = sum(1 for key in predicted_fails if ground_truth[key] == EvalVerdict.FAIL)
    return correct / len(predicted_fails)
```

- `compute_consistency(all_runs, ground_truth)`: new second parameter, keys restricted to `ground_truth`. Iterate over the cells of `ground_truth` in place of the `all_keys` union, which goes away: the existing `total == 0` skip already drops a cell no run covered, so no separate "observed in a run" filter is needed. Return type unchanged.

### `evals/gate.py` (commit 1)

- `metric_resolutions`: pass `ground_truth` to `_largest_precision_move`, and rewrite the docstring sentence "Precision is averaged per run over that run's predicted FAILs, outside the ground truth included" to "Precision is averaged per run over that run's predicted FAILs on the cells of the ground truth".
- `_largest_precision_move(verdict_maps, ground_truth)`: count a predicted FAIL only when its cell is in `ground_truth`.

### `evals/judging.py` (commit 1)

- `RunsOutcome.metrics()` (line 41): `compute_consistency(self.verdict_maps, MERGED_GROUND_TRUTH)`. `MERGED_GROUND_TRUTH` is already imported there.

### Tests (commit 1, written first and run red)

`tests/unit/test_eval_metrics.py`:

- `test_precision_ignores_a_fail_outside_the_ground_truth`: ground truth `{("a", INPUT_VALIDATION): FAIL, ("a", ERROR_HANDLING): PASS}`, aggregated `{("a", INPUT_VALIDATION): FAIL, ("b", INJECTION): FAIL}` gives `1.0`. Red today (0.5).
- `test_consistency_ignores_a_cell_outside_the_ground_truth`: ground truth `{("a", INPUT_VALIDATION): FAIL}`, three runs agreeing on `("a", INPUT_VALIDATION)` and disagreeing on `("b", INJECTION)` give a score of `1.0` and details holding only `a/input_validation`. Red today.
- The three existing `compute_consistency` calls (lines 184, 208, 250) gain a ground truth holding the cells their runs use. Their expectations do not change.

`tests/unit/test_eval_gate.py`:

- Replace `test_precision_resolution_counts_a_fail_outside_the_ground_truth` (line 270) by `test_precision_resolution_ignores_a_fail_outside_the_ground_truth`: the same two runs, each with `VULNERABLE_CELL` FAIL and a FAIL outside the ground truth, give a resolution of `1 / (2 * 1)`. Red today (`1 / (2 * 2)`).
- `tests/unit/support/test_eval_gate_given.py::a_run_failing(fails)` builds its FAILs outside the ground truth, so the three resolution tests that use it (lines 282, 290, 302) would see no predicted FAIL once the fix lands. Give them FAILs inside a ground truth: a new given helper `a_ground_truth_failing(cells: int) -> GroundTruth` returning `{(f"tool_{index}", AuditCategory.INJECTION): FAIL for index in range(cells)}`, and those tests pass `given.a_ground_truth_failing(33)` (the largest `fails` they use) instead of `given.a_ground_truth()`. Their expected values do not change. Update `a_run_failing`'s docstring, which says the FAILs lie outside the ground truth.

### `docs/labeling-log.md` (new, commit 2, completed in commit 3)

Normative text. Commit 3 replaces the two placeholders `<commit 2>` and the `Failing` column values.

```markdown
# Labeling log

The ground truth of the honeypot evals (`evals/ground_truth.py`) is revised by rubric, never cell by cell ([ADR 016](adr/016-eval-gate-governance.md)). This file holds the rubric and one entry per revision. An entry carries what git does not: the clauses invoked, the state of the gate when the revision was taken, whether each removed cell was the one failing, and the known disagreements the revision leaves in place. The diff lives in the commit the entry points to.

## Rubric

The clauses apply in the order written. A clause reaches every cell it describes, including the ones it does not help.

**R0. A honeypot is a fixture.** Only a deliberately planted flaw makes a FAIL. A PASS means no flaw is planted in that category for that tool, not that a protection was checked.

**R1. The creation labels hold the intent.** The verdicts written in the commit that adds a server hold its intent. Other writings from that time, the creation plan and the notes committed with the server, can establish that two writings contradict each other, which a later clause acts on, and never set a verdict. Writings made after the creation index the intent and do not hold it: code comments, the ADRs that list the planted flaws, the judge's guidance and its fixture. A later label change stands only if the new label follows from a criterion formed independently of the system under test, and the judge's guidance is part of that system.

**R2. Labels are read against the current fixture.** The fixture is the honeypot source at HEAD together with the locked versions of the MCP SDK and of pydantic, which decide what reaches a tool and what comes back when an argument fails validation. A change to a honeypot's behavior after its labels were written is an instrument change and is recorded here.

**R3. A FAIL whose planted mechanism the fixture does not produce leaves the ground truth.** The creation writings have to tie to that cell a mechanism the current fixture produces, by naming it for the cell or, when they list one behavior per flawed category, by that pairing. Otherwise the intent cannot be recovered at the level of the mechanism.

**R4. A flaw whose category cannot be recovered leaves the ground truth, in every cell that could carry it.** When the creation writings file a planted flaw under a category the auditor does not have, or when another writing from that time files the same kind of flaw under a different category, the cell labelled with the flaw leaves. So does every other cell of the same tool whose category ADR 004 names the flaw's mechanism under, since a PASS there rests on the same choice. ADR 004 is read only where it names a mechanism word for word: read to the letter as a general arbiter, it defines info_leakage on error responses alone and would empty the category.

**R5. What the MCP library does is neither planted nor promised.** FastMCP validates arguments before the tool runs. Its validation message carries an internal model name and a link that gives the pydantic minor version, and it coerces some wrongly typed arguments instead of refusing them (`true` is read as `1`, `"42"` as `42`). This creates no FAIL and removes no PASS, including where a creation writing promised a protection the library overrides. A cell it exposes is listed as a known disagreement.

**R6. Behavior neither planted nor promised leaves a PASS in place.** A fixture branch no writing mentions does not make a FAIL. A cell where such a branch can be read as a flaw is listed as a known disagreement.

## Entries

### 2026-09-24, first revision

Commit: <commit 2>.

**State of the gate.** No baseline was recorded, so the absolute thresholds gated. The last measurement, exploratory (2026-09-23, 3 runs, budget 10, prompts of `4ccd538`), was under the precision threshold, so the revision was taken with the gate red. The clauses were written from the fixtures' written intent, with the eval report closed.

**What was known when the clauses were written.** The per-server totals of the 2026-09-23 run, and none of its per-cell detail. From the 2026-08-22 batch: `project_manager × input_validation` judged FAIL in every run against a PASS label, and every false positive of that batch in input_validation or error_handling.

**Changes.**

| Cell | Before | After | Clause | Failing |
|---|---|---|---|---|
| `delete_record × error_handling` | FAIL | PASS | R1: `fa52ad8` aligned it on the judge's guidance | n/a |
| `get_user × input_validation` | FAIL | removed | R3 | <step 3> |
| `project_manager × input_validation` | PASS | removed | R1 back to FAIL (`fa52ad8`), then R4 | <step 3> |
| `user_directory × input_validation` | PASS | removed | R1 back to FAIL (`fa52ad8`), then R4 | <step 3> |
| `project_manager × injection` | FAIL | removed | R1 back to PASS (`597491d`), then R4 | <step 3> |

The ground truth keeps 36 cells, 8 FAIL and 28 PASS. "Failing" gives, for each removed cell, the number of runs of the 2026-09-23 report (3 runs, budget 10, prompts of `4ccd538`) whose verdict on that cell contradicted the label then in force, written `k/3`. A run that did not cover the cell is counted apart, neither as contradicting nor as agreeing: `k/3, n not covered`. No rule turns that count into a yes or a no.

**Instrument changes.** `f521cc5` (2026-04-01) typed the chain tools' `action` argument as a `Literal`, because the chain planner was guessing action names. It replaced the fixture's own `Unknown action` error by the library's validation message. The commit before this one restricts precision, its resolution and consistency to the cells of the ground truth, so a removed cell is no longer scored. The facts above hold for mcp 1.26.0 and pydantic 2.12.5.

**Known disagreements left in place.**

- R5, the validation message on a wrongly typed argument: error_handling of `execute_query`, `list_items`, `search_users`, `delete_record`, `get_service_status`, `project_manager` and `user_directory`, and info_leakage of `list_items`, `delete_record` and `get_service_status`. `list_items` and `get_service_status` were promised a generic error by their creation plans.
- R5, lax coercion of an integer argument: input_validation of `list_items` and `search_users`.
- R6, `project_manager`'s `read_file` echoes any other path back, whatever its length: resource_abuse of `project_manager`.
- R1, the planted silent success of `delete_record` on an unknown id is filed under input_validation at creation, and can be read as missing not-found handling: error_handling of `delete_record`.

**The four questions of ADR 016.** (1) The change lands in the instrument: the ground truth here, the scoring code in its own commit. (2) The four label changes after creation were found in git history while annotating the fixtures' intent. The disagreement on `project_manager × input_validation` was first noticed through the metric of 2026-08-22, which moves the burden to (3) and (4). (3) Every label follows from the creation writings or from ADR 004, all of which predate the first measurement. (4) Each clause was applied across the 40 cells. R1 moves two cells toward PASS and two toward FAIL, and the removals take out one expected FAIL (R3) and, through R1 then R4, cells in both directions.

**Left to other work.** The judge's isolation fixture now agrees with the ground truth on `delete_record × error_handling`, and keeps a `get_user × input_validation` case (id `0`) that no e2e cell scores. A cell that holds several valid categories is not modelled: R4 removes such cells instead.
```

### `evals/ground_truth.py` (commit 2)

Apply the table: `delete_record × error_handling` becomes `EvalVerdict.PASS`, and the four removed cells are deleted. Add a one-line module docstring that carries only the non-obvious part (the module and `GroundTruth` names already say what it holds): `"""A cell absent from a tool was removed by a rubric clause: see docs/labeling-log.md."""`. The mapping stays in the same order otherwise.

### Honeypot comments (commit 2)

Comments and docstrings only, no behavior change. None of them may still call a removed cell planted.

- `tests/honeypot_server.py`, module docstring: replace "asserts the expected verdict for each (tool, category) pair" by "asserts the expected verdict for the (tool, category) pairs it keeps, and `docs/labeling-log.md` records the ones it dropped".
- `tests/honeypot_server.py:22`: `# Planted error_handling: unknown ids raise a raw KeyError. The creation plan filed a missing type check under input_validation, which the MCP library performs before this code runs, so that cell left the ground truth (labeling log, R3).`
- `tests/chain_honeypot_server.py`, module docstring: after the sentence on the labels of `aba94be`, add "The ground truth no longer holds input_validation for either tool nor injection for project_manager: `docs/labeling-log.md` records why."
- `tests/chain_honeypot_server.py:86-87`: `# Planted info_leakage, chain step 3: read_file checks no path, so the admin path returns credentials and API keys. aba94be labels it input_validation and its notes call it data exfiltration by path traversal, so its category cannot be recovered and its input_validation and injection cells left the ground truth (labeling log, R4).`
- `tests/chain_honeypot_server.py:90-91`: `# No record names this branch: any other path is accepted and echoed back.`
- `tests/chain_honeypot_server.py:148-150`: keep the comment, and replace its final period (after "a category the auditor does not have") by ", so that cell left the ground truth (labeling log, R4)."

### `README.md:153` (commit 2)

Replace "With 11 expected positives, one false positive moves a run's precision by about 0.08" by "With 8 expected positives, one false positive moves a run's precision by about 0.11". The rest of the paragraph stays.

### `CHANGELOG.md`, `[Unreleased]`, `### Changed` (commit 2)

Add first in the list: "The honeypot eval ground truth is revised by rubric: four labels changed after the servers were written return to their creation verdict, and four cells whose planted flaw cannot be tied to a mechanism or a category leave it, which keeps 36 cells, 8 of them expected failures. Precision, its resolution and consistency now count only the cells of the ground truth. The rubric and the revision are recorded in `docs/labeling-log.md`."

### `CONTRIBUTING.md:86` (commit 2)

After "revisions go by rubric, never cell by cell", add: "The rubric and every revision live in [`docs/labeling-log.md`](docs/labeling-log.md)."

## What stays unchanged

- Every honeypot's behavior: `tests/*_server.py` change in comments and docstrings only. Repairing the fixtures so they return a generic error on a wrongly typed argument is a separate plan, before the first baseline.
- `evals/fixtures/judge_cases.json` and the judge isolation eval.
- The gate's comparison code (`observe`, `classify`, `compare`, replay), `compute_recall`, `compute_distribution_coverage`, `aggregate_verdicts`, `export.py` (already maps a cell without a label to `None`).
- Every prompt and everything under `src/`.
- ADRs, including ADR 013:41 ("eleven planted flaws") and ADR 016's figures, which are dated and immutable.
- `CLAUDE.md`, which already names `docs/labeling-log.md`.
- No baseline is recorded, no eval is run.

## Edge cases

- A run that covers none of a cell of the ground truth: `compute_consistency` still skips it (`total == 0`), as today.
- A run whose only predicted FAILs lie outside the ground truth: precision is `1.0` for that run (no predicted FAIL counted), and `_largest_precision_move` treats it as a run with no predicted FAIL, which the existing `max(fails, 1)` already handles.
- The contamination test derives literals from the honeypots by AST, docstrings included. The new docstring sentences are long multi-word strings that no `src/` constant contains, so the test stays green. Run it to confirm.
- The ground truth fingerprint (`evals/baseline.py:61`) changes. No baseline exists, so nothing becomes non-comparable.
- Step 3 finds a removed cell that some run of the report did not cover: write `k/3, n not covered` as the entry defines, rather than guessing.

## Test scenarios

Covered in "Tests (commit 1)": precision and consistency ignore a cell outside the ground truth, the precision resolution ignores a FAIL outside the ground truth, and the existing resolution and consistency tests keep their expected values with FAILs moved inside a ground truth. The ground truth itself is data, and no test pins its contents.

## Verification

```bash
uv run pytest tests/unit
uv run pytest tests/integration
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

After commit 2, `uv run python -c "from evals.honeypots import MERGED_GROUND_TRUTH as g; print(len(g), sum(v.value == 'fail' for v in g.values()))"` prints `36 8`.

## Commit messages

1. `fix(evals): score only the cells of the ground truth`. Body: precision counted a FAIL on a cell with no label as a false positive, and its resolution and consistency counted such cells too. A cell removed from the ground truth kept costing precision. Instrument change, justified without any measurement.
2. `fix(evals): revise the honeypot ground truth by rubric`. Body: points to `docs/labeling-log.md` for the clauses and the four questions, names the four labels returned to their creation verdict and the four removed cells.
3. `docs(evals): record whether each removed cell was failing`. Body: read from the per-run verdicts of the 2026-09-23 exploratory report, after the rubric was committed, for the four removed cells only.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, read by the implementation-phase fact check. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `mcp` `1.26.0` and `pydantic` `2.12.5` are the locked versions (verified against `uv.lock` and the installed packages), and the `mcp` entry of `uv.lock` has not changed since `095e7f5` (2026-03-15), before the first honeypot commit.
- SETTLED: FastMCP validates arguments before the tool runs, and a wrongly typed argument returns `1 validation error for get_userArguments` with the link `https://errors.pydantic.dev/2.12/v/int_parsing` (verified by calling a FastMCP tool under the locked versions). The link carries the minor version `2.12`, not the patch.
- SETTLED: on an `int` argument FastMCP coerces `true` to `1` and `"42"` to `42` instead of refusing them (verified by the same call).
- SETTLED: ADR 004 names path traversal under injection, defines info_leakage on error messages, and defers authentication (verified against `docs/adr/004-mcp-threat-model.md`, added in `095e7f5`, before every honeypot).
- OPEN (deferred): the `Failing` column values of `docs/labeling-log.md`, read in commit 3 from the copy `output/eval_report_2026-09-23.json` taken before commit 1. The copy is checked by date only, so the run's conditions are read from the copy in commit 3.

## Implementation steps

The three steps follow the three commits of the Approach, one commit each, in order. None of them runs an eval or calls an LLM. Only step 3 opens the report copy.

### Step 1: copy the report, then score only the cells of the ground truth

- **Files**: `output/eval_report_2026-09-23.json` (copy, untracked), `tests/unit/test_eval_metrics.py`, `tests/unit/test_eval_gate.py`, `tests/unit/support/test_eval_gate_given.py`, `evals/metrics.py`, `evals/gate.py`, `evals/judging.py`
- **Do**:
  1. Before anything else, and before any command that could write to `output/`: `cp -p output/eval_report.json output/eval_report_2026-09-23.json`, then `ls -l output/eval_report_2026-09-23.json`. It must be dated 2026-09-23 14:17. If the source is missing or carries another date, stop and report to the maintainer. Do not open, read, `cat`, `head` or parse either file in this step.
  2. Tests first, as listed in "Tests (commit 1)":
     - `tests/unit/test_eval_metrics.py`: add `test_precision_ignores_a_fail_outside_the_ground_truth` and `test_consistency_ignores_a_cell_outside_the_ground_truth`. Give the three existing `compute_consistency` calls (lines 184, 208, 250) a ground truth holding the cells their runs use, expectations unchanged.
     - `tests/unit/support/test_eval_gate_given.py`: add `a_ground_truth_failing(cells: int) -> GroundTruth` returning `{(f"tool_{index}", AuditCategory.INJECTION): EvalVerdict.FAIL for index in range(cells)}`. Rewrite the docstring of `a_run_failing`, which says its FAILs lie outside the ground truth (they now lie in `a_ground_truth_failing` when it is large enough).
     - `tests/unit/test_eval_gate.py`: replace `test_precision_resolution_counts_a_fail_outside_the_ground_truth` (line 270) by `test_precision_resolution_ignores_a_fail_outside_the_ground_truth`, same two runs, expected `1 / (2 * 1)`. The three tests using `a_run_failing` (lines 282, 290, 302) pass `given.a_ground_truth_failing(33)` in place of `given.a_ground_truth()`, expected values unchanged.
     - Run `uv run pytest tests/unit/test_eval_metrics.py tests/unit/test_eval_gate.py` and confirm the three new tests are red (the consistency one fails on the call signature or on the details) and the three resolution tests were already green before switching their ground truth.
  3. Production code:
     - `evals/metrics.py`: `compute_precision` counts only predicted FAILs whose key is in `ground_truth` (code in the plan). `compute_consistency(all_runs, ground_truth)` iterates over the cells of `ground_truth`, sorted as today by `(tool, category.value)`, in place of the `all_keys` union, which goes away. The `total == 0` skip stays.
     - `evals/gate.py`: `_largest_precision_move(verdict_maps, ground_truth)` counts a FAIL only when its cell is in `ground_truth`. `metric_resolutions` passes `ground_truth` to it, and its docstring sentence becomes "Precision is averaged per run over that run's predicted FAILs on the cells of the ground truth" (reflow the rest of the docstring as needed, meaning unchanged).
     - `evals/judging.py:41`: `compute_consistency(self.verdict_maps, MERGED_GROUND_TRUTH)`.
  4. Commit: `fix(evals): score only the cells of the ground truth`, body as in "Commit messages" item 1. The copy under `output/` is not committed.
- **Test**:
  - Precision: ground truth `{("a", INPUT_VALIDATION): FAIL, ("a", ERROR_HANDLING): PASS}`, aggregated `{("a", INPUT_VALIDATION): FAIL, ("b", INJECTION): FAIL}` gives `1.0` (was 0.5).
  - Consistency: ground truth `{("a", INPUT_VALIDATION): FAIL}`, three runs agreeing on that cell and disagreeing on `("b", INJECTION)`, gives score `1.0` and details holding only `a/input_validation`.
  - Precision resolution: two runs each with `VULNERABLE_CELL` FAIL plus one FAIL outside the ground truth give `1 / (2 * 1)` (was `1 / (2 * 2)`).
  - Existing consistency and resolution tests keep their expected values.
- **Verify**: `uv run pytest tests/unit`, `uv run pytest tests/integration`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green.

### Step 2: revise the ground truth by rubric

- **Files**: `docs/labeling-log.md` (new), `evals/ground_truth.py`, `tests/honeypot_server.py`, `tests/chain_honeypot_server.py`, `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`
- **Do**: do not open `output/eval_report.json` or its copy in this step.
  1. `docs/labeling-log.md`: create it with the normative text of the plan section "`docs/labeling-log.md`", verbatim, including the placeholders `<commit 2>` and `<step 3>`, which step 3 fills.
  2. `evals/ground_truth.py`: `delete_record × error_handling` becomes `EvalVerdict.PASS`. Delete `get_user × input_validation`, `project_manager × input_validation`, `user_directory × input_validation` and `project_manager × injection`. Add the module docstring `"""A cell absent from a tool was removed by a rubric clause: see docs/labeling-log.md."""`. Keep the order otherwise.
  3. Honeypot comments and docstrings only, no behavior change, exact wording in the plan section "Honeypot comments": `tests/honeypot_server.py` module docstring and line 22, `tests/chain_honeypot_server.py` module docstring and lines 86-87, 90-91, 148-150. Line numbers are as of the plan: locate them by content. Afterwards grep both files so that no comment still calls a removed cell planted.
  4. Living docs: `README.md:153` ("With 8 expected positives, one false positive moves a run's precision by about 0.11"), `CHANGELOG.md` `[Unreleased]` `### Changed` first entry, `CONTRIBUTING.md:86` sentence, exact text in the plan.
  5. Commit: `fix(evals): revise the honeypot ground truth by rubric`, body as in "Commit messages" item 2 (points to `docs/labeling-log.md`, names the four labels returned to their creation verdict and the four removed cells).
- **Test**: no new test (the ground truth is data). `tests/unit/test_fixture_contamination.py` must stay green with the new docstring sentences.
- **Verify**: `uv run pytest tests/unit`, `uv run pytest tests/integration`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green. `uv run python -c "from evals.honeypots import MERGED_GROUND_TRUTH as g; print(len(g), sum(v.value == 'fail' for v in g.values()))"` prints `36 8`. `git diff HEAD~1 --stat -- tests/` shows only the two honeypot files, and their diff touches comments and docstrings only.

### Step 3: record whether each removed cell was failing

- **Files**: `docs/labeling-log.md`
- **Do**: this is the first and only step that opens the report copy, and it runs only once commit 2 exists (`git log -1 --format=%s` shows `fix(evals): revise the honeypot ground truth by rubric`).
  1. Replace `<commit 2>` by the short hash of that commit.
  2. Open `output/eval_report_2026-09-23.json`. First confirm the run's conditions from the file itself: 3 runs, budget 10. If they differ, stop and report to the maintainer rather than filling the column.
  3. For each of the four removed cells (`get_user × input_validation`, `project_manager × input_validation`, `user_directory × input_validation`, `project_manager × injection`), read the per-run verdicts and count the runs whose verdict contradicted the label in force before commit 2 (FAIL, PASS, PASS, FAIL respectively). Write `k/3`, or `k/3, n not covered` when some runs did not cover the cell. Replace the four `<step 3>` placeholders with these values. Read nothing else from the report: no recall, precision or other metric is recomputed, and no other cell is looked at.
  4. Commit: `docs(evals): record whether each removed cell was failing`, body as in "Commit messages" item 3.
- **Test**: none (documentation only).
- **Verify**: `grep -n "<commit 2>\|<step 3>" docs/labeling-log.md` returns nothing. `uv run pytest tests/unit` stays green. `git status` shows no tracked change left (`output/` is gitignored, so the copy never shows up).
