# How the honeypot baseline changes: the instrument ADR 020 needs before a first recording

## Context

[ADR 020](../docs/adr/020-honeypot-baseline-changes.md) (Accepted in `e4cc418`) governs how the baseline of the honeypot suite, `evals/baselines/honeypot_e2e.json`, changes. It amends four clauses of ADR 016 for that suite. No baseline is recorded yet. This plan builds, before the first recording, what the ADR needs from the code, and fixes the living docs to match. It records no baseline: the two recordings (exploratory, then confirmed, at one commit) come later, by hand, after other work.

What the code does today, and what ADR 020 says it must do instead:

- **A label revision is refused.** `condition_mismatches` (`evals/baseline.py`) compares every field of `BaselineConditions`, `ground_truth_fingerprint` included, and `pre_run_refusals` (`evals/eval_session.py`) and the two recording refusals (`evals/recording.py`) all call it. Any revision of `evals/ground_truth.py` makes the next run not comparable. ADR 020: a label revision re-scores the stored observations under the current labels, and the fingerprint no longer refuses a comparison.
- **A cell a revision adds is compared as if it were observed uncovered.** `classify` (`evals/gate.py`) reads a cell missing from a run as `Observation.UNCOVERED`. A cell the baseline never recorded is then `STABLE_INCORRECT` whatever its label, and a candidate that gets it right reads `IMPROVED`. ADR 020: it has no observation and stays out of the gate until a recording covers it.
- **Agreement between two recordings depends on the labels.** `_disagreements` (`evals/recording.py`) compares `CellState`s. Under a PASS label, a cell observed `fail` in every run of the first recording and `uncovered` in every run of the second is `STABLE_INCORRECT` both times, so the two "agree" although they saw different things. Whether a baseline is confirmed then depends on labels a later revision can change.
- **Metric deltas compare two ground truths after a revision.** `_deltas` (`evals/judging.py`) subtracts `baseline.metrics`, stored at recording time under the labels of that time, from the candidate's metrics under the current labels.
- **The fixture fingerprint is broken by a docstring edit.** `fingerprint_source` hashes the token stream, so a module docstring, a quote style, a trailing comma or a pair of parentheses changes it. ADR 020: it covers only what executes or is sent to the model.
- **Refusals point at the model procedure only, or at nothing.** `_MODEL_CHANGE_PROCEDURE` names the ADR 016 model procedure, and `pre_run_refusals` returns the raw mismatch list with no way forward.

This is an instrument change only. No honeypot (`tests/*_server.py`), no label of `evals/ground_truth.py`, no prompt and no default changes, and each commit says so.

## Approach

Six code changes, all in `evals/`, and one docs pass.

1. **The ground truth fingerprint becomes provenance.** It stays in `BaselineConditions` and in the file, and `condition_mismatches` stops comparing it. Every caller of `condition_mismatches` inherits the change. `baseline_integrity` keeps its current logic: it checks the cell set of each run against the ground truth only when the fingerprints match, which is already the only case where the cell sets must be equal. Two tests pin that it tolerates a cell removed or added by a revision.
2. **A cell the baseline did not record is out of the comparison.** `classify` classifies only the cells every run holds. `compare` gives a cell with no baseline state a new outcome, `CellOutcome.NOT_RECORDED`. It is neither a flip nor an improvement, never replayed, never gated, and it shows in the report's cell table like any outcome other than `unchanged`.
3. **Agreement between recordings is judged on observations.** `_disagreements` no longer calls `classify`: a cell whose observation is the same in every run of the first recording disagrees when any run of the second observes something else. No ground truth is involved, so `Recording.ground_truth` has no reader left and is removed.
4. **The baseline is re-scored under the current labels.** A new function `rescore(baseline, ground_truth)` in `evals/baseline.py` returns the current labels restricted to the cells the baseline recorded, and the baseline's metrics recomputed from its observations under those labels. `_deltas` scores both sides of every delta on that restricted ground truth, so a delta compares one ground truth with itself. The metrics the report shows for the candidate are unchanged: only the delta computation uses the restricted set.
5. **The fixture fingerprint hashes the AST.** `fingerprint_source` parses the source, drops the module docstring and hashes `ast.dump` of the rest. Comments, blank lines, formatting and the module docstring leave it unchanged; tool names, tool docstrings, signatures (hence schemas) and code change it. The chain settings are already separate fields of `FixtureConditions`.
6. **Refusals point at the ADR 020 procedures.** One function builds the refusal for differing conditions, used by the pre-run check and both recording refusals, and names the reset procedure.

Why `NOT_RECORDED` and not dropping the cell from `compare`'s result: the report then names the cells that a revision added and that the gate does not yet protect, where silence would hide them. `Replayer.settle_flips` indexes `cells[cell]` for every cell of a honeypot's ground truth, and a complete result keeps that valid.

Why both sides of a delta are restricted, and not only the baseline re-scored: a cell a revision adds with a FAIL label has an observation on the candidate side only. Scored over the full ground truth, the candidate's recall would count it and the baseline's could not, which is again a comparison across two ground truths. Once a recording covers the cell, the restricted set equals the full one and the delta is the plain difference.

## Files to modify

### `evals/baseline.py`

`condition_mismatches`:

```python
def condition_mismatches(recorded: BaselineConditions, candidate: BaselineConditions) -> list[str]:
    # The ground truth fingerprint is provenance: a label revision re-scores (ADR 020).
    excluded = {"fixtures", "ground_truth_fingerprint"}
    mismatches = _field_mismatches(
        "", recorded.model_dump(exclude=excluded), candidate.model_dump(exclude=excluded)
    )
    ...  # fixtures loop unchanged
```

`fingerprint_source`, replacing the tokenizer version (the `io` and `tokenize` imports go, `ast` comes in):

```python
def fingerprint_source(source: str) -> str:
    """Hash of what executes or reaches the model: comments, formatting and the module
    docstring are left out (ADR 020). `ast.dump` output belongs to the Python minor version.
    """
    module = ast.parse(source)
    if ast.get_docstring(module, clean=False) is not None:
        module.body = module.body[1:]
    return hashlib.sha256(ast.dump(module).encode()).hexdigest()
```

`ast.dump` without `include_attributes` carries no line or column, so formatting cannot reach it. Function and class docstrings stay in the dump: a tool's docstring is its description, sent to the model.

`rescore`, below `condition_mismatches` and its `_field_mismatches` helper (newspaper order: it is called from `evals/judging.py`, and uses `Baseline` defined above). New imports: `dataclass`, `EvalVerdict` (`mcp_auditor.domain.models`), and `VerdictMap`, `label_scores` from `evals.metrics`, which `evals/baseline.py` already imports from without a cycle:

```python
@dataclass(frozen=True)
class RescoredBaseline:
    ground_truth: GroundTruth
    metrics: EvalMetrics


def rescore(baseline: Baseline, ground_truth: GroundTruth) -> RescoredBaseline:
    """The baseline under the current labels (ADR 020).

    An observation is what one run saw on a cell, pass, fail or uncovered, and carries no
    label, so a label revision re-scores the stored runs instead of resetting the baseline.
    A cell the revision added has no observation: it stays out of the comparison until a
    recording covers it, and `ground_truth` here holds only the cells the baseline recorded.
    Whether a baseline is confirmed depends on its observations alone, so a confirmed
    baseline stays confirmed under a revision. Consistency and distribution coverage are
    kept as recorded: no delta reads the first, and the second does not depend on the labels.
    """
    runs = baseline.observation_runs()
    recorded = {cell: verdict for cell, verdict in ground_truth.items() if cell in runs[0]}
    verdict_maps: list[VerdictMap] = [
        {cell: None if seen == Observation.UNCOVERED else EvalVerdict(seen.value) for cell, seen in run.items()}
        for run in runs
    ]
    return RescoredBaseline(
        ground_truth=recorded,
        metrics=baseline.metrics.model_copy(update=label_scores(verdict_maps, recorded)),
    )
```

Consistency is not recomputed: `metric_deltas` iterates `FLOORS` (recall, precision, distribution coverage), so a re-scored consistency would have no reader.

`runs[0]` is safe: `baseline_integrity` refuses a baseline with no run before any comparison, and every run of a recording holds the same cells (all come from `observe` against one ground truth). `RescoredBaseline` is a dataclass since it holds a `GroundTruth` keyed by tuples, which the pydantic models of this module do not need to serialize.

### `evals/metrics.py`

```python
def label_scores(verdict_maps: list[VerdictMap], ground_truth: GroundTruth) -> dict[str, float]:
    """Recall and precision averaged per run, as the report computes them."""
    runs = len(verdict_maps)
    return {
        "recall": sum(compute_recall(verdicts, ground_truth) for verdicts in verdict_maps) / runs,
        "precision": sum(compute_precision(verdicts, ground_truth) for verdicts in verdict_maps) / runs,
    }
```

Placed after `compute_precision`. Two callers: `rescore` and `_deltas`. `RunsOutcome.metrics` keeps averaging `RunDetail.recall`/`precision`, which are the same per-run values, and is not refactored here.

### `evals/gate.py`

- `CellOutcome` gains `NOT_RECORDED = "not_recorded"`.
- `classify` keeps only cells every run holds:

```python
def classify(
    runs: list[dict[Cell, Observation]], ground_truth: GroundTruth
) -> dict[Cell, CellState]:
    """Cells a run did not record get no state (ADR 020)."""
    return {
        cell: _state_of([run[cell] for run in runs], expected)
        for cell, expected in ground_truth.items()
        if all(cell in run for run in runs)
    }
```

- `compare`: `baseline_states.get(cell)` is `None` for a cell the baseline did not record, which gives `CellComparison(outcome=CellOutcome.NOT_RECORDED)`. The candidate side always holds every cell (`observe` covers the whole ground truth), so `candidate_states[cell]` stays a plain index. Shape:

```python
    return {
        cell: _compare_cell(baseline_states[cell], candidate_states[cell] == CellState.STABLE_CORRECT, _flip_cause(cell, candidate_runs))
        if cell in baseline_states
        else CellComparison(outcome=CellOutcome.NOT_RECORDED)
        for cell in ground_truth
    }
```

Whether this reads better as a small `_compare_recorded` helper is the implementer's call under the 20-line rule.

`gated_set_changes` (`evals/recording.py`) calls `classify` on an old baseline: a cell it did not record now has no state instead of `STABLE_INCORRECT`, and neither enters the gated set, so its output does not change.

### `evals/recording.py`

- `_disagreements` on observations:

```python
def _disagreements(existing: Baseline, recording: Recording) -> list[str]:
    first = existing.observation_runs()
    return sorted(
        cell_key(cell)
        for cell, seen in first[0].items()
        if all(run[cell] == seen for run in first)
        and any(run.get(cell) != seen for run in recording.runs)
    )
```

- `Recording.ground_truth` is removed, and its docstring with it. `classify` and `CellState` stay imported for `_gated_set`. `run_evals.py` stops passing `ground_truth=`.
- `_MODEL_CHANGE_PROCEDURE` is replaced by `_RESET_PROCEDURE`, and one public function builds the refusal for differing conditions:

```python
_RESET_PROCEDURE = (
    "reset the baseline under ADR 020: delete its file in the commit that makes the change, "
    "with no other change in that commit, and record twice at that commit (exploratory, then "
    "confirmed). If the gate was red, name the cells whose flip fired it at the last run, in "
    "the labeling log entry or, for a model, in the commit message: each must come out stable "
    "and correct in the confirmed baseline, or the change is reverted. Runs and budget change "
    "only from a green gate. For a model, also run both models and record the delta while "
    "the old one answers (ADR 016)"
)


def condition_refusals(baseline: Baseline, candidate: BaselineConditions) -> list[str]:
    mismatches = condition_mismatches(baseline.conditions, candidate)
    if not mismatches:
        return []
    return [
        f"conditions differ from the {baseline.status} baseline ({'; '.join(mismatches)}): "
        f"to run at other conditions without changing the baseline, pass --ungated. To change "
        f"the baseline's conditions, {_RESET_PROCEDURE}"
    ]
```

The `--ungated` clause matters at the pre-run check: a local run at another `--budget` or model hits this refusal far more often than a real change of conditions does, and a message naming only the reset would steer it toward deleting the baseline. It reads the same under `--record-baseline`, where `--ungated` records nothing.

`_other_conditions` is deleted, `_refusals` calls `condition_refusals(existing, recording.conditions)` for an exploratory baseline, and `_confirmed_refusals` calls it in place of its own mismatch block. A label revision no longer reaches this path, so the message has no clause for it.

- `exploratory_commit_refusal` gains a docstring:

```python
    """A baseline is confirmed at the commit of its first recording. A change that lands while
    it is exploratory, a label revision included, resets it: the file is deleted and recorded
    again twice at the new commit.
    """
```

The refusal text itself already says "delete it in a commit of its own".

### `evals/eval_session.py`

`pre_run_refusals` calls `condition_refusals(session.baseline, session.conditions)` in place of the raw `condition_mismatches` list. The `condition_mismatches` import goes, `condition_refusals` is imported from `evals.recording` next to `exploratory_commit_refusal`.

### `evals/judging.py`

```python
def _deltas(
    baseline: Baseline, outcome: RunsOutcome, metrics: EvalMetrics
) -> dict[str, MetricDelta]:
    rescored = rescore(baseline, MERGED_GROUND_TRUTH)
    candidate = metrics.model_copy(update=label_scores(outcome.verdict_maps, rescored.ground_truth))
    resolutions = metric_resolutions(outcome.verdict_maps, rescored.ground_truth, TOOL_COUNT)
    return metric_deltas(rescored.metrics, candidate, resolutions)
```

`TOOL_COUNT` is untouched: the distribution coverage resolution counts tools, which a label revision does not change.

### `evals/run_evals.py`

Drop `ground_truth=MERGED_GROUND_TRUTH` from the `Recording(...)` call.

### Tests

Given/then files already exist for these modules (`tests/unit/support/test_eval_*_given.py`). New builders go there when they abstract something, inline otherwise.

### Living docs

- `CONTRIBUTING.md`, section "Recording an e2e baseline" (l. 65-73): a paragraph on how the baseline changes, after the procedure paragraph. A label revision re-scores the stored runs under the current labels and needs no new recording, and a cell it adds shows as `not_recorded` and stays out of the gate until a recording covers it. A change to a honeypot's code, a tool's name, docstring or signature, a chain setting, the scoring code, the model, `--runs` or `--budget` is a reset: the file is deleted in the commit that makes the change, alone in its commit, and recorded twice at that commit. Under a red gate, the labeling log entry (the commit message for a model) names the cells that fired it at the last run, and each must come out stable and correct in the confirmed baseline, or the change is reverted. Runs and budget change only from a green gate. Comments, formatting and a module docstring in a honeypot change nothing. Pointer to ADR 020. The first paragraph's link to ADR 016 gains ADR 020.
- `CHANGELOG.md` `[Unreleased]`, the e2e gate bullet (l. 24): "A run whose conditions, ground truth or honeypot sources differ from the baseline's is reported not comparable" becomes "A run whose conditions or honeypot sources differ ...", followed by: a ground truth revision re-scores the baseline's stored runs under the current labels, and a cell it adds stays out of the comparison until a recording covers it; comments, formatting and module docstrings of a honeypot are not part of its source fingerprint. "See ADR 016" becomes "See ADR 016 and ADR 020". The gate was never released, so this edits the unreleased bullet rather than adding a new one.
- `docs/labeling-log.md`, header paragraph: the file holds the rubric and one entry per instrument change, labels, fixtures or scoring code, whatever the state of the gate (ADR 020). An entry answers the four questions of ADR 016, and when the gate is red it names the cells whose flip fired it at the last run before the change. The rest of the paragraph (what git does not carry) stays. The two existing entries are not edited.
- `CLAUDE.md`, "When an eval number comes back red": the section names ADR 016 only and says re-recording under red is forbidden outright, which ADR 020 qualifies. Add, after the "Never re-record" bullet, two bullets:
  - **A reset is not a re-recording.** A change to a fixture, the scoring code, the model, runs or budget deletes the baseline in its own commit and records it again twice. Under a red gate it names the cells that fired it, and each must come out stable and correct in the confirmed baseline, or the change is reverted. Runs and budget change only from a green gate. A label revision re-scores the stored runs and needs no reset. One such change per commit. See `docs/adr/020-honeypot-baseline-changes.md`.
  - **Every instrument change has a labeling log entry**, labels, fixtures or scoring code, whatever the state of the gate.

  The header line "Governed by `docs/adr/016-eval-gate-governance.md`" becomes "Governed by ADR 016, amended by ADR 020 for the honeypot suite".
- `README.md` l. 153: after the sentence on ADR 016, "[ADR 020](docs/adr/020-honeypot-baseline-changes.md) governs how that baseline changes." Nothing else there is made false by this plan.

Not touched: `plans/` (other than this file) and `docs/adr/`.

## What stays unchanged

- The honeypot servers (`tests/honeypot_server.py`, `tests/subtle_server.py`, `tests/chain_honeypot_server.py`), `evals/ground_truth.py`, every prompt, `src/` entirely, and every default.
- The metrics a run reports: `RunsOutcome.metrics`, `compute_recall`, `compute_precision`, `compute_consistency`, `aggregate_verdicts`, `observe`. Only the delta computation changes.
- The baseline file format: `BaselineConditions` keeps `ground_truth_fingerprint`, `FixtureConditions` keeps its fields. No file exists, so no migration.
- The fixture condition is still a refusal: a changed honeypot source, chain setting, or an added or removed honeypot makes the run not comparable, and its refusal now names the reset procedure (ADR 020: a new honeypot is a fixture change).
- `ReplayRule`, the replay mechanics, `judge_gate`, floors, `metric_resolutions` itself, the CI workflows, the recording procedure's other refusals (dirty tree, CI conditions, drift, exploratory commit).

Out of scope, decided before this plan: the code that reads a declared deliberate regression (ADR 020 defers it, so such a regression is blocked until then); any automatic check of the rules ADR 020 leaves to review (the ban on deleting the file outside the permitted cases, a green gate before changing runs or budget, the check of the red cells after a reset, one change per commit); one baseline file per honeypot (rejected by the ADR); fingerprints of the locked MCP SDK and pydantic versions and of the scoring code (limits the ADR names); anything about prompts, the generator or the default model.

## Decision taken in this plan: no labeling log entry for this change

ADR 020 asks for a labeling log entry for every instrument change, scoring code included, and its Consequences say its rules apply from the first recording. No baseline exists, and none of these changes alters how a run's verdicts become observations or metrics: a run reports the same figures before and after. What changes is how a future baseline is compared and fingerprinted. So no entry is written. If "scoring code" is read as covering the comparison code, one entry answering the four questions is the remedy, and it changes no code in this plan.

## Flagged, not treated

- **Cell keys do not carry the honeypot's name.** `cell_key` is `tool/category`, and `MERGED_GROUND_TRUTH` (`evals/honeypots.py`) merges the three ground truths into one dict, so a future honeypot that reuses a tool name would overwrite cells silently, in the ground truth and in the baseline. A guard costs one unit test, asserting that no tool name appears in two honeypots' ground truths. This plan adds that test with the refusal commit, since a new honeypot is one of the changes ADR 020 governs. It is a test only, no production code.
- **`ast.dump` output depends on the Python minor version** (3.13 already changed its default rendering of empty fields). CI and local runs both use 3.13 (`uv python install 3.13` in every workflow, `requires-python >= 3.13`, and a `.python-version` at `3.13`, committed with this plan so a recreated local venv cannot pick a newer interpreter). A move to 3.14 may change every fixture fingerprint at once, which reads as a fixture change and forces a reset, never a silent pass. The Python version is not a recorded condition, and adding it is not in scope.
- **A cell present in some runs of a baseline and not others** can only come from a hand-edited file. `classify` then leaves it unclassified, so it reads `not_recorded`. `baseline_integrity` does not check that runs share one cell set when the ground truth fingerprint differs, and this plan does not add that check.

## Edge cases

| Situation | Expected behavior |
|---|---|
| Label revision flips one verdict, same cells | Fingerprint differs, no refusal. `baseline_integrity` skips the cell-set check. Cells re-classified under the new label. Deltas on the same ground truth both sides. |
| Revision removes a cell | Baseline runs hold an extra key: no integrity problem, `compare` iterates the current ground truth, the cell disappears from the comparison and from both sides of the deltas. |
| Revision adds a cell | Baseline runs lack it: no integrity problem, `compare` gives `NOT_RECORDED`, it is never replayed nor gated, and both sides of the deltas leave it out. |
| Revision adds a FAIL cell the candidate detects | Recall delta computed without it on both sides: no false improvement. |
| First recording `fail`×3, second `uncovered`×3, label PASS | Disagreement (today: agreement). Baseline stays exploratory. |
| First recording `fail`/`uncovered`/`fail` | Not stable in the first recording: no disagreement whatever the second sees (unchanged). |
| Revision lands while baseline is exploratory | The next recording is at a new commit, `exploratory_commit_refusal` refuses it: delete and record twice (reset). |
| Honeypot module docstring edited, or `ruff format` run on a honeypot | Source fingerprint unchanged, run comparable. |
| Tool docstring, tool name, argument type or body changed | Source fingerprint changed, refusal naming the honeypot and the reset procedure. |
| Honeypot added | `fixtures.<name>: baseline None, candidate ...` mismatch, refusal with the reset procedure. |
| Model or budget differs from the baseline | Refusal before any LLM call, naming the mismatch and the reset procedure. |

## Test scenarios

Test-first: each test below is written and run red before the code that makes it pass, except the ones marked "pins", which describe behavior that already holds and are run green to confirm.

`tests/unit/test_eval_baseline.py`:

- `test_a_differing_ground_truth_fingerprint_is_no_mismatch`: conditions identical but `ground_truth_fingerprint`, `condition_mismatches` returns `[]`. Red today.
- `test_a_baseline_holding_a_cell_the_ground_truth_removed_has_no_integrity_problem`: baseline recorded under a ground truth with an extra cell, checked against one without it. Pins.
- The existing `test_a_baseline_of_another_ground_truth_gets_no_cell_set_line` already pins the added-cell direction; rename it `test_a_baseline_missing_a_cell_the_ground_truth_added_has_no_integrity_problem` only if the name reads better.
- Fingerprint: `test_source_fingerprint_ignores_the_module_docstring` (edited module docstring), `test_source_fingerprint_ignores_quotes_trailing_commas_and_parentheses` (a reformatted variant of `SERVER_SOURCE`: single quotes, a trailing comma in the argument list, a wrapped `return (...)`), both red today. `test_source_fingerprint_changes_with_a_tool_docstring` (pins: the token version already sees it) and `test_source_fingerprint_changes_with_a_changed_string_literal` (exists, pins). Add `test_source_fingerprint_changes_with_a_changed_argument_type` (`user_id: str` to `user_id: int`), pins. `SERVER_SOURCE` in the given file gains a module docstring so the docstring test has one to edit.
- `test_no_honeypot_passes_instructions_to_its_server`: for each `HONEYPOTS` source, `ast.walk` finds no `keyword` named `instructions`. Pins that the module docstring cannot reach the model. Green today.
- `test_no_tool_name_appears_in_two_honeypots`: the tool names of the three ground truths are disjoint. Green today.
- Rescoring: `test_rescoring_under_a_revised_label_recomputes_recall_and_precision` (baseline observing both cells correctly under the original labels, re-scored under a ground truth where `SAFE_CELL` is FAIL: recall 0.5, precision 1.0), `test_rescoring_leaves_out_a_cell_the_baseline_did_not_record` (ground truth with an extra FAIL cell: `rescored.ground_truth` lacks it and recall is computed without it), `test_rescoring_keeps_the_recorded_distribution_coverage`. All red (no `rescore`).
- Recording: `test_a_second_recording_seeing_uncovered_where_the_first_saw_fail_disagrees` (first `fail`×3, second `uncovered`×3 on `SAFE_CELL`, whose label is PASS: `disagreements == [cell_key(SAFE_CELL)]`, status exploratory). Red today. Existing agreement tests stay.
- Refusal wording: `test_a_second_recording_at_other_conditions_is_refused` and `test_recording_over_a_confirmed_baseline_at_other_conditions_points_at_the_model_change` are rewritten to assert the reset procedure (`"reset the baseline under ADR 020"` in a reason naming the status of the baseline), and the second is renamed `..._points_at_the_reset_procedure`. Red after rewriting.
- `given.a_recording` drops `ground_truth=`.

`tests/unit/test_eval_gate.py`:

- `test_classify_leaves_out_a_cell_a_run_did_not_record`: runs without `SAFE_CELL`, ground truth with it: no state for it. Red.
- `test_compare_marks_a_cell_the_baseline_did_not_record`: baseline runs without `SAFE_CELL`, candidate correct on it: `NOT_RECORDED`, not `IMPROVED`. Red.
- The existing `test_classify_reads_uncovered_in_every_run_as_stable_incorrect` stays: an explicit `uncovered` observation is still an observation.

`tests/unit/test_eval_metrics.py`:

- `test_label_scores_average_recall_and_precision_per_run`: two verdict maps with known per-run recall and precision. Red.

`tests/unit/test_eval_judging.py` (the given file gains a baseline built from `a_baseline_all_correct` with one FAIL cell removed from every run):

- `test_a_cell_the_baseline_did_not_record_is_neither_gated_nor_replayed`: confirmed baseline without `FLIPPED_CELL`, candidate runs missing it (`runs_missing_the_flipped_cell`): its outcome is `NOT_RECORDED`, no `regression on` reason, no audit ran. Red (today `UNCHANGED`). Do not assert a green verdict: the minimal audit reports of `an_outcome` cover no category, so distribution coverage breaches its floor and the paired verdict is red whatever the cells say.
- `test_deltas_leave_out_a_cell_the_baseline_did_not_record`: same baseline, candidate runs missing `FLIPPED_CELL` (`runs_missing_the_flipped_cell`): recall delta `0.0`. Red today. A candidate correct everywhere would not do: its recall is `1.0` over the full ground truth and over the restricted one alike, so the test would pass with the baseline re-scored alone and pin nothing about restricting the candidate side.

`tests/unit/test_eval_session.py`:

- `test_a_baseline_at_other_conditions_names_the_mismatch` is extended to assert the reset procedure in the reason. Red after extending.
- `test_a_baseline_of_another_ground_truth_is_not_refused`: session whose baseline carries another ground truth fingerprint, `pre_run_refusals` is `[]`. Red today.

## Verification

```bash
uv run pytest tests/unit
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

And by hand, once: compute `fingerprint_source` on each of the three honeypot files, then on a throwaway copy outside the repo with quotes swapped and a trailing comma added, and check the two agree. No eval run, no LLM call, no baseline recorded.

## Commit messages

Each commit body states: "Instrument change only: no honeypot, label, prompt or default changes." Suggested split, one concern each:

1. `feat(evals): fingerprint honeypot sources by AST, without the module docstring`
2. `feat(evals): re-score the honeypot baseline under the current labels` (ground truth fingerprint as provenance, `NOT_RECORDED`, `rescore`, `label_scores`, deltas)
3. `fix(evals): judge agreement between two recordings on observations`
4. `feat(evals): point condition refusals at the ADR 020 reset procedure` (plus the `exploratory_commit_refusal` docstring and the two guard tests)
5. `docs: document how the honeypot baseline changes` (CONTRIBUTING, CHANGELOG, labeling log header, CLAUDE.md, README)

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, written on 2026-09-25 and read by the implementation-phase fact check. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `ast.dump(module)` carries no line or column numbers, since `include_attributes` defaults to `False` (verified against docs.python.org/3.13/library/ast.html)
- SETTLED: `ast.dump` output depends on the Python minor version: 3.13 added `show_empty`, default `False`, which omits optional empty lists (verified against docs.python.org/3.13/library/ast.html)
- SETTLED: `ast.get_docstring(module, clean=False)` accepts a `Module` node and returns `None` when it has no docstring, `clean=False` skipping `inspect.cleandoc` (verified against docs.python.org/3.13/library/ast.html)
- SETTLED: `uv python install 3.13` runs in all five workflows under `.github/workflows/`, and `requires-python = ">=3.13"` (verified against the repository files)
- SETTLED by `.python-version` (3.13), committed with this plan. Was OPEN: local runs use Python 3.13. The current `.venv` is 3.13.12, but no `.python-version` pins it, uv 3.14.3 is installed on this machine, and uv's docs say it prefers newer managed versions, so a recreated venv may pick 3.14 and fingerprint differently from CI

## Implementation steps

Every step: test-first (write the tests, run them red, except those the plan marks "pins", which run green), then code, then the full verification. Verification commands for every step, from `CLAUDE.md`:

```bash
uv run pytest tests/unit
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

Expected: all green, pyright strict with 0 errors. Every commit body states "Instrument change only: no honeypot, label, prompt or default changes." No step touches `tests/*_server.py`, `evals/ground_truth.py`, `src/`, `docs/adr/` or another plan.

### Step 1: fingerprint honeypot sources by AST, without the module docstring

- **Files**: `tests/unit/support/test_eval_baseline_given.py`, `tests/unit/test_eval_baseline.py`, `evals/baseline.py`
- **Do**:
  1. Given file: `SERVER_SOURCE` gains a module docstring (first statement) so a test can edit it.
  2. Tests in `test_eval_baseline.py`, next to the existing `test_source_fingerprint_*` tests (see "Test").
  3. `evals/baseline.py`: replace `fingerprint_source` with the `ast` version of section "Files to modify / `evals/baseline.py`" (parse, drop the module docstring found with `ast.get_docstring(module, clean=False)`, `sha256(ast.dump(module))`). Remove the `io` and `tokenize` imports, add `ast`. Keep the docstring given in the plan.
  4. By hand, once (no file committed): compute `fingerprint_source` on each of the three honeypot files, then on a throwaway copy in the scratchpad with quotes swapped and a trailing comma added, and check the two agree.
- **Test**:
  - `test_source_fingerprint_ignores_the_module_docstring`: `SERVER_SOURCE` vs the same with its module docstring edited, equal fingerprints. Red.
  - `test_source_fingerprint_ignores_quotes_trailing_commas_and_parentheses`: reformatted variant (single quotes, trailing comma in an argument list, a wrapped `return (...)`), equal. Red.
  - `test_source_fingerprint_changes_with_a_tool_docstring`: pins.
  - `test_source_fingerprint_changes_with_a_changed_argument_type` (`user_id: str` to `user_id: int`): pins.
  - Existing `test_source_fingerprint_ignores_an_added_comment_line`, `..._ignores_blank_lines`, `..._changes_with_a_changed_string_literal` stay green.
  - `test_no_honeypot_passes_instructions_to_its_server`: for each source of `evals.honeypots.HONEYPOTS` (read the file the honeypot points at), `ast.walk` finds no `ast.keyword` whose `arg == "instructions"`. Pins, green today.
- **Verify**: the commands above. Commit: `feat(evals): fingerprint honeypot sources by AST, without the module docstring`.

### Step 2: the ground truth fingerprint becomes provenance, a cell the baseline did not record is out of the gate

- **Files**: `tests/unit/test_eval_gate.py`, `tests/unit/test_eval_baseline.py`, `tests/unit/test_eval_session.py`, `tests/unit/support/test_eval_judging_given.py`, `tests/unit/test_eval_judging.py`, `evals/gate.py`, `evals/baseline.py`
- **Do**:
  1. Tests first (see "Test"). In `test_eval_judging_given.py`, add a builder returning a baseline like `a_baseline_all_correct(status)` with `FLIPPED_CELL` removed from every run (e.g. `a_baseline_without_the_flipped_cell(status)`). The session test builds its baseline from `given.a_baseline_at_ci_conditions()` with `conditions.ground_truth_fingerprint` replaced (`model_copy`), inline unless it needs more than a line or two.
  2. `evals/baseline.py`, `condition_mismatches`: exclude `ground_truth_fingerprint` along with `fixtures` from the field comparison, with the one-line comment of the plan. `baseline_integrity` is not changed.
  3. `evals/gate.py`: `CellOutcome.NOT_RECORDED = "not_recorded"`. `classify` keeps only cells every run holds (plan snippet). `compare` returns `CellComparison(outcome=CellOutcome.NOT_RECORDED)` for a cell absent from the baseline states, `_compare_cell(...)` otherwise, still iterating the whole ground truth (a `_compare_recorded` helper if the 20-line rule asks for it). Check that the report's cell table (the code that lists outcomes other than `unchanged`) shows `not_recorded` with no extra change, and that `ReplayRule`/`Replayer.settle_flips` never selects a `NOT_RECORDED` cell.
- **Test**:
  - `test_eval_baseline.py`: `test_a_differing_ground_truth_fingerprint_is_no_mismatch` (conditions identical but that field: `[]`). Red. `test_a_baseline_holding_a_cell_the_ground_truth_removed_has_no_integrity_problem` (baseline recorded under a ground truth with an extra cell, checked against one without it: no problem). Pins. Rename the existing `test_a_baseline_of_another_ground_truth_gets_no_cell_set_line` to `test_a_baseline_missing_a_cell_the_ground_truth_added_has_no_integrity_problem` only if it reads better.
  - `test_eval_gate.py`: `test_classify_leaves_out_a_cell_a_run_did_not_record` (runs without `SAFE_CELL`, ground truth with it: no state for it). Red. `test_compare_marks_a_cell_the_baseline_did_not_record` (baseline runs without `SAFE_CELL`, candidate correct on it: `NOT_RECORDED`, not `IMPROVED`). Red. The existing `test_classify_reads_uncovered_in_every_run_as_stable_incorrect` stays.
  - `test_eval_session.py`: `test_a_baseline_of_another_ground_truth_is_not_refused` (`pre_run_refusals == []`). Red.
  - `test_eval_judging.py`: `test_a_cell_the_baseline_did_not_record_is_neither_gated_nor_replayed` (confirmed baseline without `FLIPPED_CELL`, candidate `runs_missing_the_flipped_cell()`: outcome `NOT_RECORDED`, no reason containing `regression on`, `no_audit_ran`). Red (today `UNCHANGED`). Do not assert a green verdict: distribution coverage breaches its floor on these minimal reports.
- **Verify**: the commands above. Commit: `feat(evals): keep cells the honeypot baseline did not record out of the gate`, body naming the ground truth fingerprint as provenance (ADR 020).

### Step 3: re-score the baseline under the current labels for the deltas

- **Files**: `tests/unit/test_eval_metrics.py`, `tests/unit/test_eval_baseline.py`, `tests/unit/test_eval_judging.py`, `evals/metrics.py`, `evals/baseline.py`, `evals/judging.py`
- **Do**:
  1. Tests first (see "Test"). The judging test reuses the builder added in Step 2.
  2. `evals/metrics.py`: `label_scores(verdict_maps, ground_truth) -> dict[str, float]` right after `compute_precision`, as in the plan. `RunsOutcome.metrics` is not refactored.
  3. `evals/baseline.py`: `RescoredBaseline` (frozen dataclass: `ground_truth: GroundTruth`, `metrics: EvalMetrics`) and `rescore(baseline, ground_truth)` below `condition_mismatches` and its helper, with the plan's docstring. It restricts the ground truth to the cells of `observation_runs()[0]`, maps each observation to `None` (uncovered) or `EvalVerdict(seen.value)`, and returns `baseline.metrics.model_copy(update=label_scores(...))`. Consistency and distribution coverage stay as recorded. New imports: `dataclass`, `EvalVerdict`, `VerdictMap`, `label_scores`. Confirm no import cycle.
  4. `evals/judging.py`: `_deltas` as in the plan: `rescore(baseline, MERGED_GROUND_TRUTH)`, candidate metrics re-scored with `label_scores(outcome.verdict_maps, rescored.ground_truth)`, `metric_resolutions` on the restricted ground truth with `TOOL_COUNT` unchanged. The metrics the report shows for the candidate stay the unrestricted ones.
- **Test**:
  - `test_eval_metrics.py`: `test_label_scores_average_recall_and_precision_per_run` (two verdict maps with known per-run recall and precision, e.g. one run perfect and one missing the only FAIL cell: recall 0.5). Red.
  - `test_eval_baseline.py`: `test_rescoring_under_a_revised_label_recomputes_recall_and_precision` (baseline correct on both cells under the original labels, re-scored under a ground truth where `SAFE_CELL` is FAIL: recall 0.5, precision 1.0). `test_rescoring_leaves_out_a_cell_the_baseline_did_not_record` (extra FAIL cell: absent from `rescored.ground_truth`, recall computed without it). `test_rescoring_keeps_the_recorded_distribution_coverage`. All red.
  - `test_eval_judging.py`: `test_deltas_leave_out_a_cell_the_baseline_did_not_record` (baseline without `FLIPPED_CELL`, candidate `runs_missing_the_flipped_cell()`: recall delta `0.0`). Red. Do not use a candidate correct everywhere (it would not pin the candidate-side restriction).
- **Verify**: the commands above. Commit: `feat(evals): re-score the honeypot baseline under the current labels`.

### Step 4: judge agreement on observations, point condition refusals at ADR 020

- **Files**: `tests/unit/support/test_eval_baseline_given.py`, `tests/unit/test_eval_baseline.py`, `tests/unit/test_eval_session.py`, `evals/recording.py`, `evals/eval_session.py`, `evals/run_evals.py`
- **Do**:
  1. Tests first (see "Test"). `given.a_recording` drops `ground_truth=`.
  2. `evals/recording.py`: `_disagreements` on observations (plan snippet: a cell whose observation is the same in every run of the first recording disagrees when any run of the second observes something else, `run.get(cell)`). Remove `Recording.ground_truth` and its docstring. `classify` and `CellState` stay imported for `_gated_set`.
  3. `evals/recording.py`: replace `_MODEL_CHANGE_PROCEDURE` with `_RESET_PROCEDURE` (plan text verbatim) and add the public `condition_refusals(baseline, candidate) -> list[str]` (plan snippet, with the `--ungated` clause). Delete `_other_conditions`. `_refusals` calls `condition_refusals(existing, recording.conditions)` for an exploratory baseline, `_confirmed_refusals` calls it in place of its own mismatch block. Add the plan's docstring to `exploratory_commit_refusal`.
  4. `evals/eval_session.py`: `pre_run_refusals` uses `condition_refusals(session.baseline, session.conditions)`, imported from `evals.recording` beside `exploratory_commit_refusal`. Drop the `condition_mismatches` import.
  5. `evals/run_evals.py`: drop `ground_truth=MERGED_GROUND_TRUTH` from the `Recording(...)` call (and the import if it has no other reader).
- **Test**:
  - `test_eval_baseline.py`: `test_a_second_recording_seeing_uncovered_where_the_first_saw_fail_disagrees` (first `fail`x3, second `uncovered`x3 on `SAFE_CELL`, label PASS: `disagreements == [cell_key(SAFE_CELL)]`, status exploratory). Red. Existing agreement tests stay green.
  - `test_eval_baseline.py`: rewrite `test_a_second_recording_at_other_conditions_is_refused` and `test_recording_over_a_confirmed_baseline_at_other_conditions_points_at_the_model_change` (renamed `..._points_at_the_reset_procedure`) to assert a reason naming the baseline's status and containing `"reset the baseline under ADR 020"`. Red after rewriting.
  - `test_eval_baseline.py`: `test_no_tool_name_appears_in_two_honeypots` (tool names of the ground truths of `HONEYPOTS` are pairwise disjoint). Green today.
  - `test_eval_session.py`: extend `test_a_baseline_at_other_conditions_names_the_mismatch` to assert the reset procedure in the reason. Red after extending.
- **Verify**: the commands above. Commit: `feat(evals): judge recordings on observations and point condition refusals at ADR 020`, its body noting that agreement between recordings no longer depends on the labels (a fix) and that the refusals name the reset procedure.

### Step 5: document how the honeypot baseline changes

- **Files**: `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/labeling-log.md`, `CLAUDE.md`, `README.md`
- **Do**: apply section "Living docs" of this plan, text by text:
  - `CONTRIBUTING.md`, "Recording an e2e baseline": the first paragraph's ADR 016 link gains ADR 020, and a new paragraph after the procedure paragraph on how the baseline changes (label revision re-scores, `not_recorded` cells, what is a reset and its procedure, the red-gate rule, runs and budget only from a green gate, what leaves the fingerprint unchanged, pointer to ADR 020).
  - `CHANGELOG.md` `[Unreleased]`, the existing e2e gate bullet ("The e2e evals gate against a recorded baseline..."): edit it in place as the plan says, no new bullet.
  - `docs/labeling-log.md`: header paragraph only, the two entries untouched.
  - `CLAUDE.md`, "When an eval number comes back red": header line and the two new bullets after "Never re-record".
  - `README.md`: the sentence pointing at ADR 020 after the ADR 016 sentence in the honeypot suite paragraph.
  - Follow the user's writing rules: no em dashes, avoid semicolons.
- **Test**: none (docs only). Check every claim against the code of Steps 1-4 (for instance, the outcome string is `not_recorded`, the refusal text says "reset the baseline under ADR 020").
- **Verify**: `uv run pytest tests/unit` still green, `git diff --stat` touches only the five files. Commit: `docs: document how the honeypot baseline changes`.
