# Implement ADR 022: fault injection on the honeypot gate, the recall floor, and the recording condition

## Context

[ADR 022](../docs/adr/022-honeypot-recall-floor.md) (Accepted, `0724bcc`) decides three things for the honeypot gate:

1. The recall floor is one planted flaw found per run, on average over the runs: 1 divided by the number of FAIL cells of the ground truth (1/8 today), computed from the ground truth.
2. The precision and distribution coverage floors stay at 0.50.
3. A baseline recording is refused when no planted FAIL cell, or no PASS cell, comes out stable and correct. The same condition holds when a label revision re-scores a baseline (ADR 020): a baseline left with no stable and correct cell on one side is not comparable until it is recorded again.

ADR 016 also owes a proof it names and never ran: "The proof is fault injection, named here and still to run". The gate is claimed to catch a collapse (a judge that passes or fails everything, verdicts that vanish, a generator that drops a category) and nothing shows it does. This plan runs that proof first, on the current floors, before changing anything, then makes the three changes of ADR 022, each alone in its commit (ADR 020, "One change at a time").

The runs of the recording refused on 2026-09-27 at `519168f` (3 runs on `gpt-6-luna` at `none`, recall 0.46, precision 1.00) survive only in `output/eval_report.json`, which is gitignored and overwritten by the next eval run. They become a committed fixture, the baseline the fault injection compares against.

## Approach

Six commits, in this order.

1. **The fixture and the unit-level fault injection, on the current gate.** The refused recording's observations become `evals/fixtures/fault_injection_baseline.json`. New unit tests feed the gate functions faulted candidates built from it, with no LLM and no server, and pin what the current gate does with each fault, floors at 0.50 included.
2. **The fault injection harness, run by hand with the real generator.** `evals/run_fault_injection.py` audits the three honeypots with `gpt-6-luna` and one fault injected, the fault staying active in the replays, and compares against the fixture. Its method note, `evals/fault_injection_method.md`, writes the expected result of every fault on both floor settings before any run. The command is listed in `CLAUDE.md` and `CONTRIBUTING.md`. After this commit, the harness is run once by hand on the current floors and its results are written into the method note.
3. **The recall floor** becomes "total detections over the runs below the number of runs", computed from the ground truth. The unit tests of commit 1 move to their new expectations. Labeling log entry, and the living docs that state the floors.
4. **The recording condition, and the same check after a re-score.** A recording with no stable and correct planted FAIL cell or no stable and correct PASS cell is refused, and a committed baseline that a label revision leaves in that state makes the gate not comparable. The reset procedure text and the living docs that describe recording.
5. **The protected-cells summary**, stored in the baseline, printed by the recording, recomputed at a re-score.
6. **Documentation**: the replay blind spot in the docstring of `evals/gate.py`, and the modes stated in `CONTRIBUTING.md`.

After the plan, the harness is run a second time by hand on the new floors, its results appended to the method note, then the two baseline recordings on `gpt-6-luna` at `none` are made at one commit.

## Commit 1: the fixture and unit-level fault injection

### `evals/fixtures/fault_injection_baseline.json`

A `Baseline` (the model of `evals/baseline.py`) built from the three `RunDetail.verdicts` of the refused recording's report (stored as `{tool: {category: {verdict, case_count}}}`, turned back into a `VerdictMap` first, `"uncovered"` reading as no verdict), copied to `output/eval_report_refused-2026-09-27.json` (gitignored, report timestamp `2026-09-26T23:06:09Z`) so that no eval run overwrites it. Each run's verdicts are turned into observations with `observe` over `MERGED_GROUND_TRUTH`. Its conditions are the ones `candidate_conditions` gives for `gpt-6-luna` at `none`, runs 3, budget 10, at `519168f`. Its status is `confirmed`, so the paired comparison applies to it, its `commit` is `519168f`, its `recorded_at` the report timestamp, its `metrics` the report's, and its `replay_rule` the default. A one-off conversion script is not committed: the fixture is the artifact. The file holds observations only: no payload, no response, no judgment text.

Expected content, checked when the file is built (the detections per run of the 8 FAIL cells): `delete_record × input_validation` 3, `execute_query × info_leakage` 3, `get_user × error_handling` 3, `execute_query × injection` 1, `project_manager × info_leakage` 1, `get_user × info_leakage` 0, `search_users × info_leakage` 0, `user_directory × info_leakage` 0. So 3 FAIL cells stable and correct, 3 stable and incorrect, 2 unstable, and every PASS cell stable and correct (precision 1.00, no false positive).

### `tests/unit/test_eval_fault_injection.py` (new, with `tests/unit/support/test_eval_fault_injection_given.py` and `_then.py`, where the given/then modules of this repo live)

Each test builds a faulted candidate from the fixture's runs and runs it through the real gate functions: `compare`, `settle` with a scripted replay list, `judge_gate` in `PAIRED` and `FLOORS_ONLY` modes, and `decide_recording` with no existing baseline. The faults, as observations over `MERGED_GROUND_TRUTH`:

- **Judge passes everything**: every covered cell observed PASS.
- **Judge fails everything**: every covered cell observed FAIL.
- **Judge fails at random**: a seeded draw per cell and run.
- **No verdict**: every cell UNCOVERED.
- **Half the detections lost**: each FAIL observation of the fixture turned PASS with probability 0.5, seeded, per cell and run, and replays that reproduce the loss 2 or 3 times out of 5.
- **Generator drops a category**: every cell of one category UNCOVERED, the others as in the fixture.
- **Provider refuses every chain step**: the cells that only chains cover on the chain honeypot lose their chain verdicts. Which cells those are is read from `evals/ground_truth.py` and the chain honeypot's configuration when writing the test, and stated in it.

The fixture holds observations, not case counts, and `EvalMetrics.distribution_coverage` comes from `RunDetail.distribution` (the categories among a tool's *judged cases*, chains excluded, see `compute_distribution_coverage`). Recall and precision of a faulted candidate are computed from its observations with `label_scores`, as `rescore` does. Its distribution coverage cannot be, so each fault's given states it: the fixture's 1.00 for the judge faults that still judge every case, 0.00 for no verdict (no case judged), 0.80 for a dropped category (4 of 5 categories per tool), 1.00 for the chain refusal. Note that 0.80 clears the 0.50 coverage floor: a dropped category is caught by the paired comparison (its stable and correct cells flip with cause `uncovered`), not by the floor.

Each test asserts the gate's verdict and reasons on the current floors (0.50). Where the current gate misses a fault, the test pins the miss and names it, for example the half-loss case settling `FLIP_NOT_REPRODUCED` and staying green. These tests change nothing in production code and are expected to pass at once: they describe the current gate. Their value is in commit 3, where the floor change has to move exactly the expectations that the method note predicts.

## Commit 2: the harness, run by hand

### `evals/fault_injection.py` (new)

The faults as wrappers of the production `LLMPort`, each a small class with `generate_structured`:

- `PassingJudge`, `FailingJudge`: return a `Judgment` with that verdict, a fixed justification and `low` severity, without calling the model.
- `RandomJudge(seed)`: a seeded draw per call.
- `SilentJudge`: raises `ProviderRefusal`, so every case stays unjudged, which is how "no verdict" reaches the report since the provider-refusal work.
- `lose_detections(verdicts, seed, audit_index) -> VerdictMap`: not an `LLMPort` wrapper. `generate_structured` receives only the prompt and the schema, so a judge wrapper cannot key a draw on the cell without parsing the prompt, and a per-case draw would lose a cell with k FAIL cases only with probability 0.5^k. The loss is applied instead to the aggregated `VerdictMap` of each honeypot audit, in the harness's audit function, after the real judge: each FAIL cell turns PASS with probability 0.5, the draw keyed on the cell, the seed and the audit index. The audit index counts every audit, replays included, so each replay draws afresh: a draw keyed on the run alone would make every replay reproduce the loss, and the 6/32 figure below would not hold.
- `CategoryDroppingGenerator(inner, category)`: calls the real generator and removes that category's cases from every `TestCaseBatch`, completions included, and that category's goals from every `ChainPlanBatch`, since a chain verdict also fills its cell (`aggregate_verdicts`).
- `ChainRefusingModel(inner)`: raises `ProviderRefusal` on `ChainPlanBatch`, `StepObservation` and `AuditPayload`, and passes every other call through.

These are eval tooling, not product code, and stay in `evals/`.

### Tests (test-first)

In `tests/unit/test_eval_fault_injection.py`, with its given module, on the deterministic parts of the harness only (per CLAUDE.md, never LLM quality with fakes):

- `lose_detections`: only FAIL cells ever turn PASS, the same seed and audit index give the same map, and two audit indices give independent draws (the property the 6/32 figure rests on).
- `CategoryDroppingGenerator` over a `FakeLLM`: the dropped category is absent from the returned `TestCaseBatch` and `ChainPlanBatch`, the other categories are kept.
- `ChainRefusingModel` over a `FakeLLM`: raises `ProviderRefusal` on the three chain schemas and passes a `TestCaseBatch` call through.
- The run loop moved out of `run_evals.py` keeps the existing `run_evals` tests green unchanged, and a new test runs the extracted function over `FakeLLM` and the honeypots' fake servers (or the fakes the existing tests use) and checks it returns the same verdict map, refused steps and summed token usage as the path it replaced, so a change in the CI eval path would show.
- The harness refuses a stale fixture: with a fixture whose conditions or fingerprints differ from the current ones, it stops before any LLM call with the reasons of `condition_refusals` and `baseline_integrity`.

### `evals/run_fault_injection.py` (new)

`uv run python -m evals.run_fault_injection [--fault NAME ...]`, all faults by default. For each fault:

1. Builds the models: `gpt-6-luna` at `none` for both roles through `create_llm` and `create_judge_llm`, with the fault's wrapper on the role it targets.
2. Audits the three honeypots `DEFAULT_RUNS` times at `DEFAULT_BUDGET`, as `run_evals` does, with the same models.
3. Judges the runs with the production `judge_runs`, on an `EvalSession` whose `baseline` is the fixture, once with `mode=PAIRED` and once with `mode=FLOORS_ONLY`, so the harness exercises the gate's own path (compare, replays, deltas) rather than a copy of it. The `Replayer`'s audit uses the same faulted models, so the fault stays active in the replays. `judge_runs` replays only in `PAIRED`.
4. Decides a recording of the faulted runs with no existing baseline, with `decide_recording` on the `FLOORS_ONLY` gate result's floor breaches (a first recording with no baseline).
5. Prints, per fault, the expected result from the method note next to the observed one, and writes a JSON report to `output/fault_injection_report.json`.

The run loop reuses what `run_evals.py` does rather than copying it: the per-run audit of the three honeypots moves to a public function in `evals/honeypots.py` or `evals/judging.py` that both entry points call, if `run_evals.py` keeps its behavior and its tests.

Before any call, it checks the fixture against the current conditions and ground truth with `condition_refusals` and `baseline_integrity`, as `open_session` does for a committed baseline, and stops with their reasons if either complains: a fixture made stale by a honeypot, label or model change must be rebuilt, not compared against in silence.

It needs `OPENAI_API_KEY` and makes real calls. It is never run in CI.

### `evals/fault_injection_method.md` (new)

A living method note beside the harness, as `evals/probe_method.md` is for the probe:

- What the harness does, what each fault models, and why the fault stays active in the replays.
- **Expected results, written in this commit, before any run**: per fault, the gate's verdict and the reasons expected in `PAIRED` and `FLOORS_ONLY`, and the recording decision, once for floors at 0.50 and once for the floors of ADR 022. For the half-loss fault, the expectation is probabilistic and stated as such: under the rule of 4 reproductions out of at most 5 replays with early stopping, a loss drawn at 0.5 per replay reproduces with probability about 0.19 (6/32), so the gate is expected to miss most of these losses.
- **Recorded runs**: a dated section, empty in this commit, filled after each run by hand with the observed results and where they differ from the expected ones.

### Living docs

- `CLAUDE.md`, Commands: `uv run python -m evals.run_fault_injection  # Fault injection on the honeypot gate, by hand after a change to the gate's logic (OPENAI_API_KEY, never in CI, see evals/fault_injection_method.md)`.
- `CONTRIBUTING.md`: the same command in the eval section, with when to run it.

### After this commit, by hand

Run the harness on the current floors. Write the observed results into the method note's *Recorded runs*, dated, in its own commit (documentation only).

## Commit 3: the recall floor

### `evals/gate.py`

`FLOORS` loses its `recall` entry and keeps `precision` and `distribution_coverage` at 0.50. The recall floor is a count, not a float, so that no rounding decides it when the number of FAIL cells is not a power of two:

```python
@dataclass(frozen=True)
class DetectionCount:
    detections: int  # planted FAIL cells observed FAIL, summed over the runs
    runs: int


def recall_floor_breached(count: DetectionCount) -> bool:
    """One planted flaw found per run, on average (ADR 022): the collapse it catches, a judge
    that passes everything, finds none."""
    return count.detections < count.runs
```

`DetectionCount` also carries `planted: int`, the number of FAIL cells of the ground truth, which `recall_floor_breached` does not read and the display needs (below).

`floor_breaches(metrics, count)` returns `"recall"` when that holds, then the float floors as today. Its callers (`gate_verdict.judge_gate` through `GateInput`, and every test) pass the count. `GateInput` gains `detections: DetectionCount`, computed by `RunsOutcome` from its verdict maps and the ground truth, and both `GateInput` constructions of `judging.judge_runs` (with and without a baseline) pass it. `gate_verdict._breach_reasons` reads `FLOORS[name]` for every breach today: recall gets its own message, "recall: N detection(s) over R runs, under one per run".

`metric_deltas` iterates over `FLOORS` today: it iterates over an explicit tuple of the three metric names instead, so recall keeps its delta.

`GateResult.floors` reports the float floors and the recall floor as its equivalent value, 1 over `planted`, for display only. `eval_display._add_metric_row` computes PASS/FAIL as `value >= limit`: for recall, the status reads from `gate.floor_breaches` instead, so a float rounding of the mean recall against 1/`planted` can never show a status that contradicts the count.

### Tests

The expectations of commit 1 that the method note says move with the new floor move, and only those. The existing floor tests move to the count: in `test_eval_gate.py`, the parametrized `test_floor_breach_names_the_metric` over `sorted(FLOORS)` (recall leaves `FLOORS`) and `test_deltas_cover_the_gated_metrics_only`, which asserts `set(deltas) == set(FLOORS)` and must now assert the three metric names; in `test_eval_gate_verdict.py`, every `GateInput(...)` and `test_legacy_mode_reports_floor_breaches`; in `test_eval_judging.py`, through `RunsOutcome`. `test_eval_session.py` holds no floor test. A test pins that 3 detections over 3 runs is not a breach and 2 over 3 is.

### Living docs, in this commit (CLAUDE.md, Workflow: "as part of the change, not after")

- `CHANGELOG.md`, `[Unreleased]`: the gate bullet that says recall, precision and coverage "each keep an absolute floor" states the recall floor of one detection per run.
- `CLAUDE.md`: the `--ungated` line ("Floors only") stays true, and says which floors.
- `README.md`: only if it states the floors' values (check line 153 and around).
- `evals/run_evals.py`: the `--ungated` help text.
- `.github/workflows/eval-command.yml`: the "floor or threshold" wording, if it states a value.

### `docs/labeling-log.md`

An entry for this instrument change: what changes (the recall floor, from a mean of 0.50 to one detection per run), that no observation, label or metric moves, and that no baseline is committed so no reset applies. The four questions of ADR 016, with (2) noticed after the floor refused the recording of 2026-09-27. The dated fact of that recording: 3 of the 8 planted FAIL cells stable and correct, 3 never detected, 2 unstable, with the per-cell detections listed in commit 1.

## Commit 4: the recording condition and the re-score check

### `evals/gate.py`

Right above `classify`, which it uses (newspaper rule, CLAUDE.md). `evals/baseline.py` imports from `evals/gate.py`, so commit 5 can store it in `Baseline` without a cycle.

```python
class ProtectedCells(BaseModel):
    fail_stable_correct: int
    fail_total: int
    pass_stable_correct: int
    pass_total: int
    unstable: int


def protected_cells(runs: list[dict[Cell, Observation]], ground_truth: GroundTruth) -> ProtectedCells: ...
```

Computed with `classify`.

### `evals/recording.py`

`decide_recording(existing, recording, gate)` has no ground truth today. `Recording` gains `protected: ProtectedCells`, computed by `run_evals._record` with `protected_cells(outcome.observations(), MERGED_GROUND_TRUTH)`, so `evals/recording.py` stays free of `evals/honeypots.py` (which imports the adapters). `_refusals` adds, for every recording: "no planted FAIL cell is stable and correct: the gate could not see a lost detection" and "no PASS cell is stable and correct: the gate could not see a new false positive", each when its count is 0.

`_RESET_PROCEDURE` says that a reset whose recording is refused by this condition is reverted, as one whose red cells do not come out correct.

### `evals/eval_session.py`

When a committed baseline is loaded, `pre_run_refusals` computes `protected_cells` on the re-scored baseline (`rescore` in `evals/baseline.py` restricts the ground truth to the recorded cells). The check depends on the file and the labels alone, like `baseline_integrity` and the condition refusals already there, so it runs before any LLM call instead of in `judge_runs` after three paid runs whose outcome it already knows. A side at 0 raises `Refused(REFUSED_BEFORE_ANY_LLM_CALL, ...)`, which exits 3 as a not comparable run does. `--ungated` loads no baseline and is not affected.

The reason cannot say "record it again": on a confirmed baseline, `_confirmed_refusals` refuses any recording whose gate is not green, and this gate can no longer be green. It names the reset: "under the current labels the baseline holds no stable and correct planted FAIL cell (or PASS cell): delete the baseline file in a commit of its own and record twice at that commit (ADR 022)". The same reason holds for an exploratory baseline, whose confirming recording at another commit `exploratory_commit_refusal` refuses anyway. `pre_run_refusals` also runs under `--record-baseline`, so a recording over such a baseline is refused before any LLM call too, which is the reset the reason names.

### Living docs, in this commit

- `CHANGELOG.md`, `[Unreleased]`: the same gate bullet states the recording condition and the not-comparable re-score.
- `CONTRIBUTING.md`, "Recording an e2e baseline": the recording condition, and that a baseline a label revision leaves with no stable and correct cell on one side is reset, not re-scored.

### Tests

Recording: refused with no stable FAIL cell, refused with no stable PASS cell, accepted with one of each. Re-score (`test_eval_session.py`, through `pre_run_refusals`): a baseline whose only stable and correct FAIL cell a revision relabels PASS is refused before any LLM call, with the reset in its reason. The fault-injection tests of commit 1 whose recording decision the method note says changes move.

### `docs/labeling-log.md`

An entry for this instrument change: the recording condition and the refusal of a baseline that a label revision leaves with no stable and correct cell on one side. No observation, label or metric moves, and no baseline is committed, so no reset applies.

## Commit 5: the protected-cells summary

- `Baseline` gains `protected: ProtectedCells | None = None`, filled by `_baseline_from` from `Recording.protected` when a recording is written. `None` keeps a baseline written before this change readable.
- `eval_display.print_written_recording` prints one line: "planted FAIL cells stable and correct: 3/8, PASS cells stable and correct: 28/28, unstable: 2" (the refused recording's figures: `execute_query × injection` and `project_manager × info_leakage` are its only unstable cells).
- The gate's report shows the re-scored counts when a label revision applies: `GateResult` gains `protected: ProtectedCells | None`, set by `judge_runs` from the re-scored baseline when one is loaded, and `eval_display.print_summary` prints it.
- `CHANGELOG.md`, `[Unreleased]`: the gate bullet mentions the summary printed at recording and at a re-score.

## Commit 6: documentation

The living docs that track a behavior change moved into commits 3, 4 and 5, with the change they describe. What stays here documents behavior this plan does not change:

- `evals/gate.py`, docstring of `ReplayRule` or `settle`: the rule is 4 reproductions out of at most 5 replays, stopping early. A judge that loses each detection half the time reproduces with probability about 0.19 (6/32), so the gate misses most of these losses. The method note's recorded run is the evidence.
- `CONTRIBUTING.md`: the modes stated explicitly: before any baseline, CI keeps the legacy thresholds. An exploratory baseline gates on the floors alone, a confirmed one gates cell by cell plus the floors.

## What stays unchanged

- The product: `src/` is not touched.
- The precision and coverage floors (0.50), the legacy thresholds, the replay rule and its values, the modes and how they are selected.
- The ground truth, the honeypots, the prompts, the models.
- ADRs and past plans.
- CI: no workflow runs the harness.

## Edge cases

- **A ground truth with no FAIL cell**: `recall_floor_breached` compares with the runs, so it is always breached with no FAIL cell to detect, which `baseline_integrity` and the recording condition already make moot. State it in the docstring.
- **Fewer completed runs than requested**: the count uses the completed runs, and the gate is not comparable anyway.
- **A baseline written before commit 5** has no `protected` field: it reads as `None`, and the re-score check computes the counts from its runs (it always does: the stored field is the recording-time summary, never read by the check).
- **The half-loss fault** is the one expected to stay green in `PAIRED`: that is the documented blind spot, not a harness failure.

## Test scenarios

Listed per commit above, commit 2 included. All test-first except commit 1, whose tests describe the current behavior and pass at once (they are the reference that commit 3 moves).

## Verification

```bash
uv run pytest tests/unit
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

The harness is not part of the verification: it is run by hand after commit 2 and after commit 6.

## After this plan

1. Run the harness on the new floors and append the results to the method note.
2. Record the two honeypot baselines on `gpt-6-luna` at `none`, at one commit, from a clean tree, and commit the baseline.

## Commit messages

Each says what it changes. Commit 3 says it is an instrument change with its labeling log entry and moves no metric. No plan, step or phase named.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, one line per fact. Later passes (the implementation-phase fact check among them) read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, on 2026-09-27, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `gpt-6-luna` at reasoning `none`, for both roles (verified against developers.openai.com/api/docs/models, which lists GPT-6 Luna with reasoning effort `none` among its options, and it is the repo's `openai` default in `src/mcp_auditor/config.py`)
- SETTLED: `OPENAI_API_KEY` as the key the harness needs for the default `openai` provider (verified against the repo's `CONTRIBUTING.md` and the existing `gpt-6-luna` eval reports in `output/`, not against a live OpenAI page)
- SETTLED: the refused recording ran on `gpt-6-luna` at reasoning `none`, at `519168f`, at the default conditions (verified from the recording path: `--record-baseline` checks `ci_condition_mismatches` against the defaults, provider `openai`, `gpt-6-luna`, `none`, runs 3, budget 10, and a clean tree, before any run, and the run went on to the floor refusal; the tree was checked clean at `519168f` before it was launched)

## Implementation steps

Each step is one commit, in the order of the plan's six commits. Verification commands for every step (from `CLAUDE.md`): `uv run pytest tests/unit`, `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`. All must pass (pyright strict: 0 errors). No step runs the harness or any LLM: the two hand runs of the harness (after step 2 and after step 6) and the baseline recordings are made by hand, outside these steps.

Facts checked while cutting the steps, which the implementer relies on:

- `output/eval_report_refused-2026-09-27.json` already exists (timestamp `2026-09-26T23:06:09.057206+00:00`, recall 0.458, precision 1.00, consistency 0.981, distribution coverage 1.00).
- There are **no unit tests of `run_evals.py`** today (`grep run_evals tests` finds none). The plan's "keeps the existing `run_evals` tests green unchanged" holds vacuously: the new test of the extracted run loop (step 2) is the only coverage of that path.
- `audit_honeypot` spawns a real stdio server, so the extracted run loop must take the per-honeypot audit as an injected callable (as `Replayer.audit` does with `ReplayAudit`) for a unit test to run it without a server.
- The test given/then modules live in `tests/unit/support/`. `FakeLLM` (`tests/fakes/llm.py`) pops scripted responses and raises a scripted `ProviderRefusal`.

### Step 1: fault injection baseline fixture and gate-level fault tests on the current floors

- **Files**:
  - `evals/fixtures/fault_injection_baseline.json` (create)
  - `tests/unit/test_eval_fault_injection.py` (create)
  - `tests/unit/support/test_eval_fault_injection_given.py` (create)
  - `tests/unit/support/test_eval_fault_injection_then.py` (create, only if the assertions actually abstract something)
- **Do**:
  1. Build the fixture with a throwaway script (not committed), as the plan's "Commit 1" section says: read the three `runs[*].verdicts` of `output/eval_report_refused-2026-09-27.json`, turn each `{tool: {category: {verdict, case_count}}}` back into a `VerdictMap` (`"uncovered"` as `None`), `observe(..., MERGED_GROUND_TRUTH)`, and write a `Baseline` with `status=confirmed`, `commit="519168f"`, `recorded_at` = the report timestamp, `metrics` = the report's, `replay_rule=ReplayRule()`, and `conditions` built as `candidate_conditions` gives them for `gpt-6-luna` at `none`, runs 3, budget 10 (fingerprints from the current ground truth and honeypot sources, which are unchanged since `519168f`: confirm with `git diff 519168f -- tests/*_server.py evals/ground_truth.py` returning nothing). Check the per-cell FAIL detections match the plan's expected list (3,3,3,1,1,0,0,0; 28 PASS cells all stable and correct). Check it with `baseline_integrity(fixture, MERGED_GROUND_TRUTH) == []`.
  2. Tests first, in the given module: a loader for the fixture (`load_baseline`), builders for each faulted candidate's observation runs (judge passes everything, fails everything, random seeded, no verdict, half the detections lost with a seeded draw, a dropped category, chain steps refused), the distribution coverage each fault's given states (1.00, 1.00, 1.00, 0.00, 1.00, 0.80, 1.00), and a function turning a faulted candidate into `EvalMetrics` (recall and precision via `label_scores` over the observations turned back into verdict maps, as `rescore` does, consistency via `compute_consistency`, coverage from the given). For the chain refusal fault, read `CHAIN_HONEYPOT_GROUND_TRUTH` and the chain honeypot server to determine which cells only chains cover, and name them in the given's docstring or the test's name.
  3. Each test runs the faulted candidate through the real gate functions: `compare(fixture.observation_runs(), candidate, MERGED_GROUND_TRUTH)`, `settle` on every `FLIP` with a scripted replay list, `judge_gate(GateInput(...))` in `PAIRED` and `FLOORS_ONLY`, and `decide_recording(None, Recording(...), floors_only_gate)`.
- **Test** (all pass at once, they describe the current gate, floors at 0.50):
  - Judge passes everything: `PAIRED` red (recall floor breached at 0.00, plus regressions on the 3 stable and correct FAIL cells with replays reproducing), `FLOORS_ONLY` red on recall, recording refused on recall.
  - Judge fails everything: precision under its floor, red in both modes, PASS cells flip with cause `wrong_verdict`.
  - Judge fails at random (seeded): pin whatever the seeded draw gives, named.
  - No verdict: every stable and correct cell flips with cause `uncovered`, recall and coverage breached, red in both modes, recording refused.
  - Half the detections lost, replays reproducing 2 or 3 of 5: the flipped cells settle `FLIP_NOT_REPRODUCED`, `PAIRED` stays green unless a floor fires, pinned and named as the miss.
  - Generator drops a category: flips with cause `uncovered` on that category's stable and correct cells, coverage 0.80 clears its floor.
  - Chain steps refused: pin the outcome on the chain-only cells.
  About 7 to 9 tests (one per fault, parametrize the modes where it reads better).
- **Verify**: the new tests pass without any production change. Full verification suite green.

### Step 2: fault injection harness, method note, shared run loop

- **Files**:
  - `tests/unit/test_eval_fault_injection.py` (modify: harness tests)
  - `tests/unit/support/test_eval_fault_injection_given.py` (modify)
  - `evals/fault_injection.py` (create)
  - `evals/judging.py` or `evals/honeypots.py` (modify: the extracted run loop, pick the one that keeps imports acyclic, `judging.py` is likely since it already imports `honeypots`)
  - `evals/run_evals.py` (modify: call the extracted run loop)
  - `evals/run_fault_injection.py` (create)
  - `evals/fault_injection_method.md` (create)
  - `CLAUDE.md`, `CONTRIBUTING.md` (modify: the command)
- **Do**:
  1. Tests first (see Test). Run them red.
  2. `evals/fault_injection.py`: `PassingJudge`, `FailingJudge`, `RandomJudge(seed)`, `SilentJudge`, `CategoryDroppingGenerator(inner, category)`, `ChainRefusingModel(inner)`, each with `async generate_structured[T: BaseModel](self, prompt, output_schema) -> tuple[T, TokenUsage]` satisfying `LLMPort`, and the pure `lose_detections(verdicts: VerdictMap, seed: int, audit_index: int) -> VerdictMap`, exactly as the plan's "Commit 2" section describes (the draw keyed on cell, seed and audit index, for example `random.Random(f"{seed}/{audit_index}/{cell_key(cell)}")`). A judge wrapper must return a `Judgment` only when `output_schema` is the judge's schema: check what the judge node requests, and pass anything else through to an inner model or raise, whichever the judge role needs.
  3. Extract the per-run audit of the three honeypots out of `run_evals._run_one_eval` into a public async function taking the per-honeypot audit as a callable (`Callable[[HoneypotConfig], Awaitable[AuditReport]]`) and a per-honeypot progress callback, returning `(VerdictMap, AuditReport)` with merged tool reports and summed token usage. `run_evals` passes `audit_honeypot(models_for(settings), honeypot, budget)` and its `Progress` calls through it, with unchanged output.
  4. `evals/run_fault_injection.py` as in the plan: `--fault NAME ...` (all by default), the fixture check with `condition_refusals` and `baseline_integrity` before any model is built, then per fault: models via `create_llm`/`create_judge_llm` wrapped on the targeted role, `DEFAULT_RUNS` runs at `DEFAULT_BUDGET` through the extracted loop, `judge_runs` on an `EvalSession` whose `baseline` is the fixture in `PAIRED` then `FLOORS_ONLY`, a `Replayer` whose audit uses the same faulted models (and, for the half-loss fault, applies `lose_detections` with an audit counter shared by runs and replays), `decide_recording(None, ...)` on the `FLOORS_ONLY` result, expected versus observed printed per fault, JSON report to `output/fault_injection_report.json`. Keep functions under 20 lines and the file under 300 (split the fault table from the runner if needed).
  5. `evals/fault_injection_method.md`: what the harness does, each fault, why faults stay active in replays, the expected results per fault in `PAIRED`, `FLOORS_ONLY` and the recording decision for floors at 0.50 (matching step 1's pinned tests) and for the ADR 022 floors (what step 3 and 4 will move), the half-loss probability (6/32, about 0.19), and an empty dated *Recorded runs* section.
  6. `CLAUDE.md` Commands and `CONTRIBUTING.md` eval section: the command line given in the plan.
- **Test**:
  - `lose_detections`: only FAIL cells turn PASS (PASS and `None` untouched), same seed and audit index give the same map, two audit indices differ on some cell over a large enough map (independent draws).
  - `CategoryDroppingGenerator` over `FakeLLM`: the dropped category is absent from a returned `TestCaseBatch` and from a `ChainPlanBatch`'s goals, others kept.
  - `ChainRefusingModel` over `FakeLLM`: raises `ProviderRefusal` on `ChainPlanBatch`, `StepObservation`, `AuditPayload`, passes a `TestCaseBatch` through.
  - The extracted run loop with a fake audit callable returning fixed `AuditReport`s per honeypot: the merged verdict map equals the union of `aggregate_verdicts` per report, tool reports are concatenated, token usage summed, refused steps preserved in the merged report.
  - The harness's fixture check (a pure function in `run_fault_injection.py` or `fault_injection.py`): a fixture whose conditions differ (for example budget 7) or whose runs miss a cell returns the reasons of `condition_refusals` / `baseline_integrity`, and the current fixture returns none.
- **Verify**: new tests red first, then green. Full verification suite green. `uv run python -m evals.run_fault_injection --help` prints the usage without needing a key. The harness itself is not run.

### Step 3: the recall floor as one detection per run

- **Files**:
  - `tests/unit/test_eval_gate.py`, `tests/unit/test_eval_gate_verdict.py`, `tests/unit/test_eval_judging.py`, `tests/unit/test_eval_fault_injection.py` and their given modules as needed (modify)
  - `evals/gate.py` (modify)
  - `evals/gate_verdict.py` (modify)
  - `evals/judging.py` (modify: `RunsOutcome` computes the `DetectionCount`, both `GateInput` constructions pass it)
  - `evals/eval_display.py` (modify: recall status from `gate.floor_breaches`)
  - `docs/labeling-log.md`, `CHANGELOG.md`, `CLAUDE.md`, `evals/run_evals.py` (`--ungated` help), and `README.md` / `.github/workflows/eval-command.yml` only if they state a floor value (README line 153 and the workflow's line 137 "floor or threshold" state none today: check and leave them if so)
- **Do**:
  1. Tests first: `recall_floor_breached(DetectionCount(detections=3, runs=3, planted=8))` is false, `detections=2` is true; `floor_breaches(metrics, count)` names `"recall"` from the count and the float floors from `FLOORS` (parametrize over `sorted(FLOORS)` which no longer holds recall, plus a recall case); `test_deltas_cover_the_gated_metrics_only` asserts the three metric names; every `GateInput(...)` in `test_eval_gate_verdict.py` passes `detections`, `test_legacy_mode_reports_floor_breaches` moves to the count; the recall breach reason reads "recall: N detection(s) over R runs, under one per run"; `GateResult.floors["recall"]` equals `1 / planted`; `RunsOutcome` counts detections over its verdict maps. Move only the expectations of step 1's fault tests that the method note says move with the new floor. Run red.
  2. Production, as the plan's "Commit 3" section: `DetectionCount(detections, runs, planted)` frozen dataclass, `recall_floor_breached` with the docstring noting the no-FAIL-cell edge case, `FLOORS` without recall, `floor_breaches(metrics, count)`, `metric_deltas` over an explicit tuple of the three names, `GateInput.detections`, recall's own message in `_breach_reasons`, `GateResult.floors` with recall at `1 / planted`, `eval_display._add_metric_row` reading recall's status from `floor_breaches`.
  3. `docs/labeling-log.md` entry with the four questions of ADR 016 and the dated fact of the 2026-09-27 recording (per-cell detections from step 1). `CHANGELOG.md` `[Unreleased]` gate bullet. `CLAUDE.md` `--ungated` line names the floors. `run_evals.py` `--ungated` help.
- **Test**: as listed in Do 1 (about 8 new or moved cases).
- **Verify**: red then green. Full verification suite green. `grep -rn '"recall": 0.50' evals` returns nothing.

### Step 4: the recording condition and the re-score check before any LLM call

- **Files**:
  - `tests/unit/test_eval_baseline.py`, `tests/unit/support/test_eval_baseline_given.py` (modify: recording tests, `a_recording` gains `protected`)
  - `tests/unit/test_eval_session.py`, `tests/unit/support/test_eval_session_given.py` (modify: re-score refusal)
  - `tests/unit/test_eval_fault_injection.py` (modify: recording decisions the method note says change)
  - `evals/gate.py` (modify: `ProtectedCells`, `protected_cells` right above `classify`)
  - `evals/recording.py` (modify: `Recording.protected`, the two refusals, `_RESET_PROCEDURE`)
  - `evals/eval_session.py` (modify: `pre_run_refusals` computes `protected_cells` on the re-scored baseline)
  - `evals/run_evals.py` (modify: `_record` fills `Recording.protected`), plus the harness's `Recording` construction in `evals/run_fault_injection.py`
  - `CHANGELOG.md`, `CONTRIBUTING.md` ("Recording an e2e baseline"), `docs/labeling-log.md`
- **Do**:
  1. Tests first: `protected_cells` counts (fail stable correct, fail total, pass stable correct, pass total, unstable) on a small ground truth; `decide_recording` refused with no stable and correct FAIL cell ("no planted FAIL cell is stable and correct: the gate could not see a lost detection"), refused with no stable and correct PASS cell, accepted with one of each; `pre_run_refusals` on a session whose baseline's only stable and correct FAIL cell is relabeled PASS by the current ground truth returns the reset reason of the plan (applies to an exploratory baseline too, and under `--record-baseline`). Since `pre_run_refusals` reads `MERGED_GROUND_TRUTH`, check how `test_eval_session.py` feeds baselines today and give the relabeling through a ground truth parameter or the given module rather than editing `evals/ground_truth.py`. Move the fault tests' recording expectations the method note predicts. Run red.
  2. Production as the plan's "Commit 4" section, with `rescore` giving the restricted ground truth for `protected_cells`, raising through the existing `Refused(REFUSED_BEFORE_ANY_LLM_CALL, ...)` path.
  3. Living docs and the labeling log entry.
- **Test**: as listed (about 7 cases).
- **Verify**: red then green. Full verification suite green.

### Step 5: the protected-cells summary, stored, printed at recording and at a re-score

- **Files**:
  - `tests/unit/test_eval_baseline.py` (modify), `tests/unit/test_eval_judging.py` (modify), their given modules if needed
  - `evals/baseline.py` (modify: `Baseline.protected: ProtectedCells | None = None`)
  - `evals/recording.py` (modify: `_baseline_from` copies `Recording.protected`)
  - `evals/gate_verdict.py` (modify: `GateResult.protected: ProtectedCells | None = None`)
  - `evals/judging.py` (modify: set from the re-scored baseline when one is loaded)
  - `evals/eval_display.py` (modify: `print_written_recording` and `print_summary` print the line)
  - `CHANGELOG.md`
- **Do**: tests first, then the plan's "Commit 5" section. The printed line: "planted FAIL cells stable and correct: F/FT, PASS cells stable and correct: P/PT, unstable: U". A `Baseline` JSON without `protected` still loads (`None`).
- **Test**: a written baseline carries the recording's `protected`; a baseline JSON without the field loads with `None`; `judge_runs` with a loaded baseline sets `GateResult.protected` from the re-scored baseline (a relabeled cell moves the count), and without a baseline leaves it `None`. Display is not unit-tested beyond what exists.
- **Verify**: red then green. Full verification suite green.

### Step 6: documentation of the replay blind spot and the gate modes

- **Files**:
  - `evals/gate.py` (modify: docstring of `ReplayRule` or `settle`)
  - `CONTRIBUTING.md` (modify)
- **Do**: the docstring states the rule (4 reproductions out of at most 5 replays, stopping early), that a judge losing each detection half the time reproduces with probability about 0.19 (6/32), so the gate misses most such losses, and points at `evals/fault_injection_method.md` for the evidence. `CONTRIBUTING.md` states the modes: no baseline, CI keeps the legacy thresholds; an exploratory baseline gates on the floors alone; a confirmed one gates cell by cell plus the floors. No code change.
- **Test**: none (documentation only).
- **Verify**: full verification suite green (ruff and pyright on the docstring edit).
