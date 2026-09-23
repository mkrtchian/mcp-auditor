# Paired eval gate

## Context

ADR 016 replaces the absolute thresholds of the honeypot e2e suite with a paired, cell-by-cell comparison against a recorded baseline, backed by an absolute floor per gated metric, and it records that the gate is not built. Today `evals/run_evals.py` averages four metrics over the runs that finished and compares them to `THRESHOLDS` (recall 0.80, precision 0.85, consistency 0.70, distribution coverage 0.80). CI runs it at `--runs 2 --budget 7` in `.github/workflows/evals.yml` and `.github/workflows/eval-command.yml`, while every local measurement runs at the defaults, 3 runs and budget 10, so the two never measured the same thing (the docstring of `aggregate_verdicts` derives why).

This plan builds the gate for the honeypot suite and records no baseline. The system under test is about to change (prompt work on the generator and the judge guidance), and the fixtures are about to receive their written intent, which can move cells out of the ground truth. A baseline recorded before both would have to be re-recorded after them, and ADR 016 forbids re-recording while the gate is red. So the first recording is a separate, later step, run by hand once those changes land.

Out of scope, each for its own reason: the judge isolation eval keeps its absolute F1 threshold, which ADR 016 leaves outside its decision. The acceptance layer of the CVE benchmark gates the same way, but its baseline must record an oracle version that does not exist yet. A re-grade command, which would apply a ground truth revision to a stored baseline without an LLM call, waits for the first revision taken after a baseline exists: until then a changed ground truth makes the gate refuse to compare, which fails the build, so it opens no way around the gate. Fault injection, the proof ADR 016 names that the gate catches regressions, is not built here either.

## Approach

Three modes, chosen by the state of the baseline file `evals/baselines/honeypot_e2e.json`:

- **No baseline file**: the current thresholds stand, as ADR 016 says they do until a baseline replaces them. Behavior is unchanged, apart from the conditions CI runs at and the new report fields. This is the mode the suite is in when this plan lands.
- **Exploratory baseline**: the floors alone gate. Cell outcomes are computed and reported, and they do not gate, and no replay runs. This is the reading of ADR 016 applied to the first recording: the rule it writes for a model change (exploratory, guarded by the floors alone, until a second recording agrees with it on the cells the first called stable) is the rule for the bootstrap, since a first recording is not a re-recording.
- **Confirmed baseline**: the paired gate. It fires on a regression confirmed by replay or on a floor breach.

A flag `--ungated` runs any mode as floors only, with no condition check and no comparison, for a cheap local run at other conditions. It is never used in CI, and it cannot be combined with `--record-baseline`.

The switch from thresholds to floors happens at the first exploratory recording, not in this plan. The commit that adds that first baseline file answers the four questions of ADR 016, as a change taken while the gate is red.

### Cells and their states

A cell is one `(tool, category)` key of the merged ground truth, 40 today. Only ground-truth cells are compared: a predicted FAIL outside the ground truth is seen by the precision floor alone. In one run, a cell is observed as `pass`, `fail` or `uncovered` (no judged case or chain for that key, which includes a cell whose every case the destructive-payload guard blocked). A cell is correct in a run when its observation equals the ground truth verdict, so `uncovered` is never correct.

Over the runs of one recording, a cell is:

- `stable_correct`: correct in every run. These cells form the gated set.
- `stable_incorrect`: the same wrong observation in every run.
- `unstable`: anything else, including a cell uncovered in some runs and not others.

"Stable" in ADR 016 means the same observation in every run. The split between the two stable states matters for the report (a stable-incorrect cell that becomes correct is an improvement) and for confirmation below.

### Comparison

For each ground-truth cell, the candidate runs give a candidate state by the same classification, and the outcome is:

| Baseline state | Candidate correct in every run | Otherwise |
|---|---|---|
| `stable_correct` | `unchanged` | `flip`, replayed |
| `stable_incorrect` | `improved` | `unchanged` |
| `unstable` | `unchanged` | `inconclusive` |

A flip carries its cause: `uncovered` when some candidate run left the cell uncovered, `wrong_verdict` otherwise. After replay, a flip becomes `regression` or `flip_not_reproduced`. Triage needs the cause because an uncovered flip can come from the generator or from the guard.

### Replay

A flip is replayed under a rule written before it happens: up to 5 replays, and it gates when it reproduces in at least 4, where a replay reproduces a flip when the cell is not correct in that replay run. Replays stop as soon as the outcome is decided (4 reproductions, or 2 non-reproductions), which gives the same decision at lower cost. A replay is one run of the whole honeypot server that holds the cell, at the recorded conditions, because verdicts on one tool depend on the context the auditor carries from the tools before it (ADR 009). The flipped cells of one server share its replays, and each flipped cell is decided on its own counts. A replay grades only the flipped cells: its other verdicts feed neither the metrics nor a recording.

The two numbers are recorded in the baseline file, and the comparison reads them from there. The constants in code only seed a new recording. The rule 2 of 3 was considered and rejected: for a cell with a 30% per-run error that happened to look stable over the 3 recorded runs, it gives about 14% false red per CI run (the chance the cell flips in the 3 candidate runs, 0.66, times the chance 2 of 3 replays reproduce, 0.22), and the August batch had 4 unstable cells out of 40. Counted the same way, 4 of 5 gives about 2% for that cell and about 0.01% for a healthy cell at 10% per-run error, and it catches a regression at 80% per-run error about 74% of the time once it flips, and a deterministic break always.

### Floors

Recall, precision and distribution coverage, averaged over runs as today, each with a floor of 0.50. The values live in code, since ADR 016 makes lowering one a decision for a new ADR, and they are fixed here, before any measurement. A floor is a collapse detector: a judge that passes everything scores recall 0, a judge that fails everything scores precision about 11/40, a generator that stops covering categories drops distribution coverage. `consistency` leaves the gated set in the exploratory and confirmed modes and stays in the report as a diagnostic. It keeps its threshold in the legacy mode, where the thresholds stand unchanged.

### Recorded conditions and fingerprints

The baseline records the conditions below, and the gate refuses to compare when any differs:

- `runs`, `budget`.
- `tools_filter`, always `null` today since the runner has no filter option. ADR 016 lists it, and the comparison over it is trivially equal until an option exists.
- `provider`, and the generator and judge models as `Settings.resolve_model()` and `Settings.resolve_judge_model()` return them. Temperature is not set anywhere (provider default), so there is nothing to record. The google default `gemini-3.1-flash-lite` is a stable model code that the provider says usually doesn't change, which is not a pinned version: a name records the version behind it only as far as the provider keeps it fixed, the limit ADR 016 already states.
- `ground_truth_fingerprint`: sha256 over the sorted lines `tool/category=verdict` of the merged ground truth. This is the honeypot suite's oracle version.
- per honeypot: `chain_budget`, `max_chain_steps` (they set how many chain verdicts a cell holds, the same argument as `--budget`) and `source_fingerprint`, a sha256 over the `(tokenize.tok_name[type], string)` pairs of the server's token stream with `COMMENT` and `NL` tokens dropped (`tokenize.generate_tokens`). Token positions are left out, since an added comment line shifts every line number after it. Types are hashed by name, not number, because the numbers shift between minor versions (`COMMENT` is 62 in 3.13 and 65 in 3.14). Comments do not change it, so the intent annotations coming to the fixtures leave it alone, while a change to a tool's behavior or docstring does. `tokenize` is chosen over `ast.dump` because the dump format changes across Python minor versions, and CI runs 3.13 while the local interpreter is 3.14 today.

A fixture change cannot be re-graded, so a source mismatch always means "not comparable". A ground truth mismatch means "not comparable" until a re-grade command exists.

### Recording

`--record-baseline` writes `evals/baselines/honeypot_e2e.json` for a manual commit. CI never records. It needs a git tree with no tracked modifications (`git status --porcelain --untracked-files=no` empty), and it records `commit` (`git rev-parse HEAD`) and `recorded_at`. It refuses, with the reason, when:

- any run failed, since a baseline must hold the runs its conditions claim;
- `--ungated` is passed. This one is rejected at argument parsing (see `evals/run_evals.py` below), so `decide_recording` never sees it;
- the floors are breached. With no baseline this is the only verdict that counts: the first, exploratory recording is allowed whatever the legacy thresholds say, since the floors are its guard;
- an exploratory baseline exists and the commit differs from the one it was recorded at. Agreement between two recordings is meant as a test-retest of one system. Without this rule a regression landed between the two could replace the first recording and then be confirmed by a third. Starting over is deleting the file in a commit of its own;
- a confirmed baseline exists and the conditions differ, with the message pointing at the model-change procedure of ADR 016 (run both models, record the delta, delete the file, record a new exploratory baseline);
- a confirmed baseline exists and the gate is red or not comparable;
- a confirmed baseline exists and any gated cell flipped in the run, reproduced or not. A green run can still carry flips that the replays did not reproduce, and recording from it would silently drop those cells from the gated set.

When it writes:

- no baseline: status `exploratory`.
- exploratory baseline, same commit: if the new recording classifies every cell the first called stable (either stable state) the same way, status `confirmed`, with `confirms` pointing at the first (its `commit` and `recorded_at`). Otherwise status `exploratory`, with `replaces` pointing at the first and `disagreements` listing the cells.
- confirmed baseline: status `confirmed`, with `replaces` pointing at the old one.

The recorded file holds the new recording's runs. The output lists every cell that enters or leaves the gated set compared to the file it replaces.

### Exit codes

`0` green, including inconclusive and non-reproduced flips. `1` red: a floor breach, a replay-confirmed regression, or a legacy threshold missed. `3` not comparable: a condition, ground truth or fixture mismatch, fewer completed runs than the baseline's `runs`, or a replay that failed. A refused recording also exits `3`. With `--record-baseline`, a written recording exits `0` (a floor breach would have refused it), whatever the legacy verdict of a first recording says. `2` is left to `argparse`. Both CI workflows fail on any non-zero code, which is intended: a gate that cannot compare is not green.

### Incomplete runs

`run_evals` keeps skipping a run whose audit raised, and the report now records `completed_runs` beside the requested `runs`. With a baseline present, fewer completed runs than `runs` make the result not comparable. In the legacy mode, behavior is unchanged.

### Metric deltas

With a baseline, the report gives each gated metric's delta against the baseline's value (the averaged metrics stored in the baseline file, since the stored observations cover ground-truth cells only: they miss the predicted FAILs outside the ground truth that precision counts, and distribution coverage is computed from cases per tool, chains excluded, which a cell observation cannot give back), and marks it `inconclusive` when its absolute value is below the instrument's resolution: `1 / (expected FAIL cells × runs)` for recall, `1 / (predicted FAIL cells averaged over the candidate runs × runs)` for precision, counted on the full verdict maps, `1 / (tools × categories × runs)` for distribution coverage. This is the move one misclassified case makes on the averaged metric, as ADR 016 defines it. The deltas never gate.

## Files to modify

### `evals/gate.py` (new)

Pure, no I/O. Top-down:

- `Cell = tuple[str, AuditCategory]`.
- `class Observation(StrEnum)`: `PASS = "pass"`, `FAIL = "fail"`, `UNCOVERED = "uncovered"`.
- `class CellState(StrEnum)`: `STABLE_CORRECT`, `STABLE_INCORRECT`, `UNSTABLE`.
- `class CellOutcome(StrEnum)`: `UNCHANGED`, `IMPROVED`, `INCONCLUSIVE`, `FLIP`, `REGRESSION`, `FLIP_NOT_REPRODUCED`.
- `class FlipCause(StrEnum)`: `UNCOVERED`, `WRONG_VERDICT`.
- `class ReplayRule(BaseModel)`: `replays: int = 5`, `required: int = 4`. Method `decide(reproduced: int, cleared: int) -> bool | None`: `True` once `reproduced >= required`, `False` once `cleared > replays - required`, else `None`.
- `FLOORS: dict[str, float]` with the three gated metrics at 0.50.
- `observe(verdicts: VerdictMap, ground_truth: GroundTruth) -> dict[Cell, Observation]`: one observation per ground-truth cell.
- `classify(runs: list[dict[Cell, Observation]], ground_truth: GroundTruth) -> dict[Cell, CellState]`.
- `class CellComparison(BaseModel)`: `outcome: CellOutcome`, `cause: FlipCause | None`, `replays: list[bool]` (reproduced or not, per replay).
- `compare(baseline_runs, candidate_runs, ground_truth) -> dict[Cell, CellComparison]`: the table above, flips left as `FLIP` with their cause.
- `settle(comparison: CellComparison, replays: list[bool], rule: ReplayRule) -> CellComparison`: `REGRESSION` or `FLIP_NOT_REPRODUCED`.
- `floor_breaches(metrics: EvalMetrics) -> list[str]`.
- `metric_resolutions(verdict_maps: list[VerdictMap], ground_truth: GroundTruth, tool_count: int) -> dict[str, float]`: the resolution formulas of "Metric deltas", over the candidate's full verdict maps.
- `metric_deltas(baseline: EvalMetrics, candidate: EvalMetrics, resolutions: dict[str, float]) -> dict[str, MetricDelta]` with `MetricDelta(value: float, resolution: float, inconclusive: bool)`.

The baseline's metrics are not recomputed from its observations: see "Metric deltas".

### `evals/baseline.py` (new)

The recorded file and the rules over it, pure apart from `load_baseline` and `write_baseline`, which take a `Path`.

- `class BaselineStatus(StrEnum)`: `EXPLORATORY`, `CONFIRMED`.
- `class FixtureConditions(BaseModel)`: `source_fingerprint: str`, `chain_budget: int`, `max_chain_steps: int`.
- `class BaselineConditions(BaseModel)`: `runs`, `budget`, `tools_filter: list[str] | None = None`, `provider`, `model`, `judge_model`, `ground_truth_fingerprint`, `fixtures: dict[str, FixtureConditions]`.
- `class RecordingRef(BaseModel)`: `commit: str`, `recorded_at: str`.
- `class Baseline(BaseModel)`: `status`, `conditions`, `replay_rule: ReplayRule`, `commit`, `recorded_at`, `runs: list[dict[str, Observation]]` keyed `tool/category`, `metrics: EvalMetrics` (the recording's averaged metrics, read by `metric_deltas`), `confirms: RecordingRef | None`, `replaces: RecordingRef | None`, `disagreements: list[str] = []`. Method `observation_runs() -> list[dict[Cell, Observation]]` parses the keys back.
- `fingerprint_ground_truth(ground_truth: GroundTruth) -> str`.
- `fingerprint_source(source: str) -> str`.
- `condition_mismatches(recorded: BaselineConditions, candidate: BaselineConditions) -> list[str]`: one line per differing field, naming both values.
The file imports `Observation` and `ReplayRule` from `evals/gate.py`, never the reverse.

### `evals/gate_verdict.py` (new)

Pure. It imports `gate` and `baseline`, which keeps the two free of each other.

- `class GateMode(StrEnum)`: `LEGACY_THRESHOLDS`, `FLOORS_ONLY`, `PAIRED`.
- `class GateVerdict(StrEnum)`: `GREEN`, `RED`, `NOT_COMPARABLE`.
- `class GateResult(BaseModel)`: `mode`, `verdict`, `reasons: list[str]`, `baseline_status: BaselineStatus | None`, `cells: dict[str, CellComparison]`, `floors: dict[str, float]`, `floor_breaches: list[str]`, `deltas: dict[str, MetricDelta]`. `floor_breaches` is computed in every mode, including the legacy one, because the first recording is decided on the floors while the verdict is still the legacy one.
- `judge_gate(...)`: builds the `GateResult` from the mode, the floor breaches, the settled cells and any mismatch. If this overflows three arguments, the input is a `GateInput` value object naming the grouping.

### `evals/recording.py` (new)

Pure. The recording rules of "Recording" above.

- `class Recording(BaseModel)`: what a run offers to record, `conditions`, `commit`, `recorded_at`, `runs`, `metrics: EvalMetrics`, `completed_all: bool`. A new baseline takes the existing baseline's `replay_rule`, or `ReplayRule()` when there is none.
- `class RecordingRefused(BaseModel)`: `reasons: list[str]`.
- `decide_recording(existing: Baseline | None, recording: Recording, gate: GateResult) -> Baseline | RecordingRefused`, applying the refusal list and the status rules, except the `--ungated` refusal, which the runner enforces before any run. The gate result carries the verdict and the flips on gated cells, so the function needs nothing else.
- `gated_set_changes(old: Baseline | None, new: Baseline) -> tuple[list[str], list[str]]`: cells entering and leaving the gated set.

### `evals/metrics.py`

`EvalReport.config: dict[str, int]` gains `completed_runs`. `thresholds` stays, filled only in the legacy mode. `passed` stays and equals `gate.verdict == GREEN`, which in the legacy mode is today's thresholds verdict. `EvalReport` gains `gate: GateResult`, but `gate.py` imports `metrics` for `VerdictMap`, `EvalMetrics` and the metric functions, so `EvalReport` cannot import `GateResult` from here without a cycle. `EvalReport` moves to `evals/eval_report.py` (new), which imports both, and `RunDetail`, `ToolVerdictDetail`, `ToolDistribution`, `ConsistencyDetail` stay in `metrics.py` beside the functions that fill them.

### `evals/run_evals.py`

411 lines today, over the 300 the standards allow, so presentation moves out (below) as part of this change. What stays: argument parsing, the run loop, one honeypot run, the replay loop, and the composition of the gate.

- New flags `--record-baseline` and `--ungated`, rejected together with exit `3` as a refused recording (not an argparse mutually exclusive group, which would exit `2`).
- Before any LLM call: build the candidate `BaselineConditions` (settings, fingerprints read from the three server files, chain settings from `HONEYPOTS`), load the baseline if the file exists, and exit `3` on a mismatch unless `--ungated`.
- `_run_one_eval` keeps returning the merged verdicts, and the runner also keeps each run's verdicts per honeypot so that a replay can run one server alone. A replay's verdicts are observed against that honeypot's own ground truth, not the merged one, which would read every other server's cells as `uncovered`.
- With `--record-baseline`, the clean-tree check and, when an exploratory baseline exists, the same-commit check run before the first LLM call. `decide_recording` checks the commit again after the runs.
- After the runs: observe, compare, replay each server holding a `FLIP` on a gated cell (confirmed mode only) through `_run_single_honeypot`, settle, judge, write the report, then record if asked.
- A replay that raises makes the verdict `NOT_COMPARABLE`.
- When every run fails, the exit stays `1` in the legacy mode and becomes `3` with a baseline present, as any incomplete set of runs.
- `git rev-parse HEAD` and the porcelain status are read here, through `subprocess.run`, only when `--record-baseline` is passed. `evals/` is outside the hexagon and this module is its composition root.
- `THRESHOLDS` stays for the legacy mode.

### `evals/eval_display.py` (new)

`_print_summary`, `_add_metric_row`, `_print_run_result` move here, and the summary shows the mode: thresholds table in the legacy mode, floors table otherwise, `consistency` without a PASS/FAIL status outside the legacy mode, then the non-`unchanged` cells with outcome, cause and replay counts, and the reasons for a red or not-comparable verdict. A refused recording prints its reasons, and a written one prints the gated-set changes.

### `evals/baselines/`

Not created by this plan. The first `--record-baseline` creates it.

### `.github/workflows/evals.yml`, `.github/workflows/eval-command.yml`

Drop `--runs 2 --budget 7`, so CI runs at the defaults, 3 runs and budget 10, the conditions the baseline will be recorded at. Measured on the report of 2026-08-22 (3 runs, budget 10): about 268k input and 54k output tokens in total, about twice a 2/7 run, plus up to 5 single-server runs for each server holding a flip once a confirmed baseline exists. In `evals.yml`, upload `output/eval_report.json` and `output/judged_cases.jsonl` as an artifact of the e2e job through `actions/upload-artifact@v7` with `if: always()`, so a red run on main can be triaged from its report.

In `eval-command.yml`, the PR comment names why the e2e step failed, since "Evals failed" today reads the same for a regression and for a run that could not compare. The e2e step gets `id: e2e`, runs `run_evals` under `set +e`, writes its exit code to `$GITHUB_OUTPUT` as `exit_code` and exits with it. The "Report result" step reads `steps.e2e.outputs.exit_code` and, on failure, appends `red (regression, floor or threshold)` for `1` or `not comparable (conditions, fixtures or incomplete runs, see the log)` for `3`. The judge-only mode has no e2e step and its comment is unchanged.

This changes the conditions of a gate that is red today, under the legacy thresholds. Its justification holds with the measurement deleted: the baseline records one set of conditions and CI must run at them. Its commit message answers the four questions of ADR 016.

### `README.md`

In `## Measurement`, the sentence "That change is decided and not built yet." becomes a statement that the paired gate is built, that no baseline is recorded yet, and that the absolute thresholds stand until the first recording. No number changes.

### `CONTRIBUTING.md`

Under "Running evals on a pull request", say that `/eval full` runs at the baseline's conditions. Add a short paragraph on recording a baseline: `--record-baseline` from a clean tree, the exploratory then confirmed sequence at one commit, the file committed by hand, never from CI, and what `--ungated` is for. The paragraph also says to record with the provider and model settings CI resolves, that is with no `MCP_AUDITOR_PROVIDER`, `MCP_AUDITOR_MODEL` or `MCP_AUDITOR_JUDGE_MODEL` override differing from the defaults in `.env` or the environment: CI sets only the API key, so a baseline recorded under an override makes every CI run not comparable. In the commands block at the top, add `--record-baseline` and `--ungated` beside the existing `evals.run_evals` line.

### `CLAUDE.md`

In Commands, add `uv run python -m evals.run_evals --record-baseline` and `uv run python -m evals.run_evals --ungated`, each with a short comment.

### `CHANGELOG.md`

Under `[Unreleased]` / `Changed`: the e2e evals gate against a recorded baseline cell by cell once one exists, with absolute floors, and CI runs them at 3 runs and budget 10. Link ADR 016.

## What stays unchanged

- `aggregate_verdicts`, `compute_recall`, `compute_precision`, `compute_consistency`, `compute_distribution_coverage`: the gate reuses them.
- `evals/ground_truth.py` and the three honeypot servers. They are fixtures, and this plan reads them.
- `evals/export.py` and `judged_cases.jsonl`.
- The judge isolation eval, its threshold and its workflow step.
- The CVE benchmark.
- The behavior of `run_evals` with no baseline file, apart from the report's new fields and the CI conditions.
- `docs/adr/`, `plans/` other than this file.

## Edge cases

- No baseline, `--ungated`: floors only, report mode `FLOORS_ONLY`, no condition check.
- No baseline, `--record-baseline`, precision under the legacy threshold but over its floor: records an exploratory baseline and exits on the floors, `0`. The legacy verdict of that same run is reported beside it.
- No baseline, `--record-baseline`, a floor breached: refused, exit `3`, nothing written.
- A run failed and `--record-baseline`: refused.
- Dirty tree and `--record-baseline`: refused before any LLM call, since the check costs nothing.
- Exploratory baseline, recording at another commit: refused before any LLM call.
- Confirmed baseline, conditions differ: exit `3` before any LLM call, message names each field.
- Confirmed baseline, ground truth edited: exit `3` before any LLM call, message names the ground truth fingerprint.
- Confirmed baseline, a comment added to a honeypot: comparable, fingerprint unchanged.
- Confirmed baseline, one run of three failed: not comparable, `3`.
- A gated cell uncovered in one candidate run: flip with cause `uncovered`, replayed.
- A flip on a server whose first two replays do not reproduce it: `FLIP_NOT_REPRODUCED` after 2 replays, verdict green, and a later `--record-baseline` from that run is refused.
- Two flipped cells on one server, one reproduced 4 times in 4 replays, the other cleared after 2: both decided on their own counts, replays stop when every flipped cell of the server is decided.
- A replay raises: `NOT_COMPARABLE`, never green.
- Exploratory baseline, flips present: reported, no replay, floors decide.

## Test scenarios

Unit tests, given/then files under `tests/unit/support/` per the project convention, synthetic observations, no LLM.

`tests/unit/test_eval_gate.py`:

- Observation: a ground-truth cell absent from the verdict map is `uncovered`, a present one is its verdict.
- Classification: correct in all runs is stable-correct, the same wrong observation in all runs is stable-incorrect, a mix is unstable, uncovered in one run of three is unstable.
- Comparison, one test per table cell: unchanged, flip with cause `wrong_verdict`, flip with cause `uncovered`, improved, stable-incorrect staying wrong is unchanged, inconclusive on an unstable baseline cell.
- Replay rule: 4 reproductions decide regression, 2 clearances decide not reproduced, 3 and 1 is undecided.
- Settling: a flip becomes regression or not reproduced by its counts.
- Floors: each metric under 0.50 is named, all over is empty.
- Verdict: legacy mode uses the thresholds, floors-only ignores cells, paired is red on a regression or a floor, green with only non-reproduced or inconclusive flips, not comparable on mismatch or incomplete runs.
- Deltas: a delta smaller than one case's move is inconclusive, a larger one is not. The precision resolution counts a predicted FAIL outside the ground truth.
- Floor breaches are reported in the legacy mode too.

`tests/unit/test_eval_baseline.py`:

- Ground truth fingerprint changes with one verdict flipped, not with dict order.
- Source fingerprint ignores an added comment and blank lines, changes with a changed string literal.
- Condition mismatches: equal conditions give none, a differing budget names both values, a differing fixture fingerprint names the honeypot.
- Recording, one test per refusal and per status rule of "Recording": first recording is exploratory; exploratory plus same commit plus agreement is confirmed with `confirms`; exploratory plus same commit plus disagreement is exploratory with `replaces` and `disagreements`; exploratory plus another commit is refused; confirmed plus a gated flip not reproduced is refused; confirmed plus green is confirmed with `replaces`; failed run refused; floors breached refused.
- Gated set changes: a cell becoming unstable leaves, a stable-incorrect cell becoming correct enters.
- Round trip: a `Baseline` written and loaded is equal, `observation_runs` parses the keys back to cells.

No integration test: the runner's wiring needs an LLM, and the evals themselves exercise it on the first recording.

## Verification

```bash
uv run pytest tests/unit
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run python -m evals.run_evals --record-baseline --ungated   # exits 3 before any LLM call: the two flags are exclusive
uv run python -m evals.run_evals --help                        # shows both new flags
```

A full run is not part of this plan's verification: with no baseline file, its behavior is the legacy one, and the first recording is the later, separate step described in Context.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, one line each, read by the implementation-phase fact check. A line records what was concluded once, on 2026-09-23, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `actions/upload-artifact@v7` (latest major is v7.0.1, verified against github.com/actions/upload-artifact/releases; matches the `@v7` pins of `actions/checkout` and `astral-sh/setup-uv` already in both workflows)
- SETTLED: `tokenize.generate_tokens` takes a str `readline` and yields no `ENCODING` token (verified against docs.python.org/3/library/tokenize.html). The integer `(type, string)` stream with `COMMENT` and `NL` dropped hashes identically under 3.13.12 and 3.14.3 on the three honeypot files today (checked locally)
- SETTLED: the integer values of token types are not stable across minor versions (`COMMENT` is 62 in 3.13, 65 in 3.14, `NL` 63 then 66), so the fingerprint hashes `tokenize.tok_name[type]` (decided after due diligence)
- SETTLED: `ast.dump` output changes across minor versions (`show_empty`, default `False`, added in 3.13, verified against docs.python.org/3/library/ast.html)
- SETTLED: `gemini-3.1-flash-lite` is listed on ai.google.dev/gemini-api/docs/models as a stable model code that "usually doesn't change", not a `-latest` alias; the plan states it in those terms (decided after due diligence)
- SETTLED: CI runs Python 3.13 (`uv python install 3.13` in both workflows), the local `uv run` interpreter is 3.14.3 (checked locally)
- SETTLED: `git status --porcelain --untracked-files=no`, `git rev-parse HEAD`, and `argparse` exiting `2` on a usage error (standard behavior, no live source needed)

## Implementation steps

Every step ends with the same checks, all expected clean: `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`. Given/then helpers go in `tests/unit/support/`, imported as `import tests.unit.support.<name>_given as given` (the pattern of `tests/unit/test_eval_metrics.py`). Test files are written first and run red before the production code.

### Step 1: cells, comparison, replay rule, floors and deltas (`evals/gate.py`)

- **Files**: `tests/unit/test_eval_gate.py`, `tests/unit/support/test_eval_gate_given.py`, `tests/unit/support/test_eval_gate_then.py` (only if an assertion actually abstracts something), `evals/gate.py` (new).
- **Do**:
  - Tests first, with a given module building synthetic `VerdictMap`s, ground truths of a few cells and observation runs.
  - `evals/gate.py`, pure, top-down as listed in "Files to modify / `evals/gate.py`": `Cell`, `Observation`, `CellState`, `CellOutcome`, `FlipCause`, `ReplayRule` (with `decide`), `FLOORS` (`recall`, `precision`, `distribution_coverage` at 0.50), `observe`, `classify`, `CellComparison`, `compare`, `settle`, `floor_breaches`, `metric_resolutions`, `MetricDelta`, `metric_deltas`.
  - Also `cell_key(cell: Cell) -> str` (`"tool/category"`) and `parse_cell_key(key: str) -> Cell`. `baseline.py` and `gate_verdict.py` key their dicts with them in later steps.
  - `compare` applies the table of "Comparison". A flip's cause is `UNCOVERED` when any candidate run observed the cell `uncovered`, `WRONG_VERDICT` otherwise. Replays stay empty.
  - `settle` takes the per-replay booleans, stores them in `replays`, and uses `rule.decide(reproduced, cleared)`. `True` gives `REGRESSION`, `False` gives `FLIP_NOT_REPRODUCED`. An undecided list is a caller bug (the runner replays until decided or `rule.replays` is spent, and 5 replays always decide 4-of-5), so no branch for it.
  - `metric_resolutions`: recall `1 / (expected FAIL cells × runs)`, precision `1 / (mean predicted FAIL cells over the maps × runs)` counted on the full maps (outside-ground-truth FAILs included), distribution coverage `1 / (tool_count × len(AuditCategory) × runs)`. Guard a zero denominator (no predicted FAIL) by returning `1.0` for that resolution, since no single case can move a metric that has no support.
  - `metric_deltas` covers the three gated metrics only. `inconclusive` is `abs(value) < resolution`.
- **Test** (`test_eval_gate.py`):
  - Observation: ground-truth cell missing from the map is `uncovered`, a present PASS or FAIL is itself. A cell present in the map but with verdict `None` is `uncovered` too.
  - Classification: correct in all runs is stable-correct, the same wrong observation in all runs is stable-incorrect, a mix is unstable, uncovered in one run of three is unstable.
  - Comparison, one test per table cell: stable-correct stays correct is `unchanged`, flip with `wrong_verdict`, flip with `uncovered`, stable-incorrect becoming correct is `improved`, stable-incorrect staying wrong is `unchanged`, unstable baseline with a not-always-correct candidate is `inconclusive`.
  - Replay rule: 4 reproductions give `True`, 2 clearances give `False`, 3 reproduced and 1 cleared give `None`.
  - Settling: `[True]*4` gives `REGRESSION`, `[False, False]` gives `FLIP_NOT_REPRODUCED`.
  - Floors: each metric under 0.50 is named, all over is empty, `consistency` under 0.50 is not named.
  - Deltas: a delta smaller than one case's move is inconclusive, a larger one is not. The precision resolution counts a predicted FAIL outside the ground truth.
- **Verify**: the four checks above, all clean.

### Step 2: baseline file, report move and gate verdict

- **Files**: `tests/unit/test_eval_baseline.py`, `tests/unit/support/test_eval_baseline_given.py`, `tests/unit/test_eval_gate.py` (extend), `tests/unit/support/test_eval_gate_given.py` (extend), `evals/baseline.py` (new), `evals/gate_verdict.py` (new), `evals/eval_report.py` (new), `evals/metrics.py`, `evals/run_evals.py` (import of `EvalReport` only).
- **Do**:
  - Tests first.
  - `evals/baseline.py` as specified in "Files to modify / `evals/baseline.py`": `BaselineStatus`, `FixtureConditions`, `BaselineConditions`, `RecordingRef`, `Baseline` (runs keyed with `cell_key`, `observation_runs()` using `parse_cell_key`), `fingerprint_ground_truth` (sha256 of the sorted `tool/category=verdict` lines joined by `\n`), `fingerprint_source` (sha256 over `(tokenize.tok_name[type], string)` pairs from `tokenize.generate_tokens(io.StringIO(source).readline)`, dropping `COMMENT` and `NL`, positions excluded), `condition_mismatches` (one line per differing field naming both values, one line per differing honeypot under `fixtures` naming the honeypot and the differing field), `load_baseline(path) -> Baseline | None` (`None` when the file is absent), `write_baseline(path, baseline)` (creates the parent dir, `model_dump_json(indent=2)`). Imports from `gate`, never the reverse.
  - `evals/eval_report.py`: `EvalReport` moves here from `metrics.py`, gaining `gate: GateResult`. `config` stays `dict[str, int]` and will carry `completed_runs`. `run_evals.py` imports `EvalReport` from the new module. It does not yet fill `gate`: give `gate` no default and keep the runner compiling by building a legacy `GateResult` through `judge_gate` in `_assemble_report` (legacy mode, the current thresholds), so the report and exit code are unchanged by this step. Add `completed_runs` to `config` here too, since it is the length of `run_details`.
  - `evals/gate_verdict.py`: `GateMode`, `GateVerdict`, `GateResult` (fields as in the plan, `cells` keyed with `cell_key`), and `judge_gate(gate_input: GateInput) -> GateResult`. `GateInput` is a frozen value object: `mode`, `metrics: EvalMetrics`, `thresholds: dict[str, float] | None` (legacy mode only, since `THRESHOLDS` stays in `run_evals.py`), `baseline_status`, `cells: dict[Cell, CellComparison]` (settled), `mismatches: list[str]` (condition, fingerprint, incomplete-run and replay-failure reasons, all read as not comparable), `deltas`. Verdict: any mismatch gives `NOT_COMPARABLE`. Otherwise legacy is `RED` when a threshold is missed, floors-only is `RED` on a floor breach and ignores cells, paired is `RED` on a floor breach or a `REGRESSION` cell, else `GREEN`. `floor_breaches` is always computed. `reasons` lists what made it red or not comparable.
- **Test**:
  - `test_eval_baseline.py`: ground truth fingerprint changes with one verdict flipped, not with dict insertion order. Source fingerprint ignores an added comment line and blank lines, changes with a changed string literal. Condition mismatches: equal conditions give none, a differing budget names both values, a differing fixture fingerprint names the honeypot. Round trip through `tmp_path`: written then loaded is equal, `observation_runs` gives `Cell` keys back. Loading an absent path gives `None`.
  - `test_eval_gate.py` (verdict): legacy mode red on a missed threshold and green otherwise, floors-only ignores a regression cell, paired red on a regression, red on a floor breach, green with only `FLIP_NOT_REPRODUCED` and `INCONCLUSIVE` cells, not comparable on a mismatch. Floor breaches are reported in legacy mode too.
- **Verify**: the four checks, all clean. `uv run python -m evals.run_evals --help` still works (import sanity, no LLM call).

### Step 3: recording rules (`evals/recording.py`)

- **Files**: `tests/unit/test_eval_baseline.py` (extend), `tests/unit/support/test_eval_baseline_given.py` (extend), `evals/recording.py` (new).
- **Do**:
  - Tests first.
  - `Recording` as in the plan, plus `ground_truth: GroundTruth`. Classification needs the ground truth (to tell stable-correct from stable-incorrect, and for the agreement and gated-set rules), and the baseline file stores only its fingerprint. The conditions already guarantee both recordings share it.
  - `RecordingRefused(reasons)`.
  - `decide_recording(existing, recording, gate)`: collect every applicable refusal of "Recording" (failed run via `completed_all`, floor breaches from `gate.floor_breaches`, exploratory at another commit, confirmed with `condition_mismatches` non-empty and the message pointing at the ADR 016 model-change procedure, confirmed with `gate.verdict` not `GREEN`, confirmed with any gated cell whose outcome is `FLIP`, `REGRESSION` or `FLIP_NOT_REPRODUCED`). Any refusal returns `RecordingRefused`. Otherwise build the `Baseline` with the status rules: no baseline gives `exploratory`. Exploratory at the same commit gives `confirmed` with `confirms` when every cell the first called stable (either state) has the same state in the new recording, else `exploratory` with `replaces` and `disagreements` (cell keys). Confirmed gives `confirmed` with `replaces`. `replay_rule` is the existing baseline's, or `ReplayRule()`.
  - `gated_set_changes(old, new, ground_truth) -> tuple[list[str], list[str]]` (entering, leaving), comparing the `stable_correct` sets. The plan's two-argument signature cannot classify without the ground truth, hence the third argument. With `old=None` every gated cell enters.
- **Test**: one test per refusal and per status rule of "Recording": first recording exploratory; exploratory + same commit + agreement is confirmed with `confirms`; exploratory + same commit + disagreement is exploratory with `replaces` and `disagreements`; exploratory + another commit refused; confirmed + a gated flip not reproduced refused; confirmed + conditions differ refused with the model-change message; confirmed + green is confirmed with `replaces`; failed run refused; floors breached refused, including with no baseline; no baseline + legacy thresholds missed but floors met writes an exploratory baseline. Gated set changes: a cell becoming unstable leaves, a stable-incorrect cell becoming correct enters.
- **Verify**: the four checks, all clean.

### Step 4: runner wiring, display and living docs

- **Files**: `evals/run_evals.py`, `evals/eval_display.py` (new), `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do**:
  - Move `_print_summary`, `_add_metric_row`, `_print_run_result` to `evals/eval_display.py` (public names, the module owns `console` or takes it), extended as in "Files to modify / `evals/eval_display.py`": mode, thresholds or floors table, `consistency` without status outside legacy mode, non-`unchanged` cells with outcome, cause and replay counts, the reasons of a red or not-comparable verdict, a refused recording's reasons, a written recording's gated-set changes. `run_evals.py` ends under 300 lines.
  - `run_evals.py`, per "Files to modify / `evals/run_evals.py`":
    - `--record-baseline` and `--ungated` flags. Both together: print the refusal and exit `3` right after parsing.
    - Before any LLM call: candidate `BaselineConditions` (from `load_settings()`, `resolve_model()`, `resolve_judge_model()`, `fingerprint_ground_truth` on the merged ground truth, `fingerprint_source` on each of the three server files, chain settings from `HONEYPOTS`), `load_baseline(BASELINE_PATH)` with `BASELINE_PATH = Path("evals/baselines/honeypot_e2e.json")` resolved from the repo root like the server paths. Mode: `--ungated` gives `FLOORS_ONLY` with no check, no baseline gives `LEGACY_THRESHOLDS`, exploratory gives `FLOORS_ONLY` with cells computed and reported, confirmed gives `PAIRED`. Mismatches exit `3` before any LLM call unless `--ungated`.
    - With `--record-baseline`: `git status --porcelain --untracked-files=no` must be empty and, with an exploratory baseline, `git rev-parse HEAD` must equal its `commit`, both before any LLM call, both through `subprocess.run`, exit `3` otherwise.
    - The run loop keeps each run's per-honeypot verdict maps beside the merged one. Observations of the main runs use the merged ground truth. Replays use `_run_single_honeypot` for one server and are observed against that honeypot's own ground truth.
    - After the runs: fewer completed runs than the baseline's `runs` is a mismatch (baseline present only). All runs failed: exit `1` in legacy mode, `3` with a baseline. Compare (exploratory and confirmed), replay per server holding a `FLIP` on a gated cell (confirmed only), one server run per replay shared by its flipped cells, each cell stopping on `rule.decide`, the server stopping once all its cells are decided. A replay that raises adds a mismatch reason. Settle, compute deltas (baseline present), `judge_gate`, fill the report (`passed = verdict == GREEN`, `thresholds` only in legacy mode, else `{}`), write it and `judged_cases.jsonl` as today, then `decide_recording` and `write_baseline` when asked.
    - Exit codes of "Exit codes": `0` green or a written recording, `1` red, `3` not comparable or refused recording.
    - Keep functions near 20 lines: split the post-run composition into named helpers (for example `_select_mode`, `_replay_flips`, `_judge`, `_record`), and group the run state in a small dataclass rather than passing many arguments.
  - `README.md`: the sentence "That change is decided and not built yet." becomes: the paired gate is built, no baseline is recorded yet, and the absolute thresholds stand until the first recording. No number changes.
  - `CLAUDE.md` Commands: add `uv run python -m evals.run_evals --record-baseline` (records `evals/baselines/honeypot_e2e.json` from a clean tree, commit by hand) and `uv run python -m evals.run_evals --ungated` (floors only, any conditions, never in CI).
  - `CONTRIBUTING.md`: the paragraph on recording a baseline (clean tree, exploratory then confirmed at one commit, file committed by hand, never from CI, what `--ungated` is for, and recording under the provider and model settings CI resolves, with no override differing from the defaults). In the commands block at the top, the two flags beside the existing `evals.run_evals` line.
  - `CHANGELOG.md` `[Unreleased]` / `Changed`: the e2e evals gate against a recorded baseline cell by cell once one exists, with absolute floors, linking ADR 016.
- **Test**: no new unit test (the runner needs an LLM, see "Test scenarios"). Existing unit tests stay green.
- **Verify**: the four checks, all clean. `uv run python -m evals.run_evals --record-baseline --ungated; echo $?` prints `3` with no LLM call. `uv run python -m evals.run_evals --help` shows both flags. `wc -l evals/run_evals.py` under 300.

### Step 5: CI at the baseline's conditions

- **Files**: `.github/workflows/evals.yml`, `.github/workflows/eval-command.yml`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do**:
  - Drop `--runs 2 --budget 7` from the `evals.run_evals` invocation in both workflows.
  - In `evals.yml`, after the e2e step, add an `actions/upload-artifact@v7` step with `if: always()` uploading `output/eval_report.json` and `output/judged_cases.jsonl`.
  - In `eval-command.yml`, the e2e step gets `id: e2e`, runs under `set +e`, writes `exit_code` to `$GITHUB_OUTPUT` and exits with it, and "Report result" appends the reason for `1` or `3` to the failure comment, as in "Files to modify".
  - `CONTRIBUTING.md`, under "Running evals on a pull request": `/eval full` runs at the baseline's conditions, 3 runs and budget 10.
  - `CHANGELOG.md` `[Unreleased]` / `Changed`: CI runs the e2e evals at 3 runs and budget 10.
  - Kept as its own commit because it changes the conditions of a gate that is red today: the commit message answers the four questions of ADR 016 (section "Four questions for any change taken while the gate is red"), with the justification that the baseline records one set of conditions and CI must run at them.
- **Test**: none (workflow configuration).
- **Verify**: the four checks, all clean. `grep -n "run_evals" .github/workflows/*.yml` shows no `--runs` or `--budget`.
