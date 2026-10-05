# Judge eval: progress, per-case outcomes and throttled requests

## Context

The judge isolation eval now gates case by case against a confirmed baseline (`evals/baselines/judge_isolation.json`, ADR 025), but its console shows none of the case comparison. A run prints the per-run P/R/F1 table, the per-category table, the protected counts and the verdict. A gated case that flips, is replayed and does not reproduce leaves the gate green, and nothing on screen says it happened: a run on 2026-10-05 had a PASS case judged FAIL in run 2, settled `flip_not_reproduced`, and the console showed only "Gate green.". The 234 judge calls (78 cases, 3 runs) also run with no progress display.

The eval counts no throttled request either. The LLM adapter already counts HTTP 429 per call (`ProviderUsage.throttled_requests`), the e2e evals and the CVE benchmark print the total, but `judge_one_case` drops the usage (`judgment, _ = ...`). A 429 absorbed by the client's retries is invisible, and retries that run out show only as an uncovered observation, which can replay a case or turn the gate red with a reason that does not name the cause. The judge runs 30 calls in flight by default, so this is the eval most exposed to throttling.

This change is display and report only. The gate, the comparison, the replay rule, `JudgeConditions` and the baseline file do not change, so it is not an instrument change: no labeling log entry, no baseline reset.

## Decisions

- Throttling: one yellow line at the first 429 of the session, then the total with the concurrency in the summary and in the JSON report. Not one line per throttled call: at 30 calls in flight a saturated quota would flood the console.
- Replays: the session keeps the raw observation of each replay (pass, fail, uncovered) beside the booleans the gate reads. The JSON report stores them, and the console shows them as letters. A boolean "reproduced" cannot tell a wrong verdict from no verdict.
- No grid. The e2e grid works because cells have two natural axes (tool × category). 78 cases have none. The judge shows a count per outcome and a table of the cases that left `unchanged`.

## Approach

1. The session returns, beside what it returns today, the baseline it read and the raw replay observations.
2. A pure function turns a session result and the fixture into outcome rows and outcome counts. The display renders them.
3. The composition root (`run_judge_eval.py`) wraps the judge call to advance a progress bar and count throttled requests, and adds the concurrency, the throttled total and the replay observations to the report.

## Files to modify

### `evals/judge_session.py`

- `JudgeSessionResult` gains `baseline: JudgeBaseline | None` (the baseline the run read, `None` without one or under `--ungated`) and `replay_observations: dict[str, list[Observation]]` (case id to the observations of its replays, in order, empty when nothing was replayed).
- `_replay(session, case, rule) -> list[Observation]` returns the observations. The boolean list the replay rule and the gate read is derived from them, `[observed != expected for observed in observations]`, at the one place it is needed. `rule.decide_replays` keeps reading booleans.
- `_replay_flips` returns `dict[str, list[Observation]]`. `_gate` derives the `replays: dict[str, list[bool]]` it passes to `JudgeGateInput` and returns the observations alongside the gate result (a small private dataclass or a tuple, the implementer's choice). `run_judge_gate` fills the two new fields.
- The module is already at 310 lines, past the 300-line limit (CLAUDE.md: "When they do, split"), and this change grows it. Split it in this change: move the replay helpers (`_replay_flips`, `_replay`) to a sibling module, `evals/judge_replay.py` (the `evals/` modules are named by concept, with no leading underscore). They read `_Session` today, so the moved functions take what they use instead of the private type, in three arguments or fewer (for example a small frozen dataclass naming what a replay needs: the bounded judge call, the ground truth, the declared keys, the fixture's cases). The implementer picks the grouping, the constraint is no import of a private name across modules.
- `JudgeHarness` gains `on_replays: Callable[[int], None]`, called once with the number of flipped cases about to be replayed, only when that number is above zero. It lets the composition root announce the replays, whose count is not known before the runs. Give it no default: the dataclass is frozen and built in two places (`run_judge_eval.py` and `tests/unit/support/test_judge_session_given.py`).

### `evals/judge_outcomes.py` (new)

Pure, no I/O. Builds what the display shows of the case comparison.

```python
@dataclass(frozen=True)
class JudgeOutcomeRow:
    outcome: CellOutcome
    case: str            # case id
    origin: str          # JudgeCase.origin, e.g. "cell delete_record/input_validation", "cve CVE-2025-53355"
    target: str          # "tool/category" from the case inputs
    label: CaseLabel
    baseline: str        # letters over the baseline runs, e.g. "PPPPPP"
    run: str             # letters over this run, e.g. "PFP"
    replays: str         # letters over the replay observations, "-" when none, e.g. "FPP"
    cause: str           # FlipCause value, "-" when None

def judge_outcome_rows(result: JudgeSessionResult, fixture: JudgeFixture) -> list[JudgeOutcomeRow]: ...
def outcome_counts(result: JudgeSessionResult) -> dict[CellOutcome, int]: ...
```

- `judge_outcome_rows`: one row per case of `result.gate.cases` whose outcome is not `unchanged`, sorted by outcome then case id. Empty when `result.baseline` is `None` (no comparison was made). Letters use the e2e mapping (P pass, F fail, - uncovered). Baseline letters read each baseline run with `run.get(case, Observation.UNCOVERED)`: a baseline recorded on another draw (not comparable, `judge_baseline_integrity` skips the per-case check then) lacks the fixture's new cases, which come out `not_recorded`, and an indexed read would raise `KeyError`.
- `outcome_counts`: the count of each outcome present in `result.gate.cases`, in `CellOutcome` declaration order, zero counts left out.
- The letter mapping lives today in `evals/cell_grid.py` as `_LETTERS` and `_letters(cell, runs)`. Make the mapping reusable: a public `observation_letters(observations: Iterable[Observation]) -> str` in `cell_grid.py`, used by `_letters` there and by `judge_outcomes.py`. `_replays` (a count of booleans) stays in `cell_grid.py` as is: the e2e table keeps its `n/m` form.

### `evals/judge_display.py`

- `print_summary(result, report, report_path, rows, counts)`: after the category table, when `counts` is not empty, one line `Cases: 72 unchanged, 1 flip_not_reproduced, ...`. When `rows` is not empty, a table with columns Outcome, Case, Origin, Target, Label, Baseline, Run, Replays, Cause (no box, `overflow="fold"`, as the e2e outcome table), then the legend line `P pass, F fail, - no verdict`. When `report["throttled_requests"] > 0`, the yellow line `Throttled by the model provider: N requests at concurrency C`, as the e2e summary words it.
- Five arguments exceed the project's limit (aim for 3 or fewer): group `rows` and `counts` in a frozen `CaseOutcomes` dataclass defined in `judge_outcomes.py`, built by one function `case_outcomes(result, fixture) -> CaseOutcomes`, and the signature becomes `print_summary(result, report, report_path, outcomes)`. `print_summary` already takes three, so this is the smallest grouping that names a concept.

### `evals/run_judge_eval.py`

- `judge_one_case(llm, case) -> tuple[EvalVerdict | None, ProviderUsage]`: returns the usage of the call, the one `generate_structured` returns, or `error.usage` on `UnparseableOutput` and `ProviderRefusal`. Its docstring rule (any other failure propagates) stands.
- `_evaluate` builds a counter and a progress bar around `asyncio.run(run_judge_gate(...))`:
  - `SessionThrottles` (`evals/metrics.py`) gains `count_usage(usage: ProviderUsage) -> int`, and `count(report)` becomes `return self.count_usage(report.provider_usage)`. The judge closure calls `count_usage`.
  - The closure prints, through the progress console, `The model provider throttled a judge call (HTTP 429), the total is in the summary.` in yellow the first time a call comes back throttled, and never again in the session.
  - A `rich.progress.Progress` on `display.console`, one task `Judging` with total `runs × len(fixture.cases)`, advanced by the closure on each call. `on_replays(count)` adds a second task `Replaying N flipped case(s)` with no total, which the closure advances once the run calls are done (the closure advances the replay task when the first task is complete). The progress context closes before `print_summary`.
  - `_evaluate` is already about 30 lines, and functions should rarely exceed 20 (CLAUDE.md, "When they do, split"). The counter, the first-429 warning and the two progress tasks are one concept, the judge calls' tracking: put them in a named unit of `run_judge_eval.py` (a small class, e.g. `JudgeCallTracking`, exposing the wrapped judge call and `on_replays`), placed below `_evaluate` per the newspaper rule, so `_evaluate` builds it and stays short.
- `_build_report` adds three keys: `"concurrency"`, `"throttled_requests"`, and `"replay_observations"` (case id to the list of observation values). None of them enters `"conditions"`. `"replay_observations"` comes from the session result, so `_build_report(result, fixture)` adds it. The other two are known only to `_evaluate` (`options.concurrency`, the counter's `requests`): `_evaluate` merges them into the report it got back, rather than growing `_build_report` to four arguments.
- `_evaluate` passes the `CaseOutcomes` from `judge_outcomes` to `print_summary`.

### Living docs

- `CHANGELOG.md` `[Unreleased]`: under `### Added`, one entry: the judge eval shows its progress, a count per case outcome and a table of the cases that left `unchanged` (baseline and run observations, replays, cause), warns at the first throttled request and prints the total with the concurrency, and its report records `concurrency`, `throttled_requests` and `replay_observations`.
- `CONTRIBUTING.md`, section "The judge isolation eval": one sentence after the paragraph on what gates, naming the outcome table and the throttled count. The report key list there (`output/judge_eval_report.json`) gains the three keys if it lists keys.
- `README.md` and `CLAUDE.md`: no change expected (no command, flag or env var changes). The implementer checks and leaves them if nothing is stale.

## What stays unchanged

- `evals/judge_gate.py`, `evals/gate.py`, `ReplayRule`, `JudgeConditions`, `evals/judge_baseline.py`, `evals/judge_recording.py`, the baseline file and its format. The gate still receives booleans.
- The exit codes, the refusal paths, the recording output (`_print_written`), the declarations lines, the reasons panel.
- The e2e display and its outcome table (`OutcomeRow`, `_outcome_table`, `_replays`): only the letter mapping moves to a public function, with the same letters.
- `SessionThrottles.count(report)` keeps its behavior for the e2e evals and the CVE benchmark.
- No new CLI flag.

## Edge cases

- No baseline, or `--ungated`: `result.baseline` is `None`, `gate.cases` is empty, no count line and no table. The progress bar and the throttle line still show.
- Exploratory baseline: the gate runs on the floors, but the cases are still compared (`_settled_cases`). Show the counts and rows as computed, with no replays, as the e2e does against an exploratory baseline.
- Not comparable (conditions differ): cases are compared without replay, so `flip` rows can show with `-` replays. Render as is.
- A case labeled `unspecified` stays out of the comparison, so it never appears in `gate.cases` nor in the rows.
- A replay whose call raised `UnparseableOutput` or `ProviderRefusal` shows `-` in the replay letters, and its usage is counted.
- No flipped case: `on_replays` is not called, no second progress task.
- `--runs 1` or another concurrency: totals follow `runs × cases` and the concurrency in the report follows `--concurrency`.

## Test scenarios

Test first. Fakes as in the existing judge session tests (`ScriptedJudge`).

`tests/unit/test_judge_session.py`:
- A run against a confirmed baseline returns that baseline in the result. A run with no baseline file returns `None`.
- A flipped case replayed until it reproduces returns its replay observations in order (for example `[FAIL, FAIL, FAIL, FAIL]` for a PASS case judged FAIL), and a replay whose judge call raised returns `UNCOVERED` at that position. The gate outcome is unchanged from today's tests.
- `on_replays` is called once with the number of flipped cases, and not at all when nothing flipped.

`tests/unit/test_judge_outcomes.py` (new). Building a `JudgeSessionResult` with a baseline, runs, replay observations and gate cases, and a matching fixture, abstracts real setup: it goes in `tests/unit/support/test_judge_outcomes_given.py` (per CLAUDE.md, Given/When/Then, and where the existing `_given.py` files live). Assertions stay inline unless one actually abstracts something, then `tests/unit/support/test_judge_outcomes_then.py`.
- Rows list only the cases that left `unchanged`, with origin, `tool/category`, label, baseline letters, run letters, replay letters and cause.
- A case with no replay shows `-` for replays, a comparison with no cause shows `-` for cause.
- No baseline gives no rows and no counts.
- Counts follow `CellOutcome` order and leave out zeros.

`tests/unit/test_eval_metrics.py`:
- `count_usage` adds the throttled requests and the usage, and `count(report)` still gives today's results (the existing tests stay).

`tests/unit/test_judge_session.py` (already holds the `judge_one_case` tests):
- `judge_one_case` returns the usage of a successful call, and the usage carried by `UnparseableOutput` and by `ProviderRefusal` with a `None` verdict. The existing `test_a_judge_call_that_fails_to_answer_is_uncovered` asserts `... is None` on the bare return and must be rewritten for the tuple (give the parametrized errors a non-empty usage, e.g. `ProviderUsage(throttled_requests=1)`, so the test tells the carried usage from a default one).
- `given.a_harness` (`tests/unit/support/test_judge_session_given.py`) gains an `on_replays` parameter defaulting to a no-op, so the existing session tests stay as they are and the new test passes a recorder.

Display: `tests/unit/test_eval_display.py` captures console output through `given.a_captured_console(monkeypatch)`, which patches `eval_display.console`. `judge_display` binds `console` at import (`from evals.eval_display import console`), so that helper does not capture it: a new `tests/unit/test_judge_display.py` with its `tests/unit/support/test_judge_display_given.py`, whose `a_captured_console(monkeypatch)` patches `judge_display.console` the same way (`monkeypatch.setattr(judge_display, "console", Console(file=buffer, width=200))`) and returns the buffer, and which builds the session result, report and `CaseOutcomes` the summary takes (Given/When/Then per CLAUDE.md, as `test_eval_display_given.py` does). Two tests: a summary with rows prints the case id and the outcome, and a throttled total above zero prints the throttle line.

## Verification

```bash
uv run pytest tests/unit -n auto
uv run pytest tests/integration -n auto
uv run pyright
uv run ruff check .
uv run ruff format --check .
uv run python -m evals.run_judge_eval   # needs OPENAI_API_KEY: progress bar, count line, gate green against the committed baseline
```

The last run should show the progress bar, the `Cases:` line and, if any case left `unchanged`, the table. `output/judge_eval_report.json` should hold `concurrency`, `throttled_requests` and `replay_observations`, and `conditions` should be unchanged.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, for the implementation-phase fact check. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `rich.progress.Progress(console=...)`, `Progress.add_task(description, total=None)` for a task with no total, and `Progress.advance(task_id)` (verified against the installed `rich` 14.3.3, the version `uv.lock` pins, by signature inspection)
- SETTLED: `Table.add_column(..., overflow="fold")` (verified against the installed `rich` 14.3.3 signature, and already used in `evals/eval_display.py`)
- SETTLED: HTTP 429 as the throttled status the adapter counts in `ProviderUsage.throttled_requests` (standard status code, and the existing counter the e2e and CVE displays already read)

## Implementation steps

Verification commands (CLAUDE.md): `uv run pytest tests/unit -n auto`, `uv run pytest tests/integration -n auto`, `uv run pyright`, `uv run ruff check .`, `uv run ruff format --check .`.

### Step 1: session returns the baseline and replay observations, `judge_one_case` returns its usage

- **Files**: `tests/unit/test_judge_session.py`, `tests/unit/support/test_judge_session_given.py`, `tests/unit/test_eval_metrics.py`, `evals/judge_session.py`, `evals/judge_replay.py` (new), `evals/metrics.py`, `evals/run_judge_eval.py`
- **Do**:
  - Tests first. `given.a_harness` gains `on_replays: Callable[[int], None] = lambda _: None`, passed to `JudgeHarness`. Write the session tests, the `judge_one_case` tests (rewrite `test_a_judge_call_that_fails_to_answer_is_uncovered` for the tuple, the parametrized errors carrying `ProviderUsage(throttled_requests=1)`) and the `count_usage` test listed below, run them, confirm they fail.
  - `evals/judge_session.py`: `JudgeSessionResult` gains `baseline: JudgeBaseline | None` and `replay_observations: dict[str, list[Observation]]`. `JudgeHarness` gains `on_replays: Callable[[int], None]`, no default. `_gate` derives the `replays: dict[str, list[bool]]` for `JudgeGateInput` (`[observed != expected for observed in observations]`) and returns the observations beside the gate result (private dataclass or tuple). `run_judge_gate` fills the two new fields (`baseline` is `None` with no baseline file or under `--ungated`, `replay_observations` empty when nothing was replayed).
  - `evals/judge_replay.py` (new): move `_replay_flips` and `_replay` there as public functions returning observations (`dict[str, list[Observation]]` and `list[Observation]`). They no longer take `_Session`: a small frozen dataclass names what a replay needs (bounded judge call, ground truth, declared keys, fixture cases), three arguments or fewer, no import of a private name across modules. `rule.decide_replays` keeps reading booleans, derived from the observations at the one place needed. `on_replays(count)` is called once with the number of flipped cases about to be replayed, only when it is above zero. `judge_session.py` ends at or below 300 lines.
  - `evals/metrics.py`: `SessionThrottles.count_usage(usage: ProviderUsage) -> int` adds the throttled requests and the usage, `count(report)` becomes `return self.count_usage(report.provider_usage)`.
  - `evals/run_judge_eval.py`: `judge_one_case(llm, case) -> tuple[EvalVerdict | None, ProviderUsage]`, the usage of `generate_structured`, or `error.usage` on `UnparseableOutput` and `ProviderRefusal` (any other failure propagates, docstring kept). The `_evaluate` closure unpacks the tuple and keeps the verdict for now. Pass `on_replays=lambda _: None` to `JudgeHarness` for now (step 3 replaces it).
- **Test**:
  - A run against a confirmed baseline returns that baseline in the result. A run with no baseline file returns `None`.
  - A PASS case judged FAIL and replayed until it reproduces returns `[FAIL, FAIL, FAIL, FAIL]` (or the replay count the rule gives) in `replay_observations`, a replay whose judge call raised gives `UNCOVERED` at that position. Gate outcomes unchanged from today's tests.
  - `on_replays` is called once with the number of flipped cases, and not at all when nothing flipped.
  - `judge_one_case` returns the usage of a successful call, and the usage carried by `UnparseableOutput` and `ProviderRefusal` with a `None` verdict.
  - `count_usage` adds the throttled requests and the usage, existing `count(report)` tests stay green.
- **Verify**: all five commands green.

### Step 2: pure case outcomes and the shared letter mapping

- **Files**: `tests/unit/test_judge_outcomes.py` (new), `tests/unit/support/test_judge_outcomes_given.py` (new), `evals/cell_grid.py`, `evals/judge_outcomes.py` (new)
- **Do**:
  - Tests first in `tests/unit/test_judge_outcomes.py`. The given module builds a `JudgeSessionResult` (baseline, runs, replay observations, gate cases) and a matching `JudgeFixture`. Assertions inline unless one abstracts something (then `tests/unit/support/test_judge_outcomes_then.py`).
  - `evals/cell_grid.py`: public `observation_letters(observations: Iterable[Observation]) -> str` (P pass, F fail, - uncovered), used by `_letters`. `_replays` unchanged, e2e letters unchanged.
  - `evals/judge_outcomes.py`: `JudgeOutcomeRow` (outcome, case, origin, target, label, baseline, run, replays, cause), `CaseOutcomes` frozen dataclass (`rows: list[JudgeOutcomeRow]`, `counts: dict[CellOutcome, int]`), `judge_outcome_rows(result, fixture)`, `outcome_counts(result)`, `case_outcomes(result, fixture) -> CaseOutcomes`. Rows: cases of `result.gate.cases` not `unchanged`, sorted by outcome then case id, empty when `result.baseline is None`. Baseline letters read `run.get(case, Observation.UNCOVERED)`. Replays `-` when none, cause `-` when `None` (else the `FlipCause` value). Target `tool/category` from the case inputs. Counts in `CellOutcome` declaration order, zeros left out.
- **Test**:
  - Rows list only the cases that left `unchanged`, with origin, `tool/category`, label, baseline letters, run letters, replay letters and cause.
  - A case with no replay shows `-` for replays, a comparison with no cause shows `-` for cause.
  - A baseline lacking a fixture case (not comparable draw) reads `-` letters for it, no `KeyError`.
  - No baseline gives no rows and no counts.
  - Counts follow `CellOutcome` order and leave out zeros.
- **Verify**: all five commands green (existing `cell_grid`/e2e display tests unchanged).

### Step 3: display, progress, throttle tracking, report keys and living docs

- **Files**: `tests/unit/test_judge_display.py` (new), `tests/unit/support/test_judge_display_given.py` (new), `evals/judge_display.py`, `evals/run_judge_eval.py`, `CHANGELOG.md`, `CONTRIBUTING.md`
- **Do**:
  - Tests first. The given module: `a_captured_console(monkeypatch)` patches `judge_display.console` with `Console(file=buffer, width=200)` and returns the buffer, plus builders for the session result, the report dict and `CaseOutcomes`.
  - `evals/judge_display.py`: `print_summary(result, report, report_path, outcomes: CaseOutcomes)`. After the category table: the `Cases: 72 unchanged, 1 flip_not_reproduced, ...` line when counts are not empty. When rows are not empty, a table (no box, `overflow="fold"`, as the e2e outcome table) with columns Outcome, Case, Origin, Target, Label, Baseline, Run, Replays, Cause, then `P pass, F fail, - no verdict`. When `report["throttled_requests"] > 0`, the yellow line `Throttled by the model provider: N requests at concurrency C`, worded as the e2e summary.
  - `evals/run_judge_eval.py`: a named unit below `_evaluate` (e.g. `JudgeCallTracking`) holding a `SessionThrottles`, the first-429 flag and a `rich.progress.Progress` on `display.console`. It exposes the wrapped judge call (calls `judge_one_case`, `count_usage`, prints once in yellow `The model provider throttled a judge call (HTTP 429), the total is in the summary.` through the progress console, advances `Judging` (total `runs × len(fixture.cases)`), or the replay task once the first task is complete) and `on_replays(count)` adding a task `Replaying N flipped case(s)` with no total. `_evaluate` builds it, passes `on_replays` to `JudgeHarness` (replacing step 1's no-op), closes the progress before `print_summary`, merges `"concurrency"` (`options.concurrency`) and `"throttled_requests"` into the report, and passes `case_outcomes(result, fixture)`. `_evaluate` stays around 20 lines. `_build_report` adds `"replay_observations"` (case id to list of observation values). None of the three keys enters `"conditions"`.
  - `CHANGELOG.md` `[Unreleased]` `### Added`: one entry as the plan words it. `CONTRIBUTING.md` "The judge isolation eval": one sentence after the paragraph on what gates, naming the outcome table and the throttled count, and the three report keys if a key list exists. Check `README.md` and `CLAUDE.md`, leave them if nothing is stale.
- **Test**:
  - A summary with rows prints the case id and the outcome.
  - A throttled total above zero prints the throttle line.
- **Verify**: all five commands green. Manually, if `OPENAI_API_KEY` is available: `uv run python -m evals.run_judge_eval` shows the progress bar, the `Cases:` line, gate green, and `output/judge_eval_report.json` holds `concurrency`, `throttled_requests`, `replay_observations` with `conditions` unchanged.
