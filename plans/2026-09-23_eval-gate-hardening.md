# Eval gate hardening

## Context

The paired eval gate (`plans/2026-09-23_paired-eval-gate.md`, commits `9f7df6f..3487602`) went through two reviews after implementation, one on robustness and one on code standards and architecture. No baseline is recorded yet, so CI still gates on the legacy thresholds. The reviews found paths where the gate gives a wrong answer silently, a dead end in the recording procedure, and pure logic that the new I/O modules absorbed without tests. This plan fixes all of them before the first baseline is recorded, which is the moment these checks start to matter.

Findings addressed, by source:

- Robustness: (R1) legacy mode ignores failed runs, so one surviving run can pass the thresholds and exit `0`. (R2) the baseline file's content is not checked against what it claims: a cell removed by hand is never gated, `runs: []` or a malformed key crashes after every LLM call. (R3) the recording procedure dead-ends: the tool says "Commit the file by hand" after the exploratory recording, and committing moves `HEAD`, which then refuses the confirming recording. (R4) any uncaught exception exits `1`, which the `/eval full` comment reads as "e2e red". (R5) a delta of exactly one case is marked inconclusive by float error, and the precision resolution assumes balanced runs. (R6) a CRLF checkout changes every source fingerprint. (R7) a pull request can edit or delete its own baseline, and the `/eval` comment does not say which mode gated it.
- Standards: (S1) the replay loop, which turns a flip into a regression, calls the audit directly and has no test. (S2) pre-run refusal rules are interleaved with `git` calls, `refuse` prints and exits from a library module, `_select_mode` has no test. (S3) the "exploratory baseline at another commit" rule is written twice with two messages. (S4) `GateInput(mode=LEGACY_THRESHOLDS)` without thresholds judges green silently, and the thresholds are copied into a test given. (S5) a test hardcodes the default model name. (S6) `_disagreements` ignores cells unstable in the first recording, with no test pinning it. (S7) ceremony: a public single-use constant paraphrased by a second message, a paraphrasing docstring, `ReplayPlan`, a test that only checks pydantic construction. (S8) the reproduced/cleared count is computed twice. (S9) gated-set changes travel as an anonymous tuple. (S10) two exit styles: `run_evals` raises `SystemExit` mid-flow, `_record` returns a code. (S11) test givens duplicate the cells and ground truth, and `test_eval_gate_verdict.py` borrows the given of `test_eval_gate.py`.

## Approach

Three commits, in this order, each test-first.

1. **Verdicts and exit codes** (R1, R2, R3, R4, R7, S10). Everything that can change a verdict, an exit code or what CI tells a reviewer. Exit handling moves into `main`: refusals travel as a dedicated exception, crashes exit `4`.
2. **Testability** (S1, S2, S3, S5, S6, S8). The replay loop takes the audit as an injected callable, the session rules become pure functions over a `TreeState` value object read once, and the missing tests land.
3. **Cleanup** (R5, S4, S7, S9, S11). Changes that move no verdict: thresholds beside the floors, deltas, ceremony, test support. R6 needs no change (see Commit 3).

Under ADR 016 all three are changes to the instrument's tooling, not to the system under test, and every one refuses more or reports more without loosening anything. Commit 1 changes the legacy verdict on incomplete runs while the gate is red, so its message answers the four questions of ADR 016. Commits 2 and 3 carry one line saying they move no verdict.

### Exit codes (revised)

`0` green, or a written recording. `1` red. `3` not comparable or refused: any mismatch, fewer completed runs than requested in any mode, a baseline file that fails validation or integrity, a refused recording, a failed `git` call. `4` crashed: an exception escaped the runner, the traceback is printed. `2` stays with `argparse`. This extends the contract of the paired-gate plan: it adds `4`, and incomplete runs now make legacy mode not comparable too, where that plan left legacy unchanged.

## Files to modify

### Commit 1: verdicts and exit codes

**`evals/eval_session.py`**

- `class Refused(Exception)` with `title: str` and `reasons: list[str]`. Replaces `refuse()`: the module no longer prints or exits. `open_session` and `git()` raise it.
- `_load_committed_baseline()` raises `Refused` on a `ValidationError` (unchanged message) and also when `baseline_integrity(baseline, MERGED_GROUND_TRUTH)` returns problems, title `"Refused before any LLM call."`.

**`evals/baseline.py`**

- `baseline_integrity(baseline: Baseline, ground_truth: GroundTruth) -> list[str]`, pure. Problems, one line each:
  - `runs` is empty, or `len(runs) != conditions.runs`: `"the baseline holds {n} runs, its conditions claim {runs}"`.
  - a key that `parse_cell_key` rejects (`ValueError`, or an unknown category): `"run {i}: unreadable cell key {key!r}"`.
  - a run whose parsed keys differ from `ground_truth`'s keys: `"run {i}: cells {missing} missing, {extra} unknown"` (sorted `cell_key`s, a side omitted when empty). Checked only when `baseline.conditions.ground_truth_fingerprint == fingerprint_ground_truth(ground_truth)`: after a ground truth revision every run differs, and `condition_mismatches` already refuses it with the fingerprint line, which names the real cause.
- Kept outside the pydantic model on purpose: the ground truth is a runner constant, and the file is validated against it only when the runner loads it.

**`evals/run_evals.py`**

- `main()` is the only place that exits:
  ```python
  def main() -> None:
      options = _parse_args()
      try:
          code = _evaluate(options)
      except Refused as refusal:
          display.print_refusal(refusal.title, refusal.reasons)
          code = NOT_COMPARABLE_EXIT
      except Exception:
          traceback.print_exc()
          code = CRASHED_EXIT
      raise SystemExit(code)
  ```
  `_evaluate(options) -> int` holds today's body of `main` (session, `asyncio.run`, report, judged cases, summary, then `_record` or `EXIT_CODES`). `CRASHED_EXIT = 4` lives beside `NOT_COMPARABLE_EXIT` in `eval_session.py`. `SystemExit` from `argparse` and `KeyboardInterrupt` are not `Exception` and pass through.
- `run_evals`: "all runs failed" raises `Refused("All runs failed.", ["no run completed: nothing to judge"])` instead of printing and raising `SystemExit`. Exit `3` in every mode.
- `_judge`: `_incomplete_runs(requested: int, completed: int)` compares against `session.conditions.runs` (the runs requested) and applies in every mode, with a message that no longer names a baseline: `"{completed} of {requested} runs completed"`, `--ungated` included. The legacy and floors-only-without-baseline branch passes those mismatches to `judge_gate` too. With a baseline, `session.conditions.runs` equals `baseline.conditions.runs` (the pre-run condition check guarantees it outside `--ungated`), so paired and exploratory behave as today. Replays are still skipped when a mismatch exists.
- `_record` returns `0` or raises `Refused` for a refused recording and for tree drift, instead of printing and returning `3`. It keeps its `assert session.commit is not None` narrowing (pyright strict needs it, `Recording.commit` is `str`): a failed assert is a programming error and now exits `4`. (Its drift check moves to the pure `tree_drift` of commit 2, it keeps calling `git` until then.)

**`evals/eval_display.py`**

- `print_written_recording`: the closing line depends on the status. Exploratory: `"Run --record-baseline again now, at this commit and before committing, to confirm it. Commit the file once confirmed."` Confirmed: `"Commit the file by hand."` The exploratory file is untracked until committed, and `git status --untracked-files=no` ignores it, so the confirming run starts from a clean tree at the same `HEAD`.

**`.github/workflows/eval-command.yml`**, "Report result"

- New case `4) reason=": e2e crashed (see the log)" ;;`.
- When `output/eval_report.json` exists, append the gate mode and the baseline status to both comments, read with `jq`: `gate="$(jq -r '.gate.mode + (if .gate.baseline_status then ", baseline " + .gate.baseline_status else "" end)' output/eval_report.json)"`, then `" Gate: $gate."`. The file is written only by this run (fresh checkout, `output/` is gitignored), so it cannot be stale. A reviewer sees when a pull request's own baseline edit changed the mode, without a new rule.

**`.github/workflows/evals.yml`**: unchanged (the job fails on any non-zero code).

**Docs**

- `CONTRIBUTING.md`, "Recording an e2e baseline": replace "Commit the file by hand." with the procedure: record, run `--record-baseline` again at the same commit before committing, then commit the confirmed file. Mention that a crash exits `4` and that the `/eval full` comment names the gate mode.
- `CHANGELOG.md` `[Unreleased]`, the existing paired-gate bullet: fewer completed runs than requested is not comparable in every mode, a crash exits `4`.

### Commit 2: testability

**`evals/gate.py`**

- `ReplayRule.decide_replays(self, replays: list[bool]) -> bool | None`, counting reproduced and cleared then calling `decide`. `settle` and the replay loop call it.

**`evals/replay.py`**

- `ReplayAudit = Callable[[HoneypotConfig], Awaitable[VerdictMap]]`.
- `@dataclass(frozen=True) class Replayer` with `audit: ReplayAudit`, `rule: ReplayRule`, `honeypots: list[HoneypotConfig]`, and `async def settle_flips(self, cells: dict[Cell, CellComparison]) -> tuple[dict[Cell, CellComparison], list[str]]`. Same behavior as today's `replay_flips`: one server run per replay shared by its undecided flipped cells, stop when every cell decides or `rule.replays` is spent, observe against the honeypot's own ground truth, a raising audit adds `"a replay of {name} failed"`. `ReplayPlan` and the dependency on `eval_session` go.
- `run_evals._judge` builds `Replayer(audit=..., rule=baseline.replay_rule, honeypots=HONEYPOTS)` where `audit` wraps `audit_honeypot(session.settings, honeypot, session.conditions.budget)` in `aggregate_verdicts`.

**`evals/eval_session.py`**

- `@dataclass(frozen=True) class TreeState: commit: str, dirty: bool`, and `read_tree() -> TreeState` (the only `git` caller left, via `git()`).
- `EvalSession.commit: str | None` becomes `tree: TreeState | None`, read in `open_session` when recording.
- Pure, public, tested: `select_mode(baseline, ungated) -> GateMode` (renamed from `_select_mode`), `pre_run_refusals(session: EvalSession) -> list[str]` (condition mismatches, CI conditions, dirty tree, exploratory commit, all from `session` alone), `tree_drift(before: TreeState, after: TreeState) -> list[str]`. `open_session` raises `Refused` when `pre_run_refusals` is non-empty. `_record` calls `tree_drift(session.tree, read_tree())`, after narrowing `session.tree` with the same `assert` as today's `session.commit`.

**`evals/recording.py`**

- `exploratory_commit_refusal(baseline: Baseline, commit: str) -> list[str]`, public, the single wording of the rule. `_refusals` and `pre_run_refusals` both call it. Wording: `"the exploratory baseline was recorded at {baseline.commit}, this run at {commit}: confirm it at its own commit, or delete it in a commit of its own"`.

**Tests**

- `tests/unit/test_eval_replay.py` + `tests/unit/support/test_eval_replay_given.py`: a fake audit (`async def` returning scripted `VerdictMap`s per call, or raising), two small `HoneypotConfig`s with their own ground truths (the `server` path is never opened).
- `tests/unit/test_eval_session.py` + new `tests/unit/support/test_eval_session_given.py`: CI conditions built from `Settings.model_construct()` (`resolve_model()`, `resolve_judge_model()`), never a literal model name. An `EvalSession` built with `Settings.model_construct()`.
- `tests/unit/test_eval_baseline.py`: the disagreement test of S6.

### Commit 3: cleanup

- `evals/gate.py`: `LEGACY_THRESHOLDS` moves here from `run_evals.THRESHOLDS`, beside `FLOORS`.
- `evals/gate_verdict.py`: `GateInput.thresholds` is removed, `judge_gate` reads `LEGACY_THRESHOLDS` in legacy mode (S4: a legacy input can no longer lack thresholds). The `GateInput` docstring keeps only its second sentence. `run_evals` fills `EvalReport.thresholds` with `LEGACY_THRESHOLDS if gate.mode == GateMode.LEGACY_THRESHOLDS else {}`, once (the report schema is unchanged).
- `evals/gate.py`, deltas (R5): `inconclusive = abs(value) < resolution and not math.isclose(abs(value), resolution)`. Precision resolution: `max` over the runs that predict at least one FAIL of `1 / (runs × that run's predicted FAILs)`, `1.0` when none does. Docstring of `metric_resolutions` updated to say the precision figure is the largest single-case move across runs.
- `fingerprint_source` (R6): no change. The runner reads each honeypot with `Path.read_text()`, which opens in text mode with universal newlines, so a CRLF checkout already reaches `fingerprint_source` as `\n` and fingerprints alike (checked by hand: a CRLF file read back through `read_text` gives the `\n` fingerprint). Dropping the `NEWLINE` token's string would not have been enough anyway: a multi-line string literal carries its line endings inside its `STRING` token.
- `evals/recording.py`: `MODEL_CHANGE_PROCEDURE` becomes private `_MODEL_CHANGE_PROCEDURE`, and `_other_conditions` reuses it rather than paraphrasing it: `"conditions differ from the exploratory baseline (...): delete it in a commit of its own and record a new one, and if a model differs, " + _MODEL_CHANGE_PROCEDURE`. `class GatedSetChange(BaseModel): entering: list[str], leaving: list[str]` replaces the tuple of `gated_set_changes`, and `eval_display.print_written_recording` takes it.
- Tests: `test_a_replay_rule_within_its_bounds_is_accepted` is deleted. `test_eval_gate_verdict.py` gets its own `tests/unit/support/test_eval_gate_verdict_given.py` (`metrics`, `cells_with`), and imports `LEGACY_THRESHOLDS` from `evals.gate` instead of a copy. `test_eval_baseline_given.py` imports `VULNERABLE_CELL`, `SAFE_CELL` and `a_ground_truth` from `test_eval_gate_given.py` instead of redefining them. Tests referencing `MODEL_CHANGE_PROCEDURE` by name assert on the message text.

## What stays unchanged

- The comparison table, `classify`, the replay rule values (5 and 4), the floors (0.50), the recording status rules, the fingerprinted fields and the report schema (`EvalReport` fields).
- `evals.yml`, the judge isolation eval, the CVE benchmark, anything under `src/`, the honeypots and the ground truth.
- No baseline is recorded by this work.
- Per-metric floors and legacy threshold values.

## Edge cases

- Legacy mode, 2 of 3 runs completed: not comparable, exit `3` (was green or red on the surviving runs).
- `--ungated --runs 1`, the run raises: all runs failed, exit `3`.
- Every run raises: exit `3` in every mode (legacy was `1`).
- Baseline file with a cell removed from one run, with `runs: []`, with a key `"get_user"` (no `/`), with a key `"get_user/unknown"`, with 2 runs under `conditions.runs = 3`: refused before any LLM call, exit `3`.
- A honeypot source that fails to tokenize (`tokenize.TokenError` or `IndentationError` in `fingerprint_source`): uncaught, exit `4`, "e2e crashed". It is a broken fixture, not a comparison question.
- An invalid `MCP_AUDITOR_PROVIDER`: `ValueError` from `resolve_model`, exit `4`.
- Exploratory recording then immediate second recording, file uncommitted: the tree reads clean (untracked file), `HEAD` unchanged, the confirming run proceeds.
- `/eval` in judge-only mode: no e2e step, no report, the comment carries no gate line.
- `/eval full` where the run was refused before any LLM call: no report file, reason `3`, no gate line.
- Precision resolution with a run predicting no FAIL: that run is skipped in the `max`. All runs predicting none: `1.0`.

## Test scenarios

Commit 1:

- `baseline_integrity` (in `tests/unit/test_eval_baseline.py`, beside the other `evals.baseline` tests): a consistent baseline gives `[]`. A run missing a ground-truth cell names it. A run with an extra cell names it. `runs: []` and a run-count mismatch are named. An unreadable key is named, not raised. A baseline whose ground truth fingerprint differs from the current one gets no cell-set line.
- `judge_gate` with `mismatches` from incomplete runs in legacy mode gives `NOT_COMPARABLE` (covered by the existing mismatch test, one more for legacy mode explicitly).
- No unit test for `main`, the workflow or the display (runner needs an LLM, per the paired-gate plan). Manual checks in Verification.

Commit 2:

- `Replayer.settle_flips` with a fake audit:
  The audit count is asserted on purpose, an exception to the rule against asserting on call sequences: stopping as soon as every cell decides is specified behavior, each audit is a paid server run, and a loop that always spent `rule.replays` would give the same verdicts and pass outcome-only tests. The fake audit counts its calls.
  - a cell reproduced 4 times becomes `REGRESSION` after exactly 4 audits.
  - a cell cleared twice becomes `FLIP_NOT_REPRODUCED` after exactly 2 audits.
  - two flipped cells on one server share each audit, and the server stops once both decide.
  - a flipped cell on each of two servers: each server is audited on its own.
  - the replay observes against the server's own ground truth: a cell of the other server is not read as uncovered.
  - an audit that raises leaves the cell `FLIP` and returns `"a replay of {name} failed"`.
  - no flip: no audit call.
- `ReplayRule.decide_replays` (in `tests/unit/test_eval_gate.py`): `[True]*4` gives `True`, `[False]*2` gives `False`, `[True]*3 + [False]` gives `None`.
- `select_mode`: ungated gives `FLOORS_ONLY` even with a confirmed baseline, no baseline gives `LEGACY_THRESHOLDS`, exploratory gives `FLOORS_ONLY`, confirmed gives `PAIRED`.
- `pre_run_refusals`: no baseline, not recording, gives `[]`. A baseline at other conditions names the mismatch. Recording on a dirty tree is refused. Recording at other CI conditions is refused. Recording over an exploratory baseline at another commit is refused with the shared wording.
- `tree_drift`: same state gives `[]`, a dirty `after` is named, a moved commit names both commits.
- `ci_condition_mismatches`: the existing three tests, rebuilt on the session given, with the model assertion relative to `Settings.model_construct()`.
- `decide_recording`: a cell unstable in the exploratory baseline and stable-correct in the second recording does not count as a disagreement, and the recording confirms.

Commit 3:

- `metric_deltas`: a recall delta of exactly one case (`-1/33` computed as a difference of two averages) is conclusive. A delta of half a case is inconclusive.
- `metric_resolutions`: with runs predicting 1 and 9 FAILs, precision resolution is `1/2` (`1 / (2 × 1)`).
- `judge_gate` legacy mode red on a missed `LEGACY_THRESHOLDS` value, without passing thresholds.
- `gated_set_changes` returns a `GatedSetChange` (existing tests adapted).

## Verification

Each commit: `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all clean.

Commit 1, by hand, none of them calls an LLM:

- `mkdir -p evals/baselines && echo '{"broken": true' > evals/baselines/honeypot_e2e.json && uv run python -m evals.run_evals; echo $?` prints the refusal and `3`. Remove the directory after.
- A syntactically valid baseline whose runs miss a ground-truth cell: refused, `3`.
- `MCP_AUDITOR_PROVIDER=nope uv run python -m evals.run_evals; echo $?` prints a traceback and `4`.
- `uv run python -m evals.run_evals --record-baseline --ungated; echo $?` still prints `3`.
- `jq --version` locally, and the `jq` expression of the workflow run against a hand-written `eval_report.json` with and without `baseline_status`.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, once, on 2026-09-23. Later passes read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded then, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `jq` is preinstalled on `ubuntu-latest` (maps to Ubuntu 24.04, image readme lists jq 1.7) (verified against github.com/actions/runner-images README and images/ubuntu/Ubuntu2404-Readme.md)
- SETTLED: `jq -r '.gate.mode + (if .gate.baseline_status then ", baseline " + .gate.baseline_status else "" end)' output/eval_report.json` prints `paired, baseline confirmed` and `legacy_thresholds` for a null status, matching `GateResult.mode` / `GateResult.baseline_status` in `evals/gate_verdict.py` (verified by a local run with jq 1.7)
- SETTLED: `Path.read_text()` opens in text mode with universal newlines, so a CRLF file (a multi-line string literal included) reads back with `\n` only (verified by a local Python 3 run)

## Implementation steps

Commit 2 of the Approach is cut in two steps (replay, then session rules): together they carry about 25 test cases over 11 files, past what one implementer session holds. The result is four commits, in the Approach's order. Every step runs, before committing: `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all clean.

### Step 1: verdicts and exit codes (commit 1)

- **Files**: `tests/unit/test_eval_baseline.py`, `tests/unit/support/test_eval_baseline_given.py`, `tests/unit/test_eval_gate_verdict.py`, `evals/baseline.py`, `evals/eval_session.py`, `evals/run_evals.py`, `evals/eval_display.py`, `.github/workflows/eval-command.yml`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do**:
  1. Tests first. In `test_eval_baseline.py`, the `baseline_integrity` scenarios of "Test scenarios, Commit 1". The given needs a baseline consistent with `a_ground_truth()`: `len(runs) == conditions.runs` and `ground_truth_fingerprint == fingerprint_ground_truth(a_ground_truth())` (today's `a_baseline` holds 2 runs under `runs=3` and fingerprint `"def"`). Add parameters to the existing givens rather than a parallel builder. Raw keys (`"get_user"`, `"get_user/unknown"`) go straight into `Baseline(runs=...)` since `baseline_integrity` must report them, not raise. In `test_eval_gate_verdict.py`, one test: legacy mode with a non-empty `mismatches` gives `NOT_COMPARABLE`. Run them red.
  2. `evals/baseline.py`: `baseline_integrity(baseline, ground_truth) -> list[str]`, pure, with the three problem lines of the plan (run count, unreadable key via `parse_cell_key` catching `ValueError`, cell-set difference only when the ground truth fingerprint matches). Import `parse_cell_key` from `evals.gate` (check for an import cycle: `gate.py` must not import `baseline.py`, otherwise move the call).
  3. `evals/eval_session.py`: `class Refused(Exception)` with `title` and `reasons`, `CRASHED_EXIT = 4` beside `NOT_COMPARABLE_EXIT`. Delete `refuse()`, every former call raises `Refused` (the `--record-baseline --ungated` check, `open_session`'s pre-run refusals, `_load_committed_baseline`, `git()`). `_load_committed_baseline` also raises `Refused("Refused before any LLM call.", problems)` when `baseline_integrity(baseline, MERGED_GROUND_TRUTH)` is non-empty. The module no longer imports `eval_display`.
  4. `evals/run_evals.py`: `main()` exactly as the plan's snippet, `_evaluate(options) -> int` holds the old body and returns `_record(...)` or `EXIT_CODES[...]`. `run_evals` raises `Refused("All runs failed.", ["no run completed: nothing to judge"])`. `_incomplete_runs(requested, completed)` with message `"{completed} of {requested} runs completed"`, computed from `session.conditions.runs` before the `baseline is None` branch and passed as `mismatches` to `judge_gate` in both branches. `_record` returns `0` or raises `Refused("Recording refused.", ...)` for drift and for `RecordingRefused`, keeping its `assert`.
  5. `evals/eval_display.py`: `print_written_recording` closes with the exploratory or confirmed line of the plan, chosen on the written baseline's status.
  6. `.github/workflows/eval-command.yml`, "Report result": case `4)`, and the `gate` line from `jq` appended to both comments when `output/eval_report.json` exists (expression verbatim from the plan).
  7. `CONTRIBUTING.md` "Recording an e2e baseline" and the `CHANGELOG.md` `[Unreleased]` paired-gate bullet, as the plan's Docs section says.
- **Test**: `baseline_integrity`: consistent baseline gives `[]`; a run missing a ground-truth cell names it; a run with an extra cell names it; `runs: []` names the count; 2 runs under `conditions.runs = 3` names the count; keys `"get_user"` and `"get_user/unknown"` each give `"run {i}: unreadable cell key ..."`, no exception; a baseline with another ground truth fingerprint and a missing cell gets no cell-set line. `judge_gate` legacy mode with mismatches gives `NOT_COMPARABLE`.
- **Verify**: the four commands above. Then the manual checks of Verification, Commit 1 (broken JSON baseline gives `3`, a baseline missing a cell gives `3`, `MCP_AUDITOR_PROVIDER=nope` gives a traceback and `4`, `--record-baseline --ungated` gives `3`, the `jq` expression on a hand-written report with and without `baseline_status`). Remove `evals/baselines/` after. Commit message answers the four questions of ADR 016 (`docs/adr/016-eval-gate-governance.md`, "Four questions"): the change lands in the instrument's tooling and tightens the legacy verdict on incomplete runs.

### Step 2: injected replay loop (first half of commit 2)

- **Files**: `tests/unit/test_eval_replay.py` (new), `tests/unit/support/test_eval_replay_given.py` (new), `tests/unit/test_eval_gate.py`, `evals/gate.py`, `evals/replay.py`, `evals/run_evals.py`.
- **Do**:
  1. Tests first: `ReplayRule.decide_replays` in `test_eval_gate.py`, `Replayer.settle_flips` in `test_eval_replay.py`. The given holds a counting fake audit (an object with an `async __call__(honeypot) -> VerdictMap` popping scripted maps per honeypot name, or raising, and a `calls` counter per honeypot), and two `HoneypotConfig`s with disjoint ground truths and a `server` path never opened. Build `CellComparison(outcome=CellOutcome.FLIP)` entries for the flipped cells and a stable outcome for the others. Run red.
  2. `evals/gate.py`: `ReplayRule.decide_replays(self, replays: list[bool]) -> bool | None`. `settle` calls it.
  3. `evals/replay.py`: `ReplayAudit` alias and the frozen `Replayer` dataclass with `settle_flips`, same behavior as `replay_flips` (see plan, Commit 2). `_undecided` becomes `rule.decide_replays(...) is None`. Drop `ReplayPlan`, `replay_flips`, the `eval_session` and `audit_honeypot` imports. Keep the progress print and the traceback print on a failed replay.
  4. `evals/run_evals.py` `_judge`: build `Replayer(audit=..., rule=baseline.replay_rule, honeypots=HONEYPOTS)`, the audit an `async def` closure over `session` returning `aggregate_verdicts(await audit_honeypot(session.settings, honeypot, session.conditions.budget))`.
- **Test**: `decide_replays`: `[True]*4` gives `True`, `[False]*2` gives `False`, `[True]*3 + [False]` gives `None`. `settle_flips` (the seven scenarios of "Test scenarios, Commit 2", audit counts asserted as the plan justifies): reproduced 4 times gives `REGRESSION` after 4 audits; cleared twice gives `FLIP_NOT_REPRODUCED` after 2 audits; two flips on one server share audits and stop once both decide; one flip per server audits each server separately; a cell of the other server is not read as uncovered; a raising audit leaves `FLIP` and returns `["a replay of {name} failed"]`; no flip, no audit.
- **Verify**: the four commands above, all clean. Commit message: one line saying it moves no verdict.

### Step 3: pure session rules (second half of commit 2)

- **Files**: `tests/unit/test_eval_session.py`, `tests/unit/support/test_eval_session_given.py` (new), `tests/unit/test_eval_baseline.py`, `evals/eval_session.py`, `evals/recording.py`, `evals/run_evals.py`.
- **Do**:
  1. Tests first. The session given builds CI conditions from `Settings.model_construct()` (`provider`, `resolve_model()`, `resolve_judge_model()`, runs `DEFAULT_RUNS`, budget `DEFAULT_BUDGET`) and an `EvalSession` from `Settings.model_construct()`, a `TreeState`, an optional baseline (reuse `test_eval_baseline_given.a_baseline`, whose conditions must equal the session's for the no-mismatch cases). Rewrite the three `ci_condition_mismatches` tests on it, the model assertion built from `Settings.model_construct().resolve_judge_model()`, never a literal. Add the `decide_recording` disagreement test (S6) in `test_eval_baseline.py`. Run red.
  2. `evals/recording.py`: public `exploratory_commit_refusal(baseline, commit) -> list[str]` with the plan's single wording, empty unless `baseline.status == EXPLORATORY and baseline.commit != commit`. `_refusals` uses it in place of `_other_commit`'s message for that rule (keep `_other_commit` only if it still carries another rule).
  3. `evals/eval_session.py`: `TreeState(commit, dirty)` frozen dataclass, `read_tree()` (the only `git` caller). `EvalSession.commit` becomes `tree: TreeState | None`, read in `open_session` when recording. Public pure `select_mode`, `pre_run_refusals(session)` (condition mismatches, CI conditions, `session.tree.dirty`, `exploratory_commit_refusal`), `tree_drift(before, after)` (dirty `after`, moved commit naming both). Delete `_select_mode`, `_recording_preconditions`, `_exploratory_at_another_commit`, the old `tree_drift`.
  4. `evals/run_evals.py` `_record`: `assert session.tree is not None`, `tree_drift(session.tree, read_tree())`, `Recording(commit=session.tree.commit, ...)`.
- **Test**: `select_mode`: ungated with a confirmed baseline gives `FLOORS_ONLY`, no baseline gives `LEGACY_THRESHOLDS`, exploratory gives `FLOORS_ONLY`, confirmed gives `PAIRED`. `pre_run_refusals`: no baseline, not recording, gives `[]`; a baseline at other conditions names the mismatch; recording on a dirty tree is refused; recording at other CI conditions is refused; recording over an exploratory baseline at another commit gives the shared wording. `tree_drift`: same state `[]`, dirty `after` named, moved commit names both. `ci_condition_mismatches`: the three existing tests rebuilt. `decide_recording`: a cell unstable in the exploratory baseline and stable-correct in the second recording is no disagreement, the recording confirms.
- **Verify**: the four commands above, all clean. `uv run python -m evals.run_evals --record-baseline --ungated; echo $?` still prints `3`. Commit message: one line saying it moves no verdict.

### Step 4: cleanup (commit 3)

- **Files**: `tests/unit/test_eval_gate.py`, `tests/unit/test_eval_gate_verdict.py`, `tests/unit/support/test_eval_gate_verdict_given.py` (new), `tests/unit/support/test_eval_gate_given.py`, `tests/unit/test_eval_baseline.py`, `tests/unit/support/test_eval_baseline_given.py`, `evals/gate.py`, `evals/gate_verdict.py`, `evals/recording.py`, `evals/eval_display.py`, `evals/run_evals.py`.
- **Do**:
  1. Test support first: move `metrics` and `cells_with` into the new `test_eval_gate_verdict_given.py` (keep in `test_eval_gate_given.py` only what `test_eval_gate.py` still uses), drop the `LEGACY_THRESHOLDS` copy, have `test_eval_gate_verdict.py` import `LEGACY_THRESHOLDS` from `evals.gate`. `test_eval_baseline_given.py` imports `VULNERABLE_CELL`, `SAFE_CELL`, `a_ground_truth` from `test_eval_gate_given.py`. Delete `test_a_replay_rule_within_its_bounds_is_accepted`. Tests naming `MODEL_CHANGE_PROCEDURE` assert on the message text. Write the new tests below, run red.
  2. `evals/gate.py`: `LEGACY_THRESHOLDS` beside `FLOORS` (moved from `run_evals.THRESHOLDS`). `metric_deltas` uses `abs(value) < resolution and not math.isclose(abs(value), resolution)`. `metric_resolutions` computes precision as `max` over runs with at least one predicted FAIL of `1 / (runs * that run's FAILs)`, `1.0` when none, docstring updated as the plan says.
  3. `evals/gate_verdict.py`: remove `GateInput.thresholds`, `judge_gate` reads `LEGACY_THRESHOLDS` in legacy mode, the `GateInput` docstring keeps only its second sentence. `run_evals` drops `THRESHOLDS` and the `thresholds=` argument, fills `EvalReport.thresholds` once from `LEGACY_THRESHOLDS if gate.mode == GateMode.LEGACY_THRESHOLDS else {}`.
  4. `evals/recording.py`: private `_MODEL_CHANGE_PROCEDURE`, `_other_conditions` reuses it with the plan's wording. `GatedSetChange(BaseModel)` with `entering` and `leaving`, returned by `gated_set_changes` and taken by `eval_display.print_written_recording`.
- **Test**: `metric_deltas`: a recall delta of exactly one case computed as a difference of two averages (e.g. `32/33 - 31/33` against resolution `1/33`) is conclusive, half a case is inconclusive. `metric_resolutions`: two runs predicting 1 and 9 FAILs give precision `1/2`, a run with no FAIL is skipped, all runs with none give `1.0`. `judge_gate` legacy mode red on a missed `LEGACY_THRESHOLDS` value without passing thresholds. `gated_set_changes` tests adapted to `GatedSetChange`.
- **Verify**: the four commands above, all clean. `grep -rn "THRESHOLDS\b" evals tests` shows no `run_evals.THRESHOLDS` left. Commit message: one line saying it moves no verdict.
