# Eval CI and instrument hardening

## Context

Three reviews of the eval gate and its CI (robustness and security, standards and architecture, strategy) left two groups of work to land before the first baseline is recorded.

The first group is CI security. `.github/workflows/eval-command.yml` runs on `issue_comment`, so it executes in the repository's context, with its secrets, whenever a maintainer comments `/eval` on a pull request. Its guard, `author_association` (line 21), checks the author of the comment, never the author of the pull request, and its checkout of `refs/pull/N/head` (line 62) fetches the head of a pull request opened from a fork just as well. On a fork's pull request, the fork's code then runs with `GOOGLE_API_KEY`, `uv sync --dev` runs its build backend and dependency changes first, and the head is read when the job starts, so a commit pushed between the maintainer's review and that moment is the one that runs. The same workflow enables the uv cache (`enable-cache: true`, line 68), but since 2026-06-26 GitHub gives `issue_comment` runs a read-only cache token for the default branch's scope, so it can restore there and no longer save. `publish.yml` restores a uv cache before `uv build` with `id-token: write`. Its `concurrency` block sits at workflow level with `cancel-in-progress: true` (lines 12-14), so any comment on the pull request, `/eval` or not, starts a run of the same group that cancels an eval in progress, and the `!cancelled()` guard then suppresses the result comment. Separately, the judge eval job of `evals.yml` runs on a fork's pull request, cannot read the key, and fails, which `CONTRIBUTING.md` documents as "its run fails rather than being skipped".

The second group is the instrument and its code. The precision resolution added by the gate hardening skips runs that predict no FAIL, but one false positive moves such a run's precision from 1.0 to 0.0, so the figure understates the move of one case and a delta smaller than one case can be reported as conclusive, which ADR 016 forbids. A recording decides on the baseline loaded when the session opened and never rereads it before writing, and the write is not atomic, so two recordings run side by side overwrite each other without being compared. And the standards review found the gate's judging logic still inside `run_evals.py`, the composition root, with no unit test: an incomplete run is not comparable in every mode, a replay happens only in paired mode without mismatch, deltas exist only with a baseline. It also found smaller defects listed below.

Out of scope, decided in discussion: comparing across a ground truth revision. ADR 016 records the oracle version among the conditions and refuses to compare across differing values, so comparing across a relabel would contradict it. It goes to a later ADR on resetting the paired baseline, together with deliberate regressions and new or modified fixtures. The reviewer's finding that `tool_call_timeout` is missing from the conditions is dropped: `audit_honeypot` connects with `StdioMCPClient.connect(...)` without passing `settings.tool_call_timeout` (`evals/honeypots.py:57`), so the setting has no effect on the evals.

## Approach

Five commits, in this order.

1. `ci`: refuse a fork's pull request in `/eval` and check out the exact head it resolved, stop the checkout credentials from reaching the pull request's code, turn off the uv cache where a secret or a publish runs (defence in depth: since 2026-06-26 an `issue_comment` run only gets a read-only cache token, so this closes no live poisoning path, but a job that runs a pull request's code with a secret, and a build that publishes to PyPI, have no use for a restored cache), report the evaluated sha in the result comment, move `concurrency` to the job, skip the judge eval job of `evals.yml` on a fork's pull request, and update `CONTRIBUTING.md`. External contributions stay open: a fork's pull request runs `ci.yml` as today and its evals run on main after merge. A maintainer who wants an eval before merge pushes the reviewed commit to a branch of the repository and runs `/eval` there.
2. `fix(evals)`: the precision resolution counts a run with no predicted FAIL as one case moving that run's precision by 1.
3. `fix(evals)`: a recording rereads the baseline file just before writing and refuses when it changed since the session opened, and the baseline is written atomically.
4. `refactor(evals)`: extract the gate's judging into `evals/judging.py`, tested with the fake audit, with `RunsOutcome` moving along and gaining `completed_all`. `judge_gate` fills the legacy thresholds into `GateResult`.
5. `refactor(evals)`: the smaller standards findings: `EvalSession.record` derived from `tree`, exit codes next to their table, `git` made private, `Replayer` announcing through an injected callback instead of printing, and three test cleanups.

Commits 2 and 3 change the instrument's tooling only. Their messages say which artifact they land in and that no gate verdict moves (commit 2 changes the `inconclusive` flag of the report's deltas, which never enters the verdict). Commits 4 and 5 move no behavior.

## Files to modify

### `.github/workflows/eval-command.yml` (commit 1)

- Move the `concurrency` block from the workflow to the `eval` job, same group and `cancel-in-progress: true`. A comment that does not pass the job's `if` then never joins the group.
- New step after "Acknowledge command", `id: pr`, `if: steps.cmd.outputs.mode != 'none'`, env `GH_TOKEN`: run `gh pr view ${{ github.event.issue.number }} --json isCrossRepository,headRefOid` and write `fork=<true|false>` and `sha=<headRefOid>` to `$GITHUB_OUTPUT` (parse with `jq -r`).
- New step "Refuse fork", `if: steps.pr.outputs.fork == 'true'`: post a reaction `-1` on the comment and a PR comment: "`/eval` does not run on a pull request from a fork: its code would run with the repository's API key. To evaluate it before merge, push the reviewed commit to a branch of this repository and comment `/eval` on a pull request from that branch." Then the job ends successfully (no `exit 1`), so no second, misleading comment follows.
- Every later step (checkout, uv, Python, dependencies, both evals, "Report result") additionally requires `steps.pr.outputs.fork == 'false'`.
- Checkout: `ref: ${{ steps.pr.outputs.sha }}` and `persist-credentials: false`. The sha is resolved once, before anything of the pull request runs, and the evals run exactly that commit.
- `astral-sh/setup-uv`: `enable-cache: false`.

### `.github/workflows/publish.yml` (commit 1)

- `astral-sh/setup-uv`: `enable-cache: false`. Defence in depth: the build that publishes to PyPI restores no cache, whichever workflow saved it.

### `.github/workflows/evals.yml` (commit 1)

- `judge-eval` job `if`: `github.actor != 'dependabot[bot]' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)`. The e2e job already runs only on `push` and `workflow_dispatch`.

### `CONTRIBUTING.md` (commit 1)

- The paragraph at line 44: a fork's pull request now skips the judge eval job instead of failing it, and `/eval` refuses a fork's pull request, with the push-to-a-branch path in one sentence. Keep the rest of the paragraph.
- The paragraph at line 49 ("The workflow checks out the PR's head branch"): it now checks out the head commit resolved when the command is read, so a push after the comment does not change what runs.

### `evals/gate.py` (commit 2)

- `_largest_precision_move`: a run predicting `fails` FAILs moves by `_one_case_in(runs * max(fails, 1))`, so a run with none counts as a one-case move of `1 / runs` (its precision goes from 1.0 to 0.0 on one false positive, averaged over the runs). `max(..., default=1.0)` stays for an empty run list.
- `metric_resolutions` docstring: drop "A run predicting none cannot move it." and say that a run predicting none moves the most, one false positive taking its precision from 1 to 0.

### `evals/baseline.py` (commit 3)

- `write_baseline(path, baseline)`: write to a temporary file in `path.parent` (`tempfile.NamedTemporaryFile(dir=path.parent, delete=False, suffix=".tmp")` or `path.with_suffix(".json.tmp")`), then `os.replace` onto `path`. A crash mid-write leaves the previous file whole.

### `evals/eval_session.py` (commit 3)

- `baseline_changed(loaded: Baseline | None, current: Baseline | None) -> list[str]`, pure, beside `tree_drift`: `[]` when equal, otherwise one reason: "the baseline file changed during the runs: record again".

### `evals/run_evals.py` (commits 3, 4, 5)

- Commit 3, `_record`: before `decide_recording`, reload with `load_baseline(BASELINE_PATH)` (a `ValidationError` there raises `Refused("Recording refused.", ...)` like `_load_committed_baseline`), append `baseline_changed(session.baseline, reloaded)` to the drift reasons, raise `Refused("Recording refused.", reasons)` when non-empty.
- Commit 4: `_judge` and `_incomplete_runs` leave for `evals/judging.py`, and `RunsOutcome` moves there too. `run_evals` builds the `Replayer` (see commit 5 below for `announce`; in commit 4 it is built without it) and calls `judge_runs(session, outcome, replayer)`, and `EvalReport.thresholds` copies `gate.thresholds`. `_record` uses `result.outcome.completed_all(session.conditions.runs)`.
- Commit 5: `NOT_COMPARABLE_EXIT` and `CRASHED_EXIT` move here from `eval_session.py`, beside `EXIT_CODES`. `_evaluate` branches on `session.tree` (`if session.tree is not None: return _record(session, session.tree, result)`), and `_record(session, tree, result)` loses its `assert`. The `Replayer` is built with `announce=` a function printing to `display.console`.
  Decided (option b of the plan review): the replay rule belongs to the baseline and the `Replayer` is the injected dependency, so `Replayer` drops `rule` from its constructor and `settle_flips(cells, rule)` takes it and hands it to `_replay_server(honeypot, flipped, rule)`, which reads it today through `self.rule`. `run_evals.py` builds `Replayer(audit=_replay_audit(session), honeypots=HONEYPOTS, announce=...)` and passes it to `judge_runs`. The `Replayer(...)` calls of `test_eval_replay.py` lose `rule=` and pass it to `settle_flips`.

### `evals/judging.py` (new, commit 4)

- `RunsOutcome` (moved as is), plus `completed_all(self, requested: int) -> bool`.
- `async def judge_runs(session: EvalSession, outcome: RunsOutcome, replayer: Replayer) -> GateResult`, calling `replayer.settle_flips(cells, baseline.replay_rule)` in paired mode without mismatch: today's `_judge`, with the metrics computed from `outcome.metrics()` and the mismatch from `outcome.completed_all`. The message stays `"{completed} of {requested} runs completed"`.
- `run_evals.py` computes the metrics for the report from `outcome.metrics()` as well: both call a pure function, the duplication is two lines.

### `evals/gate_verdict.py` (commit 4)

- `GateResult.thresholds: dict[str, float]`, filled by `judge_gate`: `dict(LEGACY_THRESHOLDS)` in legacy mode, `{}` otherwise. The field is required, so `tests/unit/support/test_eval_baseline_given.a_gate` (the only other `GateResult(...)` construction) passes `thresholds={}`. `GateResult` is serialized under `gate` in `eval_report.json`, so the report gains `gate.thresholds` beside the top-level `thresholds`.

### `evals/eval_session.py` (commit 5)

- `EvalSession.record` field removed, replaced by a property `record` returning `self.tree is not None`. `open_session` passes `tree=read_tree() if options.record_baseline else None` and no longer passes `record=`. `tests/unit/support/test_eval_session_given.a_session` drops its `record=tree is not None` argument (a `TypeError` otherwise).
- `pre_run_refusals`: `if session.tree is not None: reasons += _recording_refusals(session, session.tree)`, and `_recording_refusals(session, tree)` loses its `assert`.
- `git` renamed `_git`.
- Remove the two exit code constants (moved to `run_evals.py`).

### `evals/replay.py` (commit 5)

- `Replayer` gains `announce: Callable[[str], None]`. The progress line and the failure go through it: the failure passes `traceback.format_exc()` so the traceback still reaches the operator. The module no longer imports `eval_display`, `sys` nor prints.

### Tests (commits 2 to 5)

- `tests/unit/test_eval_gate.py` (commit 2): `test_precision_resolution_skips_a_run_without_predicted_fail` becomes a test that such a run sets the resolution (runs predicting 0, 33, 33 FAILs give `1/3`), and `test_precision_resolution_without_predicted_fail_is_one` becomes "two runs with none give `1/2`". The other precision tests keep their values.
- `tests/unit/test_eval_session.py` (commit 3): `baseline_changed` cases. Commit 5: delete `test_the_ci_conditions_have_no_mismatch` (its given rebuilds the expected dict from the same `Settings.model_construct()`, so it cannot fail), and the exploratory-commit test asserts on the literal commit (`OTHER_COMMIT in reasons[0]`) instead of the production function's output.
- `tests/unit/test_eval_baseline.py` (commit 3): writing over an existing file replaces it and leaves no temporary file in the directory.
- `tests/unit/test_eval_judging.py` (new, commit 4) with `tests/unit/support/test_eval_judging_given.py`. Its "zero audits" and "4 times" expectations assert on `FakeAudit.calls`, so the module docstring states the same exception as `test_eval_replay.py`'s (each audit is a paid server run, and replaying in a mode or state that forbids it would give the same verdicts). The given builds an `EvalSession` through `test_eval_session_given.a_session`, a `RunsOutcome` from verdict maps over `MERGED_GROUND_TRUTH`, and reuses `test_eval_replay_given.FakeAudit` keyed by the real `HONEYPOTS` names. `FakeAudit.__init__` today seeds `calls` from the given's own `alpha`/`beta` honeypots, so a real honeypot name raises `KeyError` on `self.calls[honeypot.name] += 1`: give it a `honeypots` parameter defaulting to `given.HONEYPOTS`, which `test_eval_replay.py`'s `audit.calls == {"alpha": ..., "beta": ...}` assertions keep relying on. The confirmed and exploratory baselines' `runs` must hold every `MERGED_GROUND_TRUTH` cell (built with `observe` over a correct verdict map and `cell_key`): `test_eval_baseline_given.a_baseline` holds a small ground truth of its own, and a cell absent from the baseline runs classifies as stable incorrect, never as the stable-correct cell the flip scenarios need.
- `tests/unit/test_eval_replay.py` (commit 5): pass an `announce` collecting into a list. Remove the `audit.calls` assertions of the two single-cell tests (lines 26 and 38): for one cell the length of `replays` already is the audit count. Keep the three others. The module docstring stays.
- `tests/unit/test_eval_gate_verdict.py` (commit 4): legacy mode carries `LEGACY_THRESHOLDS` in `thresholds`, paired and floors-only carry `{}`.

## What stays unchanged

- The gate's rules: floors, replay rule, cell classification, recording decisions, conditions and their fingerprints, including the ground truth fingerprint as a refusing condition.
- The CLI, its flags and exit codes (0, 1, 3, 4), the report schema apart from where `thresholds` is filled from.
- `ci.yml`, `cve-calibration.yml`, the e2e job of `evals.yml`.
- The honeypots, the ground truth, every prompt.
- `CLAUDE.md` commands, `README.md`, `CHANGELOG.md`: no user-facing change (CI and eval internals only).

## Edge cases

- `/eval` on a pull request from a branch of the repository, Dependabot's included: `isCrossRepository` is false, behavior as today apart from the pinned sha.
- `/eval` on a fork's pull request: reaction, explanatory comment, no checkout, job green, no second comment.
- The pull request head moves after the `pr` step: the evals still run the sha resolved there. The comment reports that run.
- `gh pr view` fails (pull request deleted): the step fails, "Report result" is skipped because `fork` is unset, and the job shows red in Actions without a comment. Acceptable.
- A comment on the pull request while an eval runs: it does not pass the job `if`, never joins the concurrency group, the eval continues. A second `/eval` still cancels the first, and so does a maintainer's comment starting with `/eval` that is not a known command (`/eval please`): it passes the job `if`, joins the group, and cancels the run before "Unknown command" answers. Accepted, the maintainer typed a command.
- A fork's pull request touching `src/**`: `judge-eval` is skipped, `ci.yml` runs.
- Precision resolution with every run predicting FAILs: unchanged values. With an empty run list: `1.0`.
- Recording while the committed baseline was replaced by another recording since the session opened: refused, nothing written. Baseline file absent at open and still absent: `baseline_changed(None, None)` is `[]`.
- Crash between the temporary write and `os.replace`: the previous baseline is untouched, a stray `.tmp` may remain (it is untracked and never read).

## Test scenarios

- Precision resolution: runs predicting 0, 33, 33 FAILs give `1/3`. Two runs predicting none give `1/2`. Runs predicting 1 and 9 still give `1/2`. The exactly-one-case and half-a-case delta tests keep their outcomes.
- `baseline_changed`: `None, None` gives `[]`, equal baselines give `[]`, `None` then a baseline gives the reason, two baselines differing in `recorded_at` give the reason.
- `write_baseline`: written then loaded is equal (existing test), writing over an existing file replaces it, no `*.tmp` left in the directory.
- `judge_runs`:
  - no baseline, all runs completed: legacy verdict from the thresholds, no cells, no deltas, zero audits;
  - no baseline, 2 of 3 runs: `NOT_COMPARABLE`, reason `"2 of 3 runs completed"`;
  - confirmed baseline, one stable-correct cell failing in every candidate run, fake audit reproducing it 4 times: cell `REGRESSION`, verdict `RED`, deltas present;
  - confirmed baseline with the same flip but 2 of 3 runs completed: `NOT_COMPARABLE`, zero audits;
  - exploratory baseline with the same flip: mode floors-only, cell `FLIP`, zero audits;
  - replay raising: `NOT_COMPARABLE` with `"a replay of <name> failed"`.
- `RunsOutcome.completed_all`: 3 details of 3 is true, 2 of 3 false.
- `judge_gate` thresholds per mode.
- `Replayer` with `announce`: a failing audit sends a message containing the traceback text (assert on `"Traceback"` in one collected message), a replay sends one progress line per attempt.

## Verification

- `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all clean after every commit.
- Commit 1: `actionlint` if available, otherwise a YAML parse (`uv run python -c "import yaml,sys; [yaml.safe_load(open(p)) for p in sys.argv[1:]]" .github/workflows/*.yml`, adding no dependency if `yaml` is absent: then read the diff). The fork path cannot be exercised locally, say so in the commit message.
- Commit 3: by hand, `--record-baseline` with a baseline file written by `write_baseline` into `evals/baselines/` after the session opened is not reproducible without an LLM run, so the pure function carries the proof. `uv run python -m evals.run_evals --record-baseline --ungated; echo $?` still prints `3`.
- `wc -l evals/run_evals.py` is about 200 after commit 4.
- After the push (not part of this implementation, commit 1 only takes effect once on main): run `/eval full` on a same-repo pull request, post a plain comment while it runs, and check the eval continues and posts its result. Whether a job skipped by its `if` stays out of a job-level concurrency group is undocumented. Then open or simulate a fork's pull request and check the refusal comment.
- `grep -rn "display\|print" evals/replay.py` finds nothing after commit 5.

## Due diligence record

What the plan-diligence pass concluded about the external facts this plan cites or defers, verified on 2026-09-23. Later passes read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `gh pr view <number> --json isCrossRepository,headRefOid` (both fields listed in the `gh pr view` manual, cli.github.com)
- SETTLED: `actions/checkout@v7` with `ref: <sha>` and `persist-credentials: false` (actions/checkout README: `ref` accepts a branch, tag or SHA, `persist-credentials` defaults to `true`)
- SETTLED: `enable-cache: false` is an accepted value of `astral-sh/setup-uv` (setup-uv README: `true`, `false` or `auto`)
- SETTLED: `jobs.<job_id>.concurrency` with `group` and `cancel-in-progress` (GitHub Actions workflow syntax docs)
- SETTLED: `content=-1` is an accepted reaction on an issue comment (GitHub REST reactions docs)
- SETTLED: `github.event.pull_request.head.repo.full_name == github.repository` identifies a same-repository pull request in the `judge-eval` job (standard `pull_request` payload, prose only)
- SETTLED: `issue_comment` runs get a read-only cache token for the default branch's scope since 2026-06-26 (GitHub changelog 2026-06-26 and the caching docs), so `eval-command.yml` cannot save a cache that `publish.yml` would restore. The plan's Context was corrected to say so.
- SETTLED: a tag-push run can restore caches created on the default branch (GitHub caching docs, prose only)
- OPEN (unverified): a job skipped by its job-level `if` does not join or cancel its job-level concurrency group. GitHub's docs do not state it, and the edge case "a comment ... never joins the concurrency group" rests on it.
- OPEN (currency): `astral-sh/setup-uv@v7` is pinned across the workflows while v10 is the latest major. The plan does not change the pin.

## Implementation steps

Five steps, one per commit of the Approach, in its order. Checks after every step: `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all clean. Commit messages never mention this plan or its commit numbers.

One ordering correction to the file sections above: the removal of `rule` from the `Replayer` constructor is listed under commit 5, but commit 4's `judge_runs(session, outcome, replayer)` calls `replayer.settle_flips(cells, baseline.replay_rule)` and `run_evals.py` builds the `Replayer` before knowing whether a baseline exists. So the `rule` move lands in step 4, and step 5 only adds `announce`.

### Step 1: Harden the `/eval` workflow and skip the judge eval on forks (`ci`)

- **Files**: `.github/workflows/eval-command.yml`, `.github/workflows/publish.yml`, `.github/workflows/evals.yml`, `CONTRIBUTING.md`
- **Do**:
  - `eval-command.yml`:
    - Move the top-level `concurrency` block (group `eval-command-${{ github.event.issue.number }}`, `cancel-in-progress: true`) under `jobs.eval`.
    - After "Acknowledge command", add a step `id: pr`, `if: steps.cmd.outputs.mode != 'none'`, env `GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}`, running `gh pr view ${{ github.event.issue.number }} --json isCrossRepository,headRefOid`, parsed with `jq -r` into `fork=<true|false>` and `sha=<headRefOid>` appended to `$GITHUB_OUTPUT`.
    - Add a step "Refuse fork", `if: steps.pr.outputs.fork == 'true'`, env `GH_TOKEN`: reaction `-1` on the comment (same `gh api ... /reactions -f content=-1` form as the other steps) and `gh pr comment` with the exact text of the plan ("`/eval` does not run on a pull request from a fork: ..."). No `exit 1`.
    - Add `&& steps.pr.outputs.fork == 'false'` to the `if` of checkout, "Install uv", "Set up Python", "Install dependencies", "Run judge eval", "Run e2e eval" and "Report result" (keep each one's existing condition, including `!cancelled()` on "Report result").
    - Checkout: `ref: ${{ steps.pr.outputs.sha }}` and `persist-credentials: false`, replacing `refs/pull/N/head`.
    - `astral-sh/setup-uv@v7`: `enable-cache: false`.
    - "Report result": both comments name the evaluated commit, ` Commit: ${{ steps.pr.outputs.sha }}.` (short form with `${sha:0:7}` in shell is fine), so a maintainer can check it against the commit they reviewed.
  - `publish.yml`: `enable-cache: false` on `astral-sh/setup-uv`.
  - `evals.yml`: `judge-eval` job `if: github.actor != 'dependabot[bot]' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)`. The e2e job and the caches of `evals.yml` stay as they are.
  - `CONTRIBUTING.md`, section "Running evals on a pull request": in the first paragraph, replace "a pull request from a fork triggers the job but can't read the key, so its run fails rather than being skipped" with the fork's pull request skipping the judge eval job, and add that `/eval` refuses a fork's pull request, with the push-the-reviewed-commit-to-a-branch path in one sentence. In "The workflow checks out the PR's head branch" paragraph: it checks out the head commit resolved when the command is read, so a push after the comment does not change what runs. Keep the rest. Follow the writing preferences (no em dashes, avoid semicolons).
- **Test**: no automated test exists for workflows. The fork path cannot be exercised locally.
- **Verify**: `actionlint` is not installed, so parse every workflow: `uv run python -c "import yaml,sys; [yaml.safe_load(open(p)) for p in sys.argv[1:]]" .github/workflows/*.yml` (PyYAML is available in the environment, add no dependency). Read the diff for each `if` expression. The commit message states that the fork path could not be exercised locally. Unit tests, ruff and pyright stay clean (no Python change).

### Step 2: Count a run without predicted FAIL in the precision resolution (`fix(evals)`)

- **Files**: `tests/unit/test_eval_gate.py`, `evals/gate.py`
- **Do**:
  - Tests first, in `tests/unit/test_eval_gate.py` (use `test_eval_gate_given.py` helpers already used by the neighbouring precision tests):
    - Replace `test_precision_resolution_skips_a_run_without_predicted_fail` with a test that runs predicting 0, 33 and 33 FAILs give a precision resolution of `1/3`.
    - Replace `test_precision_resolution_without_predicted_fail_is_one` with a test that two runs predicting none give `1/2`.
    - Leave the other precision tests and the delta tests unchanged. Run them, confirm the two new ones fail.
  - `evals/gate.py`, `_largest_precision_move`: `moves = [_one_case_in(len(verdict_maps) * max(fails, 1)) for fails in predicted_fails]`, `max(moves, default=1.0)` kept for an empty list.
  - `metric_resolutions` docstring: drop "A run predicting none cannot move it." and say a run predicting none moves the most, one false positive taking its precision from 1 to 0.
- **Test**: 0/33/33 FAILs gives `1/3`. Two runs with none gives `1/2`. Runs predicting 1 and 9 still give `1/2`. The exactly-one-case and half-a-case delta tests keep their outcomes.
- **Verify**: `uv run pytest tests/unit/test_eval_gate.py`, then the full check set. Commit message: lands in the instrument's tooling (`evals/gate.py`), changes only the `inconclusive` flag of the report's deltas, no gate verdict moves.

### Step 3: Refuse a recording when the baseline changed, write it atomically (`fix(evals)`)

- **Files**: `tests/unit/test_eval_baseline.py`, `tests/unit/test_eval_session.py`, `evals/baseline.py`, `evals/eval_session.py`, `evals/run_evals.py`
- **Do**:
  - Tests first:
    - `tests/unit/test_eval_baseline.py`: writing a baseline over an existing file (use `tmp_path`) replaces it (load gives the second one), and no `*.tmp` file remains in the directory afterwards.
    - `tests/unit/test_eval_session.py`: `baseline_changed` cases, building baselines with `test_eval_baseline_given.a_baseline` / `test_eval_session_given.a_baseline_at_ci_conditions` (`model_copy(update={"recorded_at": ...})` for the differing one).
  - `evals/baseline.py`, `write_baseline(path, baseline)`: keep `path.parent.mkdir(...)`, write the JSON to `path.with_suffix(".json.tmp")` (or a `tempfile.NamedTemporaryFile(dir=path.parent, delete=False, suffix=".tmp")`), then `os.replace(temporary, path)`.
  - `evals/eval_session.py`: `def baseline_changed(loaded: Baseline | None, current: Baseline | None) -> list[str]`, pure, placed beside `tree_drift`. `[]` when `loaded == current`, else `["the baseline file changed during the runs: record again"]`.
  - `evals/run_evals.py`, `_record`: after `tree_drift`, reload with `load_baseline(BASELINE_PATH)`, turning a `ValidationError` into `Refused("Recording refused.", [f"{BASELINE_PATH} is not a valid baseline: {error}"])`, add `baseline_changed(session.baseline, reloaded)` to the drift reasons, and raise `Refused("Recording refused.", reasons)` before `decide_recording` when the combined list is non-empty. Keep `_record` under 20 lines (extract a `_recording_drift(session) -> list[str]` helper right below it if needed).
- **Test**:
  - `baseline_changed(None, None) == []`, equal baselines give `[]`, `None` then a baseline gives the reason, two baselines differing only in `recorded_at` give the reason.
  - `write_baseline` over an existing file replaces it, leaves no `*.tmp`. The existing round-trip test stays.
- **Verify**: the full check set. `uv run python -m evals.run_evals --record-baseline --ungated; echo $?` prints `3`. Commit message: lands in the recording tooling (`evals/baseline.py`, `evals/eval_session.py`, `evals/run_evals.py`), no gate verdict moves, the concurrent-recording path is proven by the pure function only (reproducing it needs an LLM run).

### Step 4: Extract the gate's judging into `evals/judging.py` (`refactor(evals)`)

- **Files**: `tests/unit/test_eval_judging.py` (new), `tests/unit/support/test_eval_judging_given.py` (new), `tests/unit/support/test_eval_replay_given.py`, `tests/unit/test_eval_replay.py`, `tests/unit/test_eval_gate_verdict.py`, `tests/unit/support/test_eval_baseline_given.py`, `evals/judging.py` (new), `evals/replay.py`, `evals/gate_verdict.py`, `evals/run_evals.py`
- **Do**:
  - Test support first:
    - `test_eval_replay_given.FakeAudit.__init__` gains `honeypots: list[HoneypotConfig] = HONEYPOTS` and seeds `calls` from it.
    - `test_eval_baseline_given.a_gate` passes `thresholds={}`.
    - `test_eval_judging_given.py`: a session through `test_eval_session_given.a_session(baseline=...)`, a `RunsOutcome` built from verdict maps over `MERGED_GROUND_TRUTH` (a correct map, and one with a chosen stable-correct FAIL cell missed, `RunDetail`s via `build_run_detail` with a minimal `AuditReport`), a confirmed and an exploratory baseline whose `runs` hold every `MERGED_GROUND_TRUTH` cell as correct (`observe` over the correct map, keyed with `cell_key`, placed on `a_baseline_at_ci_conditions(status=...)` via `model_copy`), a `FakeAudit(scripts, honeypots=HONEYPOTS)` over the real `evals.honeypots.HONEYPOTS`, with a replay reproducing the flipped cell on its own honeypot's ground truth, and a failing variant.
  - Tests, before production code:
    - `test_eval_judging.py`, with a module docstring stating the same audit-count exception as `test_eval_replay.py`'s. Scenarios listed under **Test** below.
    - `test_eval_gate_verdict.py`: legacy mode carries `LEGACY_THRESHOLDS` in `thresholds`, paired and floors-only carry `{}`.
    - `test_eval_replay.py`: each `Replayer(...)` loses `rule=` and `settle_flips(cells, ReplayRule())` takes it.
  - `evals/replay.py`: `Replayer` drops the `rule` field. `settle_flips(self, cells, rule: ReplayRule)` passes it to `settle(...)` and to `_replay_server(honeypot, flipped, rule)`, which uses it instead of `self.rule`. Printing stays for now.
  - `evals/gate_verdict.py`: `GateResult.thresholds: dict[str, float]`, required. `judge_gate` fills `dict(LEGACY_THRESHOLDS)` in `GateMode.LEGACY_THRESHOLDS`, `{}` otherwise.
  - `evals/judging.py`: `RunsOutcome` moved as is from `run_evals.py`, plus `completed_all(self, requested: int) -> bool` (`len(self.details) >= requested`). `async def judge_runs(session: EvalSession, outcome: RunsOutcome, replayer: Replayer) -> GateResult`: today's `_judge`, metrics from `outcome.metrics()`, mismatch `[f"{completed} of {requested} runs completed"]` when not `completed_all`, `replayer.settle_flips(cells, baseline.replay_rule)` only in paired mode without mismatch. Newspaper order, functions under 20 lines.
  - `evals/run_evals.py`: import `RunsOutcome` and `judge_runs` from `evals.judging`. Remove `_judge` and `_incomplete_runs`. `run_evals` builds `Replayer(audit=_replay_audit(session), honeypots=HONEYPOTS)` and calls `judge_runs(session, outcome, replayer)`. `EvalReport.thresholds` copies `gate.thresholds`. `_record` uses `result.outcome.completed_all(session.conditions.runs)`. Drop now-unused imports.
- **Test** (`test_eval_judging.py`):
  - no baseline, all runs completed: legacy verdict from the thresholds, no cells, no deltas, zero audits
  - no baseline, 2 of 3 runs: `NOT_COMPARABLE`, reason `"2 of 3 runs completed"`
  - confirmed baseline, one stable-correct cell failing in every candidate run, fake audit reproducing it 4 times: cell `REGRESSION`, verdict `RED`, deltas present, 4 audits on that honeypot
  - confirmed baseline, same flip, 2 of 3 runs completed: `NOT_COMPARABLE`, zero audits
  - exploratory baseline, same flip: mode floors-only, cell `FLIP`, zero audits
  - replay raising: `NOT_COMPARABLE` with `"a replay of <name> failed"`
  - `RunsOutcome.completed_all`: 3 details of 3 is true, 2 of 3 false
  - `judge_gate` thresholds per mode (in `test_eval_gate_verdict.py`)
- **Verify**: the full check set. `wc -l evals/run_evals.py` gives about 200. No behavior change: the report gains `gate.thresholds` only.

### Step 5: Smaller standards findings (`refactor(evals)`)

- **Files**: `tests/unit/test_eval_replay.py`, `tests/unit/test_eval_session.py`, `tests/unit/support/test_eval_session_given.py`, `evals/replay.py`, `evals/eval_session.py`, `evals/run_evals.py`
- **Do**:
  - Tests first:
    - `test_eval_replay.py`: every `Replayer(...)` gets `announce=messages.append` on a local `messages: list[str]`. Remove the `audit.calls` assertions of the two single-cell tests (reproduced four times, cleared twice). Keep the other three and the module docstring. Add: a failing audit sends a message containing `"Traceback"`, and a replay sends one progress line per attempt (4 lines for the four-times-reproduced flip).
    - `test_eval_session.py`: delete `test_the_ci_conditions_have_no_mismatch`. The exploratory-commit test asserts `OTHER_COMMIT in reasons[0]` (the literal commit) instead of calling the production function.
    - `test_eval_session_given.a_session`: drop `record=tree is not None`.
  - `evals/replay.py`: `Replayer` gains `announce: Callable[[str], None]`. The progress line goes through it (plain text, no rich markup required), the failure through `self.announce(traceback.format_exc())`. Remove the `eval_display` and `sys` imports and every print.
  - `evals/eval_session.py`: `EvalSession.record` becomes a property `return self.tree is not None`. `open_session` no longer passes `record=`. `pre_run_refusals`: `if session.tree is not None: reasons += _recording_refusals(session, session.tree)`, and `_recording_refusals(session, tree)` drops its `assert` and uses `tree`. Rename `git` to `_git`. Remove `NOT_COMPARABLE_EXIT` and `CRASHED_EXIT`.
  - `evals/run_evals.py`: define `NOT_COMPARABLE_EXIT = 3` and `CRASHED_EXIT = 4` beside `EXIT_CODES`. `_evaluate`: `if session.tree is not None: return _record(session, session.tree, result)`. `_record(session, tree, result)` drops its `assert` and uses `tree`. The `Replayer` gets `announce=` a function printing to `display.console`.
- **Test**: the announce scenarios above. All other existing tests keep passing.
- **Verify**: the full check set. `grep -rn "display\|print" evals/replay.py` finds nothing. `uv run python -m evals.run_evals --record-baseline --ungated; echo $?` still prints `3`.
