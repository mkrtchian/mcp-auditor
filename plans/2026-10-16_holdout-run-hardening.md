# Holdout run hardening

## Context

The holdout run mode of the CVE benchmark was just built (`evals/holdout_run.py`, `evals/holdout_audit.py`, `evals/holdout_conditions.py`, the interval math, the statistic and the report). It is wired and tested on an empty target set: with `HOLDOUT_TARGETS` empty the command prints that no target is drawn and exits 0. The draw that fills `HOLDOUT_TARGETS` is the maintainer's deferred session, and the first real run happens there. A whole-run review of the just-landed code found five places where the run mode does not yet match what `docs/holdout-rule.md` (version 6) already describes, or where a real run would crash or spend money before failing. This plan closes those five, so the machinery is correct the first time the draw session runs it.

Every change here is code the rule already describes. This plan opens no new rule version, edits no ADR, and does not touch `docs/holdout-rule.md`. Two of the five are literal conformance to the rule (the retry policy of holdout-rule.md:249, and the Gamma(1,1) prior the rule names for the hierarchical control); the other three are refusals that keep a run from spending money and then crashing. Nothing is published or baselined yet (the target set is empty), so no committed number moves.

## Approach

The holdout refusal and error policy already lives in two modules: `holdout_audit.py` (the per-run infra policy, opposite to acceptance) and `holdout_run.py` (the orchestrator, with the up-front refusals `_refuse_tracing` and `_refuse_tools_filter`). All five fixes land in those two modules plus `holdout_hierarchical.py`, and none touches the acceptance path (`cve_audit.audit_target`, `graded_despite_refusals`, the acceptance gate) or any pre-registered artifact.

The five items:

1. Retry on any audit or fixture-launch error, not only on `None`. holdout-rule.md:249 reads: "A failure to launch the fixture, or an audit that ends on any other error, is retried at most 2 times." Today the detector audit is retried only when `attempt_once` returns `None`, and `cve_audit._audit` converts only `LaunchError | PlantingFailed | subprocess.CalledProcessError` into `None`; any other exception (an LLM transport error, an httpx timeout, a pydantic parse failure, a replay error outside `cve_replay`'s own catch) propagates through `asyncio.gather` and aborts the whole run after the other targets were already audited and billed. The fixture-launch half applies to the vetting phase too (`check_target` and the layout observation both launch the two container versions), so a transient Docker error during vetting currently aborts the run as well. Both the detector audit and the vetting of a target are made to retry any error at most `HOLDOUT_INFRA_ATTEMPTS` (3) times; a target that still fails is dropped from N as not-run (rule: "A target that still fails in any run is reported as not run for the whole holdout run and left out of N"), never aborting the whole run. The new retry prints only the exception's class name, never its message, because a message could echo server output and the rule forbids a holdout run from writing any proof text (holdout-rule.md "Reading"). This class-name-only discipline covers the exceptions this item newly catches (the ones that today propagate past `attempt_once`). It does not cover `attempt_once` itself (cve_audit.py), which on a caught `LaunchError`/`PlantingFailed`/`CalledProcessError` already prints the full message with `{exc}` to the console; that path is the shared acceptance audit and is left unchanged (see "What stays unchanged"). The rule's "Reading" constraint is met by the proof-free report (`holdout_report`/`holdout_results` hold only counts and place ids), not by the console transcript.

2. Refuse up front a drawn target absent from the census. `_assemble_target` reads `ctx.disclosure_dates[target.cve_id]` after a target's runs have completed and been billed, so a drawn target whose `cve_id` has no census entry would `KeyError` late, after the spend. A new up-front refusal (beside `_refuse_tracing`/`_refuse_tools_filter`, before `require_ready`, the image rebuild and any audit) refuses when a drawn target's `cve_id` is not in `disclosure_dates`, naming it. It is placed before item 1's broad catch so a deterministic lookup bug is never swallowed as a fake infra failure.

3. Refuse, rather than crash, when no target survives vetting. If vetting drops every target, or every surviving target has a run drop it, the run assembles zero per-target results and the report build divides by zero (`primary_number([])` -> `cited_interval([])` -> `wilson(count, 0)`). The orchestrator raises a clear refusal ("no target survived the pre-run check") instead, listing the not-run reasons, so the maintainer sees why nothing ran rather than a traceback.

4. Integrate the Gamma(1,1) prior the rule names, not a truncated one. `holdout_hierarchical.py` sets `D_MIN = 0.1`, but a Gamma(1,1) places `1 - e^-0.1 = 9.5 %` of its mass below 0.1, so the grid integral runs over a Gamma conditioned on `d >= 0.1`, not the Gamma(1,1) the rule names for the hierarchical control. On small homogeneous or lopsided sides (exactly the sides `check_conclusion` places against zero) this moves a bound by roughly 0.03, enough to flip a borderline placement, and the existing stability test cannot see it because the module grid and the finer grid share `D_MIN`. Lowering `D_MIN` to `1e-3` truncates `0.1 %` of the mass and aligns the integrated prior with the rule's Gamma(1,1).

5. Refuse a dirty working tree. The run records `read_tree().commit` as provenance a reader uses to tell two runs apart (holdout-rule.md:233), but drops `TreeState.dirty`. On a dirty tree the recorded commit does not describe the code that ran. The acceptance benchmark already refuses to record on a dirty tree. A holdout run is a publication, so the orchestrator refuses up front when the tree is dirty, consistent with the tracing refusal, and reads the tree once so the same `TreeState` carries the commit into the result.

## Files to modify

### `evals/holdout_audit.py` (item 1, detector half)

Wrap the `outcome = await attempt()` call in `holdout_audit` so an exception is treated as an infra failure: caught, counted as one of the `HOLDOUT_INFRA_ATTEMPTS` attempts, printed as the exception's class name with the attempt number (never `str(exc)`), and retried; after the last attempt the function returns `None` exactly as it does today for a launch failure. A `GradedAudit` still returns at once, and a `RefusedAttempt` still returns `RefusedRun` with no retry. The retry loop already exists (`for number in range(1, HOLDOUT_INFRA_ATTEMPTS + 1)`); the change is a `try/except Exception` inside it around the single await, with the existing "failed to launch" console line reused or renamed to cover any error.

Because item 1 now has two call sites that run an awaitable up to `HOLDOUT_INFRA_ATTEMPTS` times, catching exceptions and returning `None` on exhaustion (the detector audit here and the vetting unit in `holdout_run.py`), extract one helper rather than duplicate the loop: `async def retry_infra[T](attempt: Callable[[], Awaitable[T | None]], label: str) -> T | None` in `holdout_audit.py`, printing the exception class name and the attempt number, retrying on both a raised exception and a `None` result, and returning the first non-`None` value or `None` after the last attempt. The retry-on-`None` is load-bearing: the detector `attempt` is `attempt_once`, which returns `None` on a caught launch/planting failure, and that `None` must keep triggering a retry (holdout-rule.md:249, pinned by `test_an_infra_failure_is_retried_twice_then_gives_up`, which scripts `[None, None, None]` and expects three calls). A helper that returned the first result including `None` would skip the retry and regress that behaviour. `holdout_audit` calls it for the detector attempt and keeps its own `GradedAudit`/`RefusedAttempt`/`None` routing on the result; the vetting unit never returns `None`, so for it only the exhaustion-`None` matters (mapped to a drop reason in `_vet`). Keep the helper small; if the two sites do not read cleanly from one helper, inline both loops instead (three similar lines beat a wrong abstraction), and the reviewer decides.

### `evals/holdout_run.py` (items 1 vetting half, 2, 3, 5)

Size decision (settled): items 2, 3 and 5 add three refusal functions plus the dirty-tree threading, roughly +25 lines, taking `holdout_run.py` from 297 to about 322. Keep them in `holdout_run.py` and accept the soft "rarely exceed 300" guideline rather than extract a sibling module now: the four up-front guards (`_refuse_tracing`, `_refuse_tools_filter`, `_refuse_missing_census`, `_refuse_dirty_tree`) are a cohesive group that shares the orchestrator's `Refused` idiom and flow, and a module of four thin single-purpose refusals would be a premature split. If a later change pushes the file well past 300, extract the guards then.

Item 1 (vetting): `_vet(target, deps)` runs `deps.check` then `deps.layout`; wrap that unit in `retry_infra` so a launch error during vetting retries the whole unit (both calls are idempotent, no state, so re-running both is correct). On exhaustion `_vet` returns a drop reason string ("vetting failed to launch after retries") rather than letting the exception propagate, which fits the existing `str | None` contract where a string drops the target from N and `None` runs it. `_vet_all`'s shape is unchanged.

Item 2: a new `_refuse_missing_census(targets, disclosure_dates)` raised from `run_holdout` beside the other up-front refusals, before `require_ready` and before `default_deps`/`rebuild`. It refuses, naming each target, when `entry.target.cve_id not in disclosure_dates`.

Item 3: after `_run_all`, when `assembled` is empty, `run_holdout` raises `Refused("holdout run refused", ["no target survived the pre-run check", ...the not-run reasons])` instead of returning a result with `targets=[]`. The CLI guards the empty-`HOLDOUT_TARGETS` case before calling `run_holdout`, so this fires only when at least one target was drawn and none survived.

Item 5: a new `_refuse_dirty_tree(tree: TreeState)` raised up front. Resolve `deps` first (so the injected `read_tree` is used by the tests), read the tree once via `deps.read_tree()`, refuse when `tree.dirty`, and thread that same `TreeState` into `_assemble_run` for `commit=tree.commit`, removing the second `deps.read_tree()` call at assembly. The refusal lands before the image rebuild and any audit.

The order of the up-front guards in `run_holdout`: tracing, tools filter, missing census (item 2), then resolve `conditions.require_ready` and `deps`, then dirty tree (item 5, needs `deps.read_tree`), then rebuild, vet, run. The all-dropped refusal (item 3) is after the runs, by nature.

### `evals/holdout_hierarchical.py` (item 4)

`D_MIN = 1e-3` in place of `0.1`. Consider raising `D_POINTS` from 128 if the stability test needs it to stay within the cited precision over the wider log range `[1e-3, 2000]`; keep it at 128 if the existing stability test still passes. `D_MAX`, `THETA_POINTS` and the priors are unchanged.

### Tests

`tests/unit/test_holdout_audit.py`: a fake `attempt` that raises once then returns a `GradedAudit` yields that `GradedAudit` (the raise was retried); a fake that always raises returns `None` after exactly `HOLDOUT_INFRA_ATTEMPTS` calls; the printed text is the exception class name, not its message (assert the message string does not appear in the captured output). The existing pass-through and no-retry-on-`RefusedAttempt` tests stay green.

`tests/unit/test_holdout_run.py`: a drawn target whose `cve_id` is absent from `disclosure_dates` refuses before any check (no dep is called); a dirty `TreeState` from the fake `read_tree` refuses before rebuild/audit; when every target is dropped by vetting the run refuses with the not-run reasons rather than returning an empty result; a vetting dep that raises once then succeeds lets the target through, and one that always raises drops the target from N as not-run (and does not abort the run for the other targets). The existing assembly, drop, refused-run and tools-filter tests stay green.

`tests/unit/test_holdout_hierarchical.py`: the existing Gamma(1,1) anchor stays within its tolerance under the new `D_MIN` (re-verify, delta is about 0.001); add an all-extreme case (every target detected on every run, or none on any) whose bound is pinned against the wider-`D_MIN` value computed offline, so a future re-truncation of the prior is caught. `D_MIN` feeds `contrast_hierarchical` too (the pre/post-cutoff comparison), and this item moves it, so add the same kind of pinned all-extreme anchor for `contrast_hierarchical` (one side all-detected, the other none), computed offline under the new `D_MIN`. This anchor also guards the magnitude of the earlier `contrast_hierarchical` d-marginalisation fix, so the separate cleanup change no longer needs its own contrast anchor.

`tests/unit/test_run_holdout.py`: unchanged unless the dirty/census refusals are surfaced at the CLI level too; they are raised in the orchestrator and caught by `main`'s existing `Refused` handler (`REFUSED_EXIT`), so the CLI code is untouched. The empty-`HOLDOUT_TARGETS` exit-0 test and the tracing-refusal test stay green.

### Living docs

`CHANGELOG.md` `[Unreleased]`: one line for the holdout run hardening (retry on any error including vetting, the census-absent / dirty-tree / no-survivor refusals, the prior-truncation fix). No `docs/holdout-log.md` entry: no logged run-condition value changes and the plan opens no rule version. No README change: the command's public description is unchanged (it still publishes no number).

## What stays unchanged

The acceptance path: `cve_audit.audit_target`, `graded_despite_refusals`, `attempt_once(overrides=None)`, the acceptance gate, `run_cve_benchmark`. `cve_audit.py`'s exception-to-`None` set is not widened (the broad catch is a holdout policy, in `holdout_audit`/`holdout_run`, not the shared audit). `docs/holdout-rule.md`, `docs/adr/*` and `plans/*` are not edited. The grammar, the places and the layout check are untouched. `provider_usage`/`generator_usage`/`judge_usage` semantics are unchanged. The pure-cleanup items from the same review (a `CLAUDE.md` wording fix, deleting the single-caller `_hierarchical`/`_hier_contrast` helpers, de-duplicating `_refuse_tracing`, inlining `_silent_client`) are out of this plan and handled separately as a small change. The `contrast_hierarchical` regression anchor that was going to the cleanup change moves into this plan's test scope instead, since item 4 moves the `D_MIN` that shifts the contrast bound.

## Edge cases

A detector audit that raises on every attempt: `None` after 3 calls, the target dropped from N, the run continues for the others. A detector audit that raises then succeeds: the success stands. A `RefusedAttempt`: still `RefusedRun` at once, no retry (unchanged). A vetting unit that raises then succeeds: the target is vetted normally. A vetting unit that always raises: dropped from N as not-run, the run continues. A drawn target absent from the census: refused up front, named, nothing launched. All targets dropped (vetting or a run): refused with the reasons, no division by zero. A dirty tree: refused up front, nothing launched. The exception message of a newly-caught propagating error never reaches the console (class name only) or the report; the report stays proof-free regardless, while `attempt_once`'s pre-existing `{exc}` console print on a caught launch/planting error is unchanged. `D_MIN = 1e-3` on a mixed-data side: the bound is essentially unchanged (the likelihood kills small `d`); on a homogeneous or lopsided side the bound moves toward its untruncated value.

## Test scenarios

Covered above per file. The load-bearing ones: the exception-class-only print (no proof leak), the retry-then-drop for both the audit and the vetting, the three up-front/graceful refusals, and the all-extreme hierarchical anchor under the new `D_MIN`.

## Verification

`uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .` and `uv run pyright` with no file argument, all green. The full honeypot and CVE suites stay green, confirming the acceptance path did not move. `uv run python -m evals.run_holdout run` still exits 0 on the empty target set. Every function stays rarely over 20 lines; `holdout_run.py` reaches about 322 lines once items 2/3/5 land, accepted under the soft "rarely exceed 300" guideline (see the size decision under the `holdout_run.py` heading).

## Due diligence record

The due-diligence pass writes this section, and later passes (the implementation-phase fact check) read it to see what external-fact verification concluded. It records what was concluded once, not what is true now: no pass may treat a line here as a reason to skip a verification. A human who edits one of these facts in the plan by hand should delete its line rather than update it, so this section never ends up asserting something nobody re-checked.

No external facts to verify. The plan cites no third-party endpoint, no external library or action version, and no platform contract, and defers no such value to implementation. Its references are internal (`docs/holdout-rule.md` version 6, the project's own `evals/` modules) and its numeric claims are closed-form math verified by hand. Diligence ran and found nothing external to check.

## Implementation steps

### Step 1: Retry on any error and the three up-front refusals (items 1, 2, 3, 5)

**Files**
- `evals/holdout_audit.py` (modify: add `retry_infra` helper, rewrite `holdout_audit` to use it)
- `evals/holdout_run.py` (modify: wrap `_vet` in `retry_infra`, add `_refuse_missing_census`, `_refuse_dirty_tree`, the all-dropped refusal, thread the single `TreeState`)
- `tests/unit/test_holdout_audit.py` (modify)
- `tests/unit/test_holdout_run.py` (modify)
- `CHANGELOG.md` (modify: one `[Unreleased]` line)

**Do** (write the tests first, run them red, then the code)

Tests in `tests/unit/test_holdout_audit.py`:
- a `_ScriptedAttempts` that raises once then returns a `GradedAudit` yields that `GradedAudit` (the raise was retried, `calls == 2`). `_ScriptedAttempts.__call__` must be extended to raise when the scripted item is an `Exception` instance.
- a fake that always raises returns `None` after exactly `HOLDOUT_INFRA_ATTEMPTS` (3) calls.
- the printed text on a raised exception is the exception **class name**, not its message: raise an exception whose message is a distinctive sentinel string and assert that sentinel does **not** appear in the captured console output, while the class name does.
- keep the existing pass-through, detection-with-refused-step, no-retry-on-`RefusedAttempt` and `[None, None, None]`-then-`None` tests green.

Tests in `tests/unit/test_holdout_run.py`:
- a drawn target whose `cve_id` is absent from `disclosure_dates` raises `Refused` (match "census") before any dep is called (an `audit`/`check`/`layout` that raises `AssertionError` must never be reached). Build the `dates` mapping without that target's id. Note `_run`'s helper currently derives `dates` from the targets, so this test constructs `dates` directly or calls `run_holdout` with a dates mapping missing the id.
- a dirty `TreeState` (fake `read_tree` returns `TreeState(commit=..., dirty=True)`) raises `Refused` (match "dirty" or the chosen wording) before rebuild/audit (rebuild and audit fakes that raise `AssertionError` must never be reached).
- when every target is dropped by vetting (`check` returns a dead-condition reason for each), the run raises `Refused` listing "no target survived the pre-run check" plus the not-run reasons, rather than returning a result with `targets == []`. Note this changes the expectation of the existing `test_a_target_dead_on_a_version_is_not_run` and `test_a_normal_target_the_layout_breaks_is_dropped`: with a single target that is dropped, those now refuse. Either add a surviving second target to those tests so a result is still assembled, or convert them to assert the refusal. Keep the behaviour each test names (dead-on-version drop, normal-layout-break drop) observable.
- a vetting dep (`check` or `layout`) that raises once then succeeds lets the target through (the target is vetted and run normally).
- a vetting dep that always raises drops that target from N as not-run (reason "vetting failed to launch after retries") and does **not** abort the run for a second, healthy target in the same call (assert the healthy target is assembled).
- keep the existing assembly, refused-run, fallback-kept, run-failed-to-launch, tools-filter and tracing tests green.

Production in `evals/holdout_audit.py`:
- add `async def retry_infra[T](attempt: Callable[[], Awaitable[T | None]], label: str) -> T | None`: loop `for number in range(1, HOLDOUT_INFRA_ATTEMPTS + 1)`, `try: result = await attempt()` and return it when not `None`, `except Exception as exc:` print the `label`, the exception **class name** (`type(exc).__name__`, never `str(exc)`) and `number/HOLDOUT_INFRA_ATTEMPTS`; on a `None` result print the same style of line and continue; return `None` after the last attempt. Retries on **both** a raised exception and a `None` result.
- rewrite `holdout_audit` to call `retry_infra` for the detector `attempt` and keep its own routing: a `GradedAudit` result returns at once, a `RefusedAttempt` returns `RefusedRun(outcome.report)` with no retry, exhaustion returns `None`. The `RefusedAttempt` check must stay inside the per-attempt path (it is not an infra failure), so `retry_infra`'s `attempt` for the detector returns `GradedAudit | None` and the `RefusedAttempt` is handled before/around it, or `holdout_audit` keeps its loop and calls `retry_infra` only to wrap the single await: preserve that a `RefusedAttempt` returns immediately without consuming further attempts and that the `[None, None, None]` script still calls three times. Reuse/rename the existing "failed to launch" console line to cover any error.

Production in `evals/holdout_run.py`:
- `_vet`: wrap the `deps.check` + `deps.layout` unit in `retry_infra` (both idempotent, safe to re-run together). On exhaustion (`retry_infra` returns `None`) return the drop-reason string "vetting failed to launch after retries"; otherwise return `vet_reason(...)`. `_vet_all`'s shape is unchanged.
- `_refuse_missing_census(targets, disclosure_dates)`: raise `Refused("holdout run refused", [...])` naming each `entry` whose `entry.target.cve_id not in disclosure_dates`.
- `_refuse_dirty_tree(tree: TreeState)`: raise `Refused` when `tree.dirty`, wording consistent with `_refuse_tracing`.
- in `run_holdout`, order the up-front guards: `_refuse_tracing()`, `_refuse_tools_filter(targets)`, `_refuse_missing_census(targets, disclosure_dates)`, then `conditions.require_ready(model_ids)` and resolve `deps`, then read the tree once `tree = deps.read_tree()` and `_refuse_dirty_tree(tree)`, then `deps.rebuild(...)`, vet, run. Thread `tree` into `_assemble_run` so `commit=tree.commit` replaces the second `deps.read_tree()` call at assembly.
- after `_run_all`, when `assembled` is empty raise `Refused("holdout run refused", ["no target survived the pre-run check", *reasons])` where `reasons` are the not-run reasons from `[*not_run, *dropped]`, instead of calling `_assemble_run` with `targets=[]`.

`CHANGELOG.md`: one `[Unreleased]` line for the holdout run hardening (retry on any error including vetting; the census-absent, dirty-tree and no-survivor refusals).

**Test**
- holdout_audit: raise-then-graded -> the graded audit, 2 calls; always-raise -> `None`, 3 calls; sentinel message absent from console, class name present; existing four tests green.
- holdout_run: missing-census target -> `Refused` before any dep; dirty tree -> `Refused` before rebuild/audit; all dropped -> `Refused` with reasons; vetting raise-then-succeed -> target run; vetting always-raise -> that target not-run, a second healthy target still assembled; existing tests green (dead-on-version / normal-layout-break adjusted to keep a survivor or assert the refusal).

**Verify**
- `uv run pytest tests/unit/test_holdout_audit.py tests/unit/test_holdout_run.py -n auto --maxprocesses 4` green.
- `uv run pyright evals/holdout_audit.py evals/holdout_run.py tests/unit/test_holdout_audit.py tests/unit/test_holdout_run.py` clean.
- `uv run ruff check .` and `uv run ruff format --check .` clean.
- Closing check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (no file argument) all green; `uv run python -m evals.run_holdout run` exits 0 on the empty target set.

### Step 2: Integrate the untruncated Gamma(1,1) prior (item 4)

**Files**
- `evals/holdout_hierarchical.py` (modify: `D_MIN`, maybe `D_POINTS`)
- `tests/unit/test_holdout_hierarchical.py` (modify)

**Do** (write/compute the anchors first, then flip `D_MIN`, then confirm)

- Set `D_MIN = 1e-3` in place of `0.1`. `D_MAX`, `THETA_POINTS` and the priors are unchanged.
- Compute the pinned anchor values **offline** under the new `D_MIN` (a throwaway script run with the module's own grid, in the scratchpad, not committed): one all-extreme `hierarchical_interval` case (every target detected on every run, or none on any) and one all-extreme `contrast_hierarchical` case (one side all-detected, the other none). Record the computed bounds as literals in the tests.
- Tests in `tests/unit/test_holdout_hierarchical.py`:
  - re-verify the existing offline scipy anchor (`test_matches_the_offline_scipy_anchor`) still holds under the new `D_MIN` (delta about 0.001); widen its tolerance only if it genuinely moved past it, documenting the new value.
  - add the all-extreme `hierarchical_interval` anchor pinned against the offline value, so a future re-truncation of the prior is caught.
  - add the all-extreme `contrast_hierarchical` anchor (one side all-detected, the other none) pinned against the offline value; this also guards the magnitude of the earlier contrast d-marginalisation fix.
  - keep `test_stable_between_the_module_grid_and_a_finer_grid` green. If the wider log range `[1e-3, 2000]` pushes the module-vs-finer-grid delta past its tolerance, raise `D_POINTS` from 128 until it passes again; otherwise leave `D_POINTS` at 128.

**Test**
- The scipy anchor stays within tolerance; the two new all-extreme anchors match their offline literals; grid stability holds; the direction tests (`test_more_concentration_pulls_toward_the_pooled_rate`, clamps, contrast straddle/positive/clamp) stay green.

**Verify**
- `uv run pytest tests/unit/test_holdout_hierarchical.py -n auto --maxprocesses 4` green.
- `uv run pyright evals/holdout_hierarchical.py tests/unit/test_holdout_hierarchical.py` clean.
- `uv run ruff check .` and `uv run ruff format --check .` clean.
- Closing check: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (no file argument) all green.
