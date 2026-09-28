# Parallel audits in the CVE benchmark and the honeypot evals

## Context

`evals.run_cve_benchmark` audits its targets and their runs one after the other: `run_gated` awaits `_run_target` per target, `_run_target` awaits each run, and `_gate` settles the replays of one target after the other. With six targets and three runs, a graded run is 18 audits of about 80 s, about 25 minutes, and a baseline takes two recordings. `--calibrate` also calibrates one target at a time (about 47 s). `evals.run_evals` does the same: `_run_all` loops over the runs, `audit_honeypots` audits the three honeypots in turn, and `Replayer.settle_flips` replays one server after the other. A run of the e2e evals is 9 audits.

Nothing requires the sequence. Each CVE audit builds its own environment: a temporary directory, a network and a sidecar with random names (`mcp-auditor-cve-<hex>`), `--rm` containers with no fixed name, a stdio dialogue with no host port, and its own graph and MCP client. Each honeypot audit starts its own server process, and the honeypots hold no mutated state. The audit graph itself stays sequential per tool (ADR 009): only whole audits run side by side.

Three things break or degrade under concurrency and are fixed here:

- `target.environment()` is a synchronous context manager. Entering it runs `docker network create`, `docker run -d` and `git` seeding, and leaving it runs `docker stop` on the SSRF sidecar. That sidecar is busybox `httpd` as PID 1, which ignores SIGTERM, so `docker stop` waits its 10 s grace period. Run on the event loop, that call freezes every other audit for 10 s, including the 30 s `asyncio.timeout` of their tool calls (`StdioMCPClient._tool_call_timeout`), so a frozen loop could turn a slow server answer into a timeout and a false miss.
- `run_evals._post_langsmith_feedback` attaches recall and precision to "the most recent LangSmith run" (`client.list_runs(project_name, limit=1)`). In sequence that is the trace of the last honeypot audited. In parallel it is any run's trace, and the `except Exception: pass` hides it.
- The console: CVE audits print nothing while they run, and the honeypot "Auditing X..." lines do not say which run they belong to once runs interleave.

Throttling by the model provider (HTTP 429) is out of scope: it is counted and surfaced by a separate plan, written after this one lands and against the parallel code, so it can attribute a 429 to the audit that met it. Until then, a throttle that exhausts the retries still shows as an incomplete run, not comparable.

### Governance

Concurrency is an execution setting, not a condition of the baseline: it changes no label, no fixture, no scoring code, no model, no runs and no budget (ADR 016, ADR 020, ADR 024). It needs no labeling log entry and no reset, and the confirmed honeypot baseline, recorded in sequence, stays comparable. Its only plausible effect on a grade is a tool call timing out under load, which the thread offload and the bound remove. A provider that throttles past its retries already yields an incomplete run, which reads as not comparable. The concurrency used is written in each report, for traceability, and is not compared.

## Approach

- One bounded pool of whole audits. In the CVE benchmark, all target × run audits go into one `asyncio.gather`, bounded by a semaphore. The replays of one target stay sequential, because they stop as soon as the replay rule decides, but different targets settle their replays side by side. In the honeypot evals, the runs are gathered, and within a run the three honeypots are gathered, under the same kind of bound. The replays of one server stay sequential, different servers replay side by side.
- One `--concurrency N` flag on both runners, default 6, `1` restores today's sequence. It bounds the audits in flight, and so the LLM calls in flight, since an audit makes its calls one at a time. It also bounds `--calibrate`. The default comes from the public CI runner (4 vCPU, 16 GB) and the CVE containers carrying no memory bound. A value below 1 is refused by argparse.
- Environment entry and exit run in a worker thread.
- `gather` keeps submission order, so every list that feeds a baseline or a report (runs per target, runs per honeypot, replay lists) keeps the order it has today.

## A shared bound: `evals/concurrency.py` (new)

```python
def bounded[**P, R](
    call: Callable[P, Awaitable[R]], limit: int
) -> Callable[P, Awaitable[R]]:
    """At most `limit` calls in flight at once, the others waiting their turn."""
```

One `asyncio.Semaphore(limit)` created at call time, held around `await call(...)`. Three callers: the CVE audit, the CVE calibration, the honeypot audit. `limit < 1` raises `ValueError`. Each call to `bounded` makes its own semaphore, so a bound shared by several callers (the honeypot runs and replays) means one `bounded` callable built once and passed to all of them.

The argparse type both runners share lives here too: `positive_int(text: str) -> int`, raising `argparse.ArgumentTypeError` below 1. Two private copies in the two runners would be duplication.

The semaphore is created outside any running loop when `bounded` is called from synchronous composition code (`_harness` in `run_cve_benchmark`). Since Python 3.10 an `asyncio.Semaphore` binds to the loop on first use, not on creation, so this is safe (the project runs on 3.13).

The generic async helper the CVE benchmark needs lives here too, below `bounded`:

```python
@asynccontextmanager
async def entered_in_thread[T](manager: AbstractContextManager[T]) -> AsyncIterator[T]:
    """Enters and leaves a blocking context manager off the event loop."""
```

`__enter__` through `asyncio.to_thread`. On exit, `__exit__` through `asyncio.to_thread` with the exception triple of the body (or three `None`), and the body's exception re-raised unless `__exit__` returned true, as `contextlib.ExitStack` does. Generator-based context managers are not bound to a thread, so entering in one worker thread and leaving in another is safe.

## CVE benchmark

### `evals/cve_environments.py`

The module docstring gains one sentence: the benchmark enters and leaves these environments in a worker thread (`entered_in_thread`, in `evals/concurrency.py`), because leaving the SSRF environment stops a sidecar that ignores SIGTERM and waits 10 s. The module is at 291 lines, so the helper itself does not go here (CLAUDE.md: files should rarely exceed 300 lines), and it is not CVE-specific.

### `evals/cve_audit.py`

- `audit_target(budget: int, concurrency: int) -> AuditTarget` returns `bounded(audit, concurrency)`. The models are still built once, before anything runs. The existing test in `tests/unit/test_cve_audit.py` calls `audit_target(budget=10)` and gains `concurrency=1`.
- `with target.environment() as launch:` becomes `async with entered_in_thread(target.environment()) as launch:`. The grade is still computed before the exit, so a failed teardown still cannot erase a completed run.
- After a completed audit, one progress line: `console.print(f"{target.cve_id}: {grade.status}")` (`RunGrade.status` is a `CVEStatus`, a `StrEnum`, so it prints its value). A skipped run already prints its own line prefixed by the CVE id, and so do the incidents.

### `evals/cve_session.py`

- `run_gated`: `runs = await _run_targets(session)` instead of the list comprehension.
- `_run_target` becomes:

```python
async def _run_targets(session: _Session) -> list[_TargetRuns]:
    count = session.options.conditions.runs
    targets = session.options.targets
    outcomes = await asyncio.gather(
        *(session.harness.audit(target) for target in targets for _ in range(count))
    )
    return [
        _target_runs(target, outcomes[index * count : (index + 1) * count])
        for index, target in enumerate(targets)
    ]


def _target_runs(target: CVETarget, outcomes: Sequence[RunGrade | None]) -> _TargetRuns:
    # today's body of _run_target after the awaits, unchanged
```

- `_gate`: compute every `compare_target` first, as today, then `asyncio.gather` the `_replayed` calls for the targets that have a baseline and no condition mismatch, keeping the order of `runs` in the `comparisons` list. `_replayed` does not change: one target's replays stay sequential. A comparison that needs no replay goes through `_replayed` as today (its `while` loop does not run) or is passed through as is, whichever reads better.
- The session knows nothing of the bound: it gathers, and the `AuditTarget` it receives decides how many run at once. The `CVEHarness` docstring or the `AuditTarget` alias docstring says so in one clause: the audit may be called concurrently.

### `evals/cve_calibration.py`

- `calibrate_all(targets, ci, concurrency)` gathers `bounded(_calibrate_one, concurrency)` over the targets not skipped, then prints the `live`/`dead` lines in target order once all are done. Skip lines print first, as today. `_calibrate_one` enters the environment with `entered_in_thread`. Its error and dead reports are printed with no `await` between their lines, so they do not interleave with another target's.
- Three arguments: `targets`, `ci`, `concurrency`. If `ci` and `concurrency` read better as a small `CalibrationOptions` dataclass, the implementer may extract it, not required. The integration tests in `tests/integration/test_cve_calibration.py` call `calibrate_all(targets)` with no other argument: `concurrency` either keeps a default (`ci: bool = False, concurrency: int = 1`, as `ci` does today) or those four calls pass it. The first of them calibrates two targets, one dead at startup, and passing `concurrency=2` there exercises the parallel path against a real stub server for free.

### `evals/run_cve_benchmark.py`

- `--concurrency`, `type=positive_int` (from `evals/concurrency.py`), default `CVE_CONCURRENCY = 6`, help: "Audits (or calibrations) in flight at once; 1 runs them one after the other."
- `_harness(args.budget)` becomes `_harness(args.budget, args.concurrency)`, passing it to `audit_target`.
- `calibrate_all(graded, ci=args.ci, concurrency=args.concurrency)`.
- The concurrency is written in the report: `CVEBenchmarkReport` (in `evals/cve_oracle.py`) gains `concurrency: int` next to `conditions` (`tests/unit/support/test_cve_oracle_given.py` builds one and passes it), **not** inside `CVERunConditions`, so it is never compared nor recorded in a baseline. `render_markdown` shows it on the conditions line. Check that the fixture fingerprint and the baseline file do not include report fields (they should not, they are built from `CVERunConditions` and the target).

## Honeypot evals

### `evals/honeypots.py`

- `audit_honeypots(audit)` gathers the three audits, then merges verdicts and reports in `HONEYPOTS` order, exactly as today. If one audit raises, the exception propagates as today (the run fails), and the other two tasks are left to finish: `gather` without `return_exceptions` does not cancel them. That is acceptable, their results are discarded as they are today when the run fails.
- The docstring: "One run: every honeypot audited side by side, their verdicts and reports merged in a fixed order."

### `evals/replay.py`

- `Replayer.settle_flips` gathers `_replay_server` over the honeypots that have flipped cells, keeping `HONEYPOTS` order when it folds the results into `settled` and `failures`. A replay that raises is still caught per honeypot, so the try/except moves into a small per-honeypot coroutine that returns either the replays or the failure message. `_replay_server` does not change: one server's replays stay sequential.

### `evals/fault_harness.py`

The fault injection reuses `audit_honeypots` and `Replayer`, so its audits of the three honeypots now run side by side too. Two consequences to handle:

- `FaultedAudit.replay` takes `next(self.audits)` **after** the audit today. Once replays of different servers run side by side, the order in which they finish is not deterministic, so the index each one gets, and so the fault's draw, would not be either. Take the index before the first `await`: `index = next(self.audits)`, then the audit, then `self.fault.degrade(verdicts, index)`. Tasks created by `gather` start in creation order and run until their first `await`, so the first replay of each server gets its index in `HONEYPOTS` order. A server's second and later replays still take theirs when its previous replay finishes, so their indices depend on which server finishes first against the real honeypot processes. That is acceptable: the half-loss test asserts by rule, whatever the draws (`evals/fault_injection_method.md`).
- `RandomJudge` draws from one shared `random.Random(seed)` in call order. The three honeypots' judgments now interleave, so which cell gets which draw varies between runs of the test. Its test already asserts by rule (precision red, some PASS cells flipped), for the same reason, so nothing changes, but the implementer checks it holds over several runs. `runs()` does not change: its index is taken after the whole run, and its runs stay in sequence (the fault harness does not gain `--concurrency`).
- `FixtureJudge` counts judgments per cell. The three honeypots have disjoint cells, so interleaving their audits within a run does not change any cell's count. The implementer confirms it by reading the fake, and by running `tests/integration/test_gate_fault_injection.py` several times.
- The connected servers are shared per scenario (one per honeypot), and never by two concurrent audits, since each honeypot is audited once per run and once per replay step.

### `evals/run_evals.py`

- `--concurrency`, same parser helper (`positive_int`) and default as the CVE benchmark (`DEFAULT_CONCURRENCY = 6` in `evals/eval_session.py` beside `DEFAULT_RUNS`), passed through `EvalOptions`. **Not** added to `BaselineConditions` (the honeypot conditions model) or anything the baseline compares. `tests/unit/support/test_eval_session_given.py` builds `EvalOptions` by keyword and passes it too.
- `EvalSession` does not carry it (`fault_harness.Harness._session` builds one and would have to invent a value): `_evaluate` passes `options.concurrency` to `run_evals(session, concurrency)`, which hands it to `_run_all` and `_replay_audit` through the one bounded callable below.
- `_run_all` gathers the runs. Each run keeps its own `try/except`, so a failed run still prints its warning and advances the progress bar by the number of honeypots, and the others go on. Each run prints its `display.print_run_result` and posts its LangSmith feedback as soon as it completes, inside its own coroutine, so progress shows while the others run. After the gather, the completed runs are appended to `outcome` in run index order.
- The honeypot audit passed to `audit_honeypots` and to `_replay_audit` is wrapped once by `bounded(..., concurrency)`, so runs, honeypots and replays share one bound. Today the audit handed to `audit_honeypots` is a closure built per run in `_run_one_eval` (it prints and advances the progress bar), so the bounded callable is built once in `run_evals` and the per-run closures call it. The "auditing" line is printed once the slot is acquired, not before, or all nine lines would print at start: the bounded callable takes what it needs to print it (`bounded` is generic over the parameters), or the line moves inside the bounded function. `models_for(session.settings)` is built once per session instead of per audit (today it is rebuilt on each call). If that changes behavior, it is a separate commit.
- The "Auditing X..." line says the run: `f"  Run {index + 1}: auditing [bold]{honeypot.name}[/bold]..."`.
- `EvalReport.config` gains `"concurrency"`. It is a free dict, so no model change.
- `run_evals.py` is at 270 lines and gains the gathered runs, the per-run coroutine, the trace ids and possibly `CompletedRun`. If it passes 300 lines, the run loop (`_run_all`, `_run_one_eval`, `_post_langsmith_feedback` and what they alone use) moves to its own module under `evals/` (CLAUDE.md: files should rarely exceed 300 lines, when they do, split).

### LangSmith feedback

- In the honeypot audit closure of `_run_one_eval`, the audit runs inside `langchain_core.tracers.context.collect_runs()`, and the root run's id (`collector.traced_runs[0].id`) is kept with the report. An audit that raised may leave `traced_runs` empty: the id is read only after a completed audit, and a missing id skips that trace's feedback. `collect_runs` sets a `ContextVar`, and each task created by `gather` has its own copy, so concurrent audits do not see each other's runs. It is only entered when LangSmith tracing is on, so an untraced run keeps no run tree in memory.
- `_run_one_eval` returns the ids of the run's three traces with the verdicts and the report. `_post_langsmith_feedback(run_detail, trace_ids)` attaches recall and precision to each of the three traces, instead of asking LangSmith for its most recent run. The `project_name` argument goes (it was only there for `list_runs`). The `try/except` stays best-effort, as today.
- How the ids travel from `_run_one_eval` to `_run_all` is left to the implementer, within the argument limit (a small dataclass for a run's result, e.g. `CompletedRun(verdicts, report, trace_ids)`, if a tuple of three reads badly).

## What stays unchanged

- The audit graph, the prompts, the guard, `src/`: nothing in the hexagon changes.
- The replay rules, the gates, the recordings, the baselines and their files, `CVERunConditions`, `BaselineConditions`, the fingerprints.
- The order of runs in every baseline and report.
- `audit_honeypot`, `connected` and `audit_connected` (their signatures and bodies).
- `evals/capture_probe_corpus.py` and the probe: not parallelized here.
- The CI workflows: they run with the default concurrency, no flag added (decided in discussion: the nine honeypot audits are small Python processes, far from the 30 s tool call timeout on 4 vCPU, and the report records the concurrency. A false miss traced to load puts `--concurrency 1` in the workflows).

## Edge cases

- `--concurrency 1`: exactly today's sequence of audits, and the same order in every baseline, report and grade (the semaphore is FIFO and tasks start in submission order). The console groups a few lines differently: calibration prints its `live`/`dead` lines once all targets are done.
- A CVE audit that is skipped (launch failure) under concurrency: still `None` in its slot, the target is incomplete, as today.
- A failed teardown in a worker thread: `_best_effort` still logs and does not raise.
- An exception from the audit body with the environment entered in a thread: `__exit__` still runs, in a thread, and the exception still reaches `audit`'s `except`.
- A run of the honeypot evals where one honeypot audit raises: that run fails, the other runs complete, the progress bar still reaches its total.
- Ctrl-C during a gathered run: the tasks are cancelled, their environments' `__exit__` run in threads (the `finally` of `entered_in_thread`). An environment cancelled while its `__enter__` still runs in its thread is never exited: the thread finishes entering and nobody leaves. Its network and sidecar carry the `mcp-auditor-cve` label and are swept as today, its temporary directory stays in the system temp dir.

## Test scenarios

Unit tests, in the Given/When/Then layout of the existing files.

`tests/unit/test_concurrency.py` (new):

- No more than `limit` calls are in flight at once: gather ten calls of a coroutine that records the number in flight around an `await asyncio.sleep(0)`, with `limit=3`, assert the maximum seen is 3.
- Results come back in submission order.
- `limit=0` raises `ValueError`.

`tests/unit/test_cve_session.py`:

- The existing tests stay green unchanged (the scripted audit hands out its script in call order, and `gather` calls in submission order).
- The runs of two targets overlap: an audit that waits on an `asyncio.Event` set only once both targets have started returns, instead of hanging. Guard it with `asyncio.timeout(1)` so a regression fails instead of hanging.
- Two gated targets both missed once each settle their replays, and the comparisons come back in the targets' order.

`tests/unit/test_concurrency.py`, for `entered_in_thread`:

- `entered_in_thread` enters and leaves a context manager, and yields its value.
- It runs `__exit__` when the body raises, and re-raises the body's exception.
- The event loop is not blocked while `__enter__` sleeps: a concurrent coroutine makes progress during a `time.sleep(0.2)` in `__enter__`.

`tests/unit/test_cve_calibration.py` does not reach `calibrate_all` (it tests `dead_conditions` only). The integration test `tests/integration/test_cve_calibration.py` covers it: its two-target test passes `concurrency=2` and still finds each target's line.

`tests/unit/test_eval_fault_harness.py` and the replay tests:

- `audit_honeypots` merges in `HONEYPOTS` order when the audits finish in reverse order.
- `Replayer.settle_flips` folds the replays of two servers in `HONEYPOTS` order, and a failed replay of one server still lets the other settle.
- `FaultedAudit.replay` hands out indices in start order when two replays finish in reverse order. `FaultedAudit` reaches the servers through `ConnectedHoneypot.client`, an `MCPClientPort`, so the test controls the finishing order with a fake client whose `list_tools` waits on an `asyncio.Event`, and a `half_the_detections_lost` fault makes the index observable.

`tests/unit/test_run_evals.py` (or wherever `_post_langsmith_feedback` can be reached): feedback goes to the given trace ids, one call per trace and metric, with a fake LangSmith client if one can be injected cheaply. If injecting a client means adding a Port only for this best-effort call, skip the test and say so in the commit.

`tests/unit/test_run_cve_benchmark.py`: `--concurrency 0` is refused by the parser. The report carries the concurrency.

## Verification

```bash
uv run pytest -n auto
uv run pytest tests/integration -n auto   # the fault injection, several times, for determinism
uv run ruff check . && uv run ruff format --check . && uv run pyright
uv run python -m evals.run_cve_benchmark --calibrate                     # all live, time it against the 47 s measured in sequence
uv run python -m evals.run_cve_benchmark --calibrate --concurrency 1     # same verdicts
uv run python -m evals.run_cve_benchmark --ungated --cve CVE-2025-65513 --cve CVE-2025-53355 --runs 2   # the SSRF sidecar teardown under concurrency, no stall
docker ps -a --filter label=mcp-auditor-cve                              # no orphan after the run
uv run python -m evals.run_evals --ungated                               # one e2e run, wall time against the ~12 min of the last sequential job
```

The measured wall times go in the commit messages, dated, with the machine's core count. They are not written in an ADR.

## Commits

One change per commit:

1. `evals/concurrency.py` and `entered_in_thread`, with their tests.
2. The CVE benchmark: session, audit, calibration, flag, report field.
3. The LangSmith feedback on the traces' own ids (still sequential, so its effect is checkable alone).
4. The honeypot evals: `audit_honeypots`, `Replayer`, the fault harness index, `run_evals`, flag, report field.

## Living docs

- `CLAUDE.md` Commands: `--concurrency N` on `run_evals` and `run_cve_benchmark`, one line each, default 6, 1 for the old sequence.
- `CONTRIBUTING.md`: the same flag beside the eval and benchmark commands.
- `README.md`: the CVE benchmark command block gains the flag in one example.
- `CHANGELOG.md` `[Unreleased]`, `### Changed`: the CVE benchmark, its calibration and the e2e evals run their audits side by side, six at once by default, `--concurrency` sets it, and each report records it. The LangSmith feedback of the e2e evals goes to the traces of its own run.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, checked on 2026-09-28. Later passes (the implementation-phase fact check among them) read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `asyncio.Semaphore` binds to the running loop on first contended `acquire` (`_LoopBoundMixin._get_loop`), not on creation, so building it in synchronous composition code is safe as long as it is used inside a single `asyncio.run` (verified against the CPython 3.13.12 `asyncio/mixins.py` and `asyncio/locks.py` installed in the project, docs.python.org 3.13 asyncio-sync).
- SETTLED: `asyncio.Semaphore` wakes waiters in FIFO order and a newcomer does not barge while waiters are queued, in CPython 3.13 (verified against the installed `asyncio/locks.py`, a `deque` of waiters). The Python docs guarantee fairness for `Lock` only, not for `Semaphore`: this is an implementation property.
- SETTLED: `from langchain_core.tracers.context import collect_runs`, yielding a `RunCollectorCallbackHandler` whose `traced_runs` holds root runs only, so `collector.traced_runs[0].id` is the root run id of the audit's single `graph.ainvoke` (verified against installed langchain-core 1.6.4, `tracers/context.py`, `tracers/run_collector.py`, `tracers/base.py`). The hook is registered non-inheritable through a `ContextVar`, so each task created by `gather` sees its own collector.
- SETTLED: `docker stop` sends SIGTERM and waits 10 s by default on Linux before SIGKILL (verified against docs.docker.com, docker container stop). The sentinel sidecar runs `exec httpd` as PID 1 with no `--init` (verified in `evals/docker/Dockerfile.sentinel` and `evals/cve_environments.py`).
- SETTLED: `ubuntu-latest` on a public repository has 4 CPUs and 16 GB of RAM (2 CPUs and 8 GB on a private one), and `mkrtchian/mcp-auditor` is public (verified against docs.github.com, GitHub-hosted runners reference, and `gh repo view`).
- SETTLED: PEP 695 generic syntax (`def bounded[**P, R]`, `def entered_in_thread[T]`) is available, `requires-python = ">=3.13"` (verified against `pyproject.toml` and the local interpreter 3.13.12).

## Implementation steps

Verification commands (from `CLAUDE.md`): `uv run pytest tests/unit`, `uv run pytest -n auto`, `uv run pytest tests/integration -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`. Every step ends with all of them green (integration tests that need Docker skip without it).

The four commits of the plan become six steps: the CVE commit and the honeypot commit each touch too many files for one session, so each is cut in two along a line where the tree stays green and coherent in between. The step order is the commit order.

### Step 1: the shared bound and the thread-entered context manager

- **Files**: `tests/unit/test_concurrency.py` (new), `tests/unit/support/test_concurrency_given.py` and `..._then.py` only if a helper actually abstracts something, `evals/concurrency.py` (new).
- **Do**:
  - Tests first (see Test), run them red.
  - `evals/concurrency.py`, newspaper order: `bounded[**P, R](call, limit) -> Callable[P, Awaitable[R]]` (raises `ValueError` when `limit < 1`, one `asyncio.Semaphore(limit)` per call to `bounded`, held around `await call(*args, **kwargs)`), then `entered_in_thread[T](manager: AbstractContextManager[T])` as an `@asynccontextmanager` (`__enter__` via `asyncio.to_thread`, body in `try`, on exception `__exit__` via `asyncio.to_thread` with `type(exc), exc, exc.__traceback__` and re-raise unless it returned true, otherwise `__exit__(None, None, None)` in a thread), then `positive_int(text: str) -> int` raising `argparse.ArgumentTypeError` below 1 (and on a non-integer).
  - No caller yet.
- **Test** (`tests/unit/test_concurrency.py`):
  - ten gathered calls with `limit=3`, each recording in-flight count around `await asyncio.sleep(0)`: max seen is 3.
  - results come back in submission order.
  - `bounded(call, 0)` raises `ValueError`.
  - `entered_in_thread` enters, yields the manager's value, and leaves (a small recording context manager).
  - body raises: `__exit__` ran, the body's exception is re-raised.
  - `__enter__` doing `time.sleep(0.2)`: a concurrent coroutine advances meanwhile (e.g. increments a counter in a loop of `await asyncio.sleep(0.01)`), counter > 0 when the enter returns.
  - `positive_int("0")` raises `ArgumentTypeError`, `positive_int("3") == 3`.
- **Verify**: `uv run pytest tests/unit/test_concurrency.py` red then green, then the full command set.

### Step 2: CVE graded audits side by side

- **Files**: `tests/unit/test_cve_session.py`, `tests/unit/support/test_cve_session_given.py`, `tests/unit/test_cve_audit.py`, `tests/unit/test_run_cve_benchmark.py`, `tests/unit/support/test_cve_oracle_given.py`, `evals/cve_session.py`, `evals/cve_audit.py`, `evals/cve_environments.py` (docstring only), `evals/cve_oracle.py`, `evals/run_cve_benchmark.py`, `CLAUDE.md`, `CONTRIBUTING.md`, `README.md`, `CHANGELOG.md`.
- **Do**:
  - Tests first:
    - `test_cve_session.py`: runs of two targets overlap (an audit fake that awaits an `asyncio.Event` set once both targets have started, under `asyncio.timeout(1)`), and two gated targets each missed once settle their replays with comparisons in target order. Existing tests stay unchanged. Add the overlapping fake to the `given` module.
    - `test_cve_audit.py`: `audit_target(budget=10, concurrency=1)`.
    - `test_run_cve_benchmark.py`: `--concurrency 0` refused by the parser (SystemExit from argparse), and the report carries the concurrency (through `render_markdown` or the model, whichever the existing tests reach cheaply).
    - `test_cve_oracle_given.py`: builds `CVEBenchmarkReport(..., concurrency=...)`.
  - `evals/cve_session.py`: `run_gated` calls `_run_targets(session)` (gather over target × run in submission order, sliced per target), `_target_runs(target, outcomes)` holds today's post-await body of `_run_target`. `_gate` computes every `compare_target` first, then gathers `_replayed` for the targets that need it, keeping `runs` order. `_replayed` unchanged. The `AuditTarget` docstring says the audit may be called concurrently. Add `import asyncio`.
  - `evals/cve_audit.py`: `audit_target(budget, concurrency) -> AuditTarget` returns `bounded(audit, concurrency)`, models still built first. `async with entered_in_thread(target.environment()) as launch:`, grade still computed inside. After a completed audit, `console.print(f"{target.cve_id}: {grade.status}")`.
  - `evals/cve_environments.py`: one docstring sentence on why the benchmark enters and leaves these environments in a worker thread (`entered_in_thread`, SSRF sidecar ignores SIGTERM, 10 s stop).
  - `evals/cve_oracle.py`: `CVEBenchmarkReport.concurrency: int` beside `conditions` (not in `CVERunConditions`). `render_markdown` shows it on the conditions line (pass it to `_render_conditions` or append it after). Confirm `fixture_fingerprint` and the baseline files are built from `CVERunConditions` and the target, not the report.
  - `evals/run_cve_benchmark.py`: `CVE_CONCURRENCY = 6`, `--concurrency` with `type=positive_int`, help "Audits in flight at once; 1 runs them one after the other." (step 3 extends it to calibrations), `_harness(args.budget, args.concurrency)`, report built with `concurrency=args.concurrency`.
  - Living docs: `CLAUDE.md` Commands line for `run_cve_benchmark --concurrency N` (default 6, 1 for the old sequence), `CONTRIBUTING.md` beside the benchmark commands, `README.md` one example in the CVE benchmark block, `CHANGELOG.md` `[Unreleased]` `### Changed` entry for the CVE benchmark (the entry is extended by steps 3, 4 and 6).
- **Test**: as above. The overlap test would hang (and fail by timeout) on the sequential code.
- **Verify**: new tests red, then green. Full command set. If Docker and an LLM key are available: `uv run python -m evals.run_cve_benchmark --ungated --cve CVE-2025-65513 --cve CVE-2025-53355 --runs 2`, then `docker ps -a --filter label=mcp-auditor-cve` shows no orphan. Record the wall time and core count for the commit message.

### Step 3: CVE calibration side by side

- **Files**: `tests/integration/test_cve_calibration.py`, `evals/cve_calibration.py`, `evals/run_cve_benchmark.py`, `CHANGELOG.md`, `CLAUDE.md` (only if the step 2 line needs "calibrations").
- **Do**:
  - Test first: the two-target integration test (one target dead at startup) passes `concurrency=2` and still finds each target's line. The other three calls keep the default.
  - `calibrate_all(targets, ci=False, concurrency=1)`: skip lines print first, then gather `bounded(_calibrate_one, concurrency)` over the non-skipped targets, then print the `live`/`dead` lines in target order. `_calibrate_one` enters the environment with `entered_in_thread`, and prints its error and dead reports with no `await` between their lines. A `CalibrationOptions` dataclass is optional.
  - `run_cve_benchmark.py`: `calibrate_all(graded, ci=args.ci, concurrency=args.concurrency)`, flag help becomes "Audits (or calibrations) in flight at once; 1 runs them one after the other."
  - `CHANGELOG.md`: the entry names the calibration too.
- **Test**: the integration test above (skips without Docker if that is how the file behaves today, check).
- **Verify**: `uv run pytest tests/integration/test_cve_calibration.py`, full command set. If Docker is available: `uv run python -m evals.run_cve_benchmark --calibrate` (all live, time it against 47 s) and `--calibrate --concurrency 1` (same verdicts). Record the times for the commit message.

### Step 4: LangSmith feedback on the traces' own ids (still sequential)

- **Files**: `tests/unit/test_run_evals.py` (new, only if a fake client can be injected cheaply) with its `given` module if needed, `evals/run_evals.py`, `CHANGELOG.md`.
- **Do**:
  - In `_run_one_eval`'s audit closure, when LangSmith tracing is on (same env check as `_post_langsmith_feedback`), run the audit inside `langchain_core.tracers.context.collect_runs()` and keep `collector.traced_runs[0].id` after a completed audit (none when `traced_runs` is empty). When tracing is off, no collector.
  - `_run_one_eval` returns the verdicts, the report and the run's trace ids, through a small dataclass (e.g. `CompletedRun(verdicts, report, trace_ids)`) if a triple reads badly.
  - `_post_langsmith_feedback(run_detail, trace_ids)`: one `create_feedback` per trace and metric (recall, precision), no `list_runs`, no `project_name`. Best-effort `try/except` kept.
  - The runs stay sequential in this step.
  - `CHANGELOG.md`: the LangSmith feedback of the e2e evals goes to the traces of its own run.
  - If `run_evals.py` passes 300 lines here, the split described in step 6 can happen now instead.
- **Test**: feedback goes to the given trace ids, one call per trace and metric, with a fake client, if the client can be injected without a new Port. Otherwise no test, and the commit message says why.
- **Verify**: full command set.

### Step 5: honeypots and their replays audited side by side

- **Files**: `tests/unit/test_eval_fault_harness.py`, `tests/unit/support/test_eval_fault_harness_given.py` (and `_then.py` if used), `tests/unit/test_eval_replay.py`, `tests/unit/support/test_eval_replay_given.py`, `evals/honeypots.py`, `evals/replay.py`, `evals/fault_harness.py`.
- **Do**:
  - Tests first:
    - `audit_honeypots` merges in `HONEYPOTS` order when the audits finish in reverse order (a fake audit whose honeypots wait on events released in reverse).
    - `Replayer.settle_flips` folds two servers' replays in `HONEYPOTS` order when they finish in reverse, and a failed replay of one server still lets the other settle.
    - `FaultedAudit.replay` hands out indices in start order when two replays finish in reverse order: a fake `MCPClientPort` whose `list_tools` waits on an `asyncio.Event`, wrapped in `ConnectedHoneypot`, and a `half_the_detections_lost` fault making the index observable. If building a real `FaultedAudit` against a fake client requires models that answer the whole graph, use the existing `FakeLLM` fakes. Keep the test readable through the `given` module.
    - Existing replay tests: `test_each_replay_attempt_announces_one_progress_line` and the audit-count tests may depend on cross-server order. Keep them asserting behavior, adapt only if their assertion was about an order the plan now leaves free.
  - `evals/honeypots.py`: `audit_honeypots` gathers the three audits, merges in `HONEYPOTS` order. Docstring: "One run: every honeypot audited side by side, their verdicts and reports merged in a fixed order."
  - `evals/replay.py`: `settle_flips` gathers a per-honeypot coroutine (holding the try/except, returning the replays or the failure message) over the honeypots with flips, folds results in `HONEYPOTS` order. `_replay_server` unchanged.
  - `evals/fault_harness.py`: `FaultedAudit.replay` takes `index = next(self.audits)` before the first `await`. `runs()` unchanged.
  - Until step 6 adds the bound, a run audits its three honeypots unbounded (three at most), which is harmless.
- **Test**: as above.
- **Verify**: new tests red, then green. `uv run pytest tests/integration -n auto` run at least three times: `tests/integration/test_gate_fault_injection.py` holds every time (read `FixtureJudge` and `RandomJudge` to confirm the plan's claims on per-cell counts and rule-based assertions). Full command set.

### Step 6: the honeypot runner gathers its runs under one bound

- **Files**: `tests/unit/support/test_eval_session_given.py`, `evals/eval_session.py`, `evals/run_evals.py`, possibly a new `evals/` module for the run loop, `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do**:
  - `evals/eval_session.py`: `DEFAULT_CONCURRENCY = 6` beside `DEFAULT_RUNS`, `EvalOptions.concurrency: int`. Not in `BaselineConditions`, not on `EvalSession`. Update `test_eval_session_given.py` to pass it.
  - `evals/run_evals.py`:
    - `--concurrency`, `type=positive_int`, default `DEFAULT_CONCURRENCY`, passed into `EvalOptions`.
    - `_evaluate` calls `run_evals(session, options.concurrency)`.
    - `run_evals` builds `models_for(session.settings)` once and one bounded honeypot audit (`bounded(..., concurrency)`) that prints `f"  Run {index + 1}: auditing [bold]{honeypot.name}[/bold]..."` once its slot is acquired (the bounded function takes what it needs to print, or the print moves inside it), shared by `_run_all` (through the per-run closures) and `_replay_audit`. If building the models once changes behavior, that goes to its own commit.
    - `_run_all` gathers the runs. Each run's coroutine keeps its own try/except (warning, traceback, progress advanced by `len(HONEYPOTS)`), prints `display.print_run_result` and posts its LangSmith feedback on completion. After the gather, completed runs are appended to `outcome` in run index order.
    - `EvalReport.config` gains `"concurrency"`.
    - If the file passes 300 lines, move `_run_all`, `_run_one_eval`, `_post_langsmith_feedback` and what only they use into a new `evals/` module.
  - Living docs: `CLAUDE.md` Commands line for `run_evals --concurrency N`, `CONTRIBUTING.md` beside the eval commands, `CHANGELOG.md` entry names the e2e evals and that each report records the concurrency.
- **Test**: no new unit test beyond the session `given` update (the runner is composition code reached by evals, and the gathering it relies on is tested in steps 1 and 5). Existing unit tests stay green.
- **Verify**: full command set, fault injection integration test again. If an LLM key is available: `uv run python -m evals.run_evals --ungated`, wall time against the ~12 min of the last sequential job, recorded with the core count in the commit message.
