# One test per fault scenario, and the integration suite run in parallel with pytest-xdist

## Context

`tests/integration/test_gate_fault_injection.py` runs its eight scenarios (the healthy audit and the seven faults of `evals/fault_catalog.py`) in a module-scoped async fixture that awaits `asyncio.gather` over one `Harness.inject` per scenario, then serves the results to nine tests. That design has three costs. A scenario that raises fails the whole `gather`, so all nine tests error and the failing fault is hidden. The module-scoped fixture needs a module event loop (`pytest_asyncio.fixture(scope="module", loop_scope="module")` and `pytestmark = pytest.mark.asyncio(loop_scope="module")`), the only such machinery in the suite. And the random judge's draws depend on how the eight scenarios interleave on the shared loop.

The aim of this change is isolation: each scenario becomes its own test, which injects its own fault and asserts on it. Run one after the other, the eight scenarios take about 60 seconds, so the integration suite is run in parallel with `pytest-xdist` to keep its duration where it is.

Measured on 2026-09-27 on a 16-core machine, with a prototype of one test per scenario and `pytest-xdist` added on the fly:

| Run | Duration |
|---|---|
| Integration suite today (gather, no xdist) | 32 s |
| Integration suite today under `-n auto` | 60 s (every worker recomputes the module fixture) |
| The 8 scenarios, one test each, no xdist | 60 s |
| The 8 scenarios, one test each, `-n 8` | 18 s |
| Integration suite, one test per scenario, `-n 4` | 28 s |
| Integration suite, one test per scenario, `-n auto` | 25 s |
| The 32 other integration tests, no xdist / `-n 4` | 16 s / 8 s |
| Unit suite, no xdist / `-n 4` / `-n auto` | 3.6 s / 4.2 s / 7.9 s |

The scenarios are CPU-bound as much as they are I/O-bound (one process with `gather` takes 16 s, eight xdist workers take 18 s), so the speed gain comes from the 32 other integration tests, not from the fault injection. The duration stays about the same. What changes is that the tests are independent.

## Approach

- Add `pytest-xdist` as a dev dependency.
- Rewrite the fault injection test module so that each scenario is injected exactly once, by the test that asserts on it, with no shared fixture.
- Pass `-n auto` on the integration command only (CI and living docs), and on the documented full-suite command. Nothing goes in `addopts`: under `-n auto` the unit suite slows from 3.6 s to 7.9 s from worker start-up alone, and the developer loop runs `uv run pytest tests/unit`.

## `pyproject.toml` and `uv.lock`

`uv add --dev pytest-xdist` adds it to `[dependency-groups] dev` with a lower bound at the version it resolves, following the `>=` style of the other entries, and updates `uv.lock`. The version is whatever uv resolves on the day. `pytest-asyncio` stays: every async test still needs it, under `asyncio_mode = "auto"`.

## `tests/integration/test_gate_fault_injection.py`

No module-scoped fixture, no `pytest_asyncio` import, no `pytestmark`: under `asyncio_mode = "auto"` each async test gets its own function-scoped loop, like the other integration tests.

```python
FIXTURE = given.the_fixture()
RANDOM_JUDGE = "judge_fails_at_random"
HALF_LOSS = "half_the_detections_lost"
PINNED_FAULTS = [f for f in FAULTS if f.expectation is not None and f.name != RANDOM_JUDGE]


async def test_the_healthy_audit_reproduces_the_fixture():
    healthy = await given.injected(given.HEALTHY, FIXTURE)
    assert given.HEALTHY.expectation is not None
    then.expectation_met(healthy, given.HEALTHY.expectation)
    then.the_fixture_reproduced(healthy, FIXTURE)


@pytest.mark.parametrize("fault", PINNED_FAULTS, ids=lambda fault: fault.name)
async def test_the_gate_answers_each_fault(fault: Fault):
    assert fault.expectation is not None
    then.expectation_met(await given.injected(fault, FIXTURE), fault.expectation)


async def test_a_random_judge_breaks_precision_and_flips_pass_cells():
    fault = given.fault_named(RANDOM_JUDGE)
    result = await given.injected(fault, FIXTURE)
    assert fault.expectation is not None
    then.expectation_met(result, fault.expectation)
    then.some_pass_cells_flipped(result)


async def test_losing_half_the_detections_obeys_the_gate_rules():
    result = await given.injected(given.fault_named(HALF_LOSS), FIXTURE)
    then.the_half_loss_obeys_the_rules(result, FIXTURE)
```

The random judge leaves the parametrized list and gets one test holding both of its assertions, so that it is injected once and not twice (it is the slowest scenario, about 10 s). The `assert ... expectation is not None` narrowings are required by pyright strict (`Fault.expectation` is `Expectation | None`, and `expectation_met` takes an `Expectation`). They stay inline, as above: a given helper would only wrap that one line. The module's imports shrink to `pytest`, `given`, `then` and `FAULTS, Fault` from `evals.fault_catalog`: `pytest_asyncio`, `FaultResult` and `fixture_refusals` go (ruff would flag them unused), the last one moving to the given module. The test count goes from 9 to 8: the healthy test, five parametrized faults, the random judge and the half-loss rule, one test per scenario.

## `tests/integration/support/test_gate_fault_injection_given.py`

- `every_scenario_injected` goes, and so does the `asyncio` import.
- New `async def injected(scenario: Fault, fixture: Baseline) -> FaultResult`: it asserts `fixture_refusals(fixture) == []`, then returns `await a_harness(fixture).inject(scenario)`. The check moves here from the deleted module fixture so that a stale fixture still fails every test with the integrity reason, before any audit runs, instead of producing confusing gate failures.
- New `fault_named(name: str) -> Fault`: looks up `FAULTS` by name, raising if the name is absent, so a renamed fault fails loudly instead of skipping.
- `a_harness`, `HEALTHY`, `BUDGET` and `the_fixture` stay. The docstring of `every_scenario_injected` ("each scenario gets its own harness...") moves to `injected` or `a_harness`, since that reason still holds.

## `tests/integration/support/test_gate_fault_injection_then.py`

Unchanged.

## CI and living docs

- `.github/workflows/ci.yml`: the integration step runs `uv run pytest tests/integration -n auto -v`. The unit step does not change. A standard GitHub-hosted Linux runner has fewer cores than the machine above, so the CI duration is measured on the first run and not predicted here. `timeout-minutes: 20` stays.
- `CLAUDE.md`, Commands: `uv run pytest -n auto` for unit and integration together, and `uv run pytest tests/integration -n auto` for the integration tests (comment kept: fault injection included, one test needs Docker). `uv run pytest tests/unit` unchanged.
- `CONTRIBUTING.md`: the same commands at lines 11 and 18. Line 84 says the fault injection is "run by `uv run pytest tests/integration`": add `-n auto`. Line 121 (`uv run pytest && ...` before a release) gets `-n auto` too.
- `evals/fault_injection_method.md`, last paragraph (line 68, "The eight scenarios ... run concurrently"): each scenario is now its own test, run in parallel by pytest-xdist with its own fakes and server processes, with the durations measured at implementation time: the scenarios alone and the integration suite, under `-n auto`, on the implementer's machine, with its core count. The method note is a living note beside the eval, not an ADR, so it is edited in place.
- `CHANGELOG.md`: no entry, the change is dev-only.

## What stays unchanged

- `evals/fault_harness.py`, `evals/fault_catalog.py`, `evals/fault_injection.py`, the fakes in `tests/fakes/`, the gate and the fixture. The assertions of the then module.
- The other integration tests. They are already xdist-safe: each spawns its own stdio server processes, `test_confined_launch` uses `tmp_path` and a container name with a random suffix, and no integration test uses a module- or session-scoped fixture once this change removes the only one.
- The unit tests and the unit CI step: no `-n`.
- `pyproject.toml` `[tool.pytest.ini_options]`: no `addopts`.

## Edge cases

- `uv run pytest tests/integration` without `-n` still works, sequentially, in about 76 s. That is a supported way to run it, only slower.
- A scenario that raises now fails its own test only. The other scenarios still report.
- `-n auto` on a machine with one core runs a single xdist worker: the tests run one after the other, but in one worker subprocess, not in the main process (`-n 0` or `-p no:xdist` is the truly sequential run).
- The random judge's draws come from a seeded `random.Random` per `RandomJudge` (`evals/fault_injection.py`). With one scenario per test, the draws no longer interleave with other scenarios. They still depend on the order of the judge calls inside one audit (`audit_honeypots` may audit the honeypots concurrently), which is why its test asserts by rule and not on the exact flipped cells.

## Test scenarios

The eight tests above, all green under `-n auto` and without `-n`. No unit test changes: the harness, the catalog and the fakes are untouched.

## Verification

- `uv run pytest tests/integration/test_gate_fault_injection.py -n auto --durations=10`: 8 passed.
- `uv run pytest tests/integration/test_gate_fault_injection.py -p no:xdist`: 8 passed, sequentially, to prove the tests do not depend on xdist.
- `uv run pytest tests/integration -n auto --durations=10`: all pass, duration recorded for the method note.
- `uv run pytest -n auto`, `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: all pass.
- `grep -rn "every_scenario_injected\|loop_scope" tests/`: nothing.

## Commit message

The fault injection test gives each scenario its own test, so a fault that raises no longer hides the others, and the integration suite runs in parallel under pytest-xdist to keep its duration. Name no plan, step or phase.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, written so that the implementation-phase fact check can read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, on 2026-09-27, not what is true now. A human who edits one of these facts by hand deletes the line rather than updating it.

- SETTLED: `-n auto` sizes the workers from the CPU count, and `-n 0` disables distribution and runs in the main process (verified against the pytest-xdist distribution docs and `src/xdist/plugin.py` on GitHub)
- SETTLED: `-p no:xdist` disables the plugin, pytest's standard `-p no:<name>` mechanism applied to the `xdist` entry point (checked against pytest's plugin mechanism; xdist's docs do not mention it, so the Verification section is where it is proved in practice)
- SETTLED: the standard `ubuntu-latest` GitHub-hosted runner has fewer cores than 16: 4 vCPU on a public repository, 2 on a private one (verified against docs.github.com, GitHub-hosted runners reference)
- OPEN (deferred): the `pytest-xdist` lower bound in `[dependency-groups] dev`, left to what `uv add --dev pytest-xdist` resolves on the day (PyPI showed 3.8.0 at verification time, requiring `pytest>=7.0.0` and Python `>=3.9`, compatible with the pinned `pytest>=9.0` and Python 3.13)
- OPEN (unverified): whether `-n auto` counts physical or logical cores without `psutil` (docs say physical, the master source tries `os.process_cpu_count()` first, which counts logical ones), so the worker count on the 16-core machine and on CI is observed, not predicted

## Implementation steps

### Step 1: One test per fault scenario, integration suite under pytest-xdist

**Files**
- `pyproject.toml`, `uv.lock` (via `uv add --dev pytest-xdist`)
- `tests/integration/test_gate_fault_injection.py` (rewrite)
- `tests/integration/support/test_gate_fault_injection_given.py` (modify)
- `.github/workflows/ci.yml` (integration step)
- `CLAUDE.md`, `CONTRIBUTING.md`, `evals/fault_injection_method.md` (living docs)

**Do**
1. Run `uv add --dev pytest-xdist`. Check that it lands in `[dependency-groups] dev` with a `>=` lower bound and that `uv.lock` changed. Leave `[tool.pytest.ini_options]` without `addopts`.
2. Tests first: rewrite `tests/integration/test_gate_fault_injection.py` as in the plan section of the same name. Keep the module docstring. Drop `pytest_asyncio`, `pytestmark`, the `results` fixture, `FaultResult` and `fixture_refusals` imports. Define `FIXTURE`, `RANDOM_JUDGE = "judge_fails_at_random"`, `HALF_LOSS = "half_the_detections_lost"`, `PINNED_FAULTS` (faults with an expectation, minus the random judge). Four test functions: `test_the_healthy_audit_reproduces_the_fixture`, `test_the_gate_answers_each_fault` (parametrized over `PINNED_FAULTS`, ids by name), `test_a_random_judge_breaks_precision_and_flips_pass_cells` (expectation plus `some_pass_cells_flipped`, one injection), `test_losing_half_the_detections_obeys_the_gate_rules`. Keep the `assert ... expectation is not None` narrowings inline. Run it: it fails because `given.injected` and `given.fault_named` do not exist yet.
3. In the given module: delete `every_scenario_injected` and the `asyncio` import. Add `async def injected(scenario: Fault, fixture: Baseline) -> FaultResult` that asserts `fixture_refusals(fixture) == []` (import it from `evals.fault_harness`) then returns `await a_harness(fixture).inject(scenario)`. Move the "each scenario gets its own harness: the fakes count judgments per cell..." docstring onto `injected` or `a_harness`. Add `def fault_named(name: str) -> Fault` that looks up `FAULTS` by name and raises (e.g. `next(...)` over a generator, or an explicit `ValueError`) when absent. Keep `a_harness`, `HEALTHY`, `BUDGET`, `the_fixture`. Place helpers newspaper order (public before the private `a_harness` they call).
4. `.github/workflows/ci.yml`: integration step becomes `uv run pytest tests/integration -n auto -v`. Unit step and `timeout-minutes` unchanged.
5. `CLAUDE.md` Commands: `uv run pytest -n auto` for unit + integration, `uv run pytest tests/integration -n auto` for integration (keep its comment about Docker), `uv run pytest tests/unit` unchanged.
6. `CONTRIBUTING.md`: add `-n auto` at line 11 (`uv run pytest`), line 18 (integration), line 84 (`run by uv run pytest tests/integration -n auto`), line 121 (release check `uv run pytest -n auto && ...`). Line 17 (unit) unchanged.
7. Run the verification commands below, record the durations and the core count, then rewrite the last paragraph of `evals/fault_injection_method.md` ("## Cost"): each scenario is its own test, run in parallel by pytest-xdist with its own fakes and server processes, with the measured durations of the scenarios alone and of the integration suite under `-n auto`, dated, with the machine's core count. No `CHANGELOG.md` entry.

**Test**
- 8 tests in `test_gate_fault_injection.py`: the healthy audit (expectation met and fixture reproduced), five parametrized pinned faults (each expectation met), the random judge (expectation met and some pass cells flipped), the half-loss rule.
- No unit test changes.

**Verify**
- `uv run pytest tests/integration/test_gate_fault_injection.py -n auto --durations=10`: 8 passed.
- `uv run pytest tests/integration/test_gate_fault_injection.py -p no:xdist`: 8 passed.
- `uv run pytest tests/integration -n auto --durations=10`: all pass (the Docker test may skip), duration noted for the method note.
- `uv run pytest -n auto`, `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: all pass.
- `grep -rn "every_scenario_injected\|loop_scope" tests/`: no output.
