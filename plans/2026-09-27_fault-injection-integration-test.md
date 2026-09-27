# Fault injection as a deterministic integration test, without an LLM

## Context

The plan `plans/2026-09-27_honeypot-recall-floor.md` added a fault injection harness, `evals/run_fault_injection.py`, to discharge the proof ADR 016 names ("The proof is fault injection, named here and still to run"). It audits the three honeypots with the real generator (`gpt-6-luna`), one fault planted per run, 7 faults × 3 runs × 3 honeypots plus the replays, one fault after the other. An audit of the three honeypots takes about 13 minutes on the real model, so one pass of the harness takes several hours, for about $1. It was meant to be run by hand, twice. That is far too heavy for what it proves.

What the fault injection has to prove is wiring: a fault planted in the models reaches the gate through a real audit (the graph, the aggregation of verdicts, `judge_runs`, the replays with the fault still active, the recording decision) and produces the gate's response that ADR 022 and the method note predict. The unit tests in `tests/unit/test_eval_fault_injection.py` already feed faulted observations to the gate functions, but take on trust what an audit makes of each fault: that a refused judgment leaves a cell uncovered, that a dropped category survives the retry and completion loop of the generator and gives a distribution coverage of 0.80, that refused chains leave the chain-only cells with their single-step verdicts, that the fault stays active in the replays. All of that is deterministic code, and a real model adds nothing to it. What a real model adds (a realistic number of cases per cell, the real judge's pattern, real noise in the replays) is either frozen already in the fixture, a real run of 2026-09-27, or not part of what the gate claims.

So the harness becomes an integration test with real honeypot servers and no LLM, deterministic, free, about two minutes, run in CI with the other integration tests. The healthy state reproduces the fixture: a fake judge answers, for each cell and each run, what `gpt-6-luna` observed on 2026-09-27, so the test keeps the fixture's shape (3 stable and correct FAIL cells, 2 unstable, 3 never detected, 28 stable and correct PASS cells) and exercises the gate's real weaknesses. A perfect judge would hide them: it would make the two chain-only flaws stable and correct, turning the documented miss of the chain refusal fault into a catch, and it would never exercise an unstable cell.

## Approach

1. **The harness logic stays, its entry point goes.** `Harness`, `FaultedAudit` and `fixture_refusals` move from `evals/run_fault_injection.py` to `evals/fault_harness.py`, with no CLI, no report file and no print. The models become a constructor argument, the budget too. `evals/run_fault_injection.py` is deleted, with its command in `CLAUDE.md` and `CONTRIBUTING.md`.
2. **Two fakes in `tests/fakes/`**: a schema-keyed generator and a fixture-shaped judge.
3. **The expectations become the test's assertions**: `FAULTS` in `evals/fault_catalog.py` loses its prose `expected` strings for a structured expectation per fault, and `tests/integration/test_gate_fault_injection.py` runs one parametrized test per fault against the committed fixture.
4. **The method note is rewritten** for what the test proves, its scope, and what it does not measure.

## `evals/fault_harness.py` (moved from `evals/run_fault_injection.py`)

```python
@dataclass(frozen=True)
class Harness:
    fixture: Baseline
    base_models: AuditModels
    budget: int

    async def inject(self, fault: Fault) -> FaultResult: ...
```

- `inject` builds `FaultedAudit(fault, fault.models(self.base_models), self.budget)`, runs `DEFAULT_RUNS` runs, judges them with the production `judge_runs` in `PAIRED` and in `FLOORS_ONLY` against the fixture, and decides a first recording of the faulted runs, as today. `FaultResult` keeps its fields but `expected`.
- The conditions are the fixture's own, read from `fixture.conditions` rather than held as a field of their own: its `runs` (3, `DEFAULT_RUNS`) is what `judge_runs` checks the completed runs against, and a first recording (`decide_recording(None, ...)`) compares no conditions.
- `EvalSession` is built from a `Settings` that never reads the environment or `.env`: `Settings.model_construct(provider="openai", model="gpt-6-luna", reasoning="none")`, as `ci_condition_mismatches` already does. A plain `Settings(...)` would still read the `MCP_AUDITOR_*` variables for the fields it does not name. It is only used to satisfy the type: `judge_runs` never reads it and no model is built from it.
- The models are stateful (`FixtureJudge` counts judgments per cell), so each test builds its own `Harness` with fresh fakes: a harness, or its models, shared across the parametrized tests would read the fixture's runs out of step.
- `FaultedAudit` takes the budget instead of reading `DEFAULT_BUDGET`, and keeps its shared audit counter, runs and replays included, so a detection loss is drawn afresh at each audit. `FaultedAudit.runs` stops catching and printing the exception of a failed run: it propagates, so a server that fails to start fails the test with its traceback (see Edge cases). `inject`'s "no run completed" check goes with it. The `Replayer` keeps its own catch on replays (production code): a failed replay shows as a `mismatches` reason in the gate result. Its `announce` and `warn` callables become no-ops.
- `fixture_refusals` stays and keeps `baseline_integrity` against `MERGED_GROUND_TRUTH`: a label revision can make the fixture inconsistent, and the test must say so instead of comparing against it. `condition_refusals` leaves it: the fixture's model and budget are those of the refused recording, the test runs fakes at another budget, and the conditions play no role in the comparison.
- `inject_all`, `main`, `_parse_args`, `_harness_or_refused`, `_refuse`, `_warn`, the printing, `FaultInjectionReport`, `REPORT_PATH` and `REFUSED_EXIT` are deleted with the command. `FIXTURE_PATH` moves with the harness.

The fault wrappers of `evals/fault_injection.py` and `lose_detections` do not change, nor do their unit tests in `tests/unit/test_eval_fault_harness.py`. That file imports `fixture_refusals` from the new module, and its tests of it change with the signature, now `fixture_refusals(fixture: Baseline) -> list[str]`: `test_the_harness_accepts_the_fixture_at_the_current_conditions` becomes "accepts the fixture" with no conditions, `test_the_harness_refuses_a_fixture_recorded_at_other_conditions` is deleted, `test_the_harness_refuses_a_fixture_whose_runs_miss_a_cell` drops its conditions argument. In `tests/unit/support/test_eval_fault_harness_given.py`, `the_current_conditions`, `the_current_conditions_at_budget` and `HARNESS_CONDITIONS_OPTIONS` go with them.

## `evals/fault_catalog.py`

`Fault.expected: str` becomes a structured expectation:

```python
@dataclass(frozen=True)
class Expectation:
    paired: GateVerdict
    floors_only: GateVerdict
    recording_refused: bool
    reasons: tuple[str, ...]  # substrings expected among the gate's or the recording's reasons
```

The values are those of the method note's table for the floors of ADR 022, restated for this test's healthy state (the fixture). The half-loss fault is not pinned to its draws: its outcome depends on the audit index, which the runs and the replays share, so a legitimate change to the number or order of replays would move it with no regression behind it, and re-pinning it would be fitting the test to the gate. Its test asserts only what follows from the gate's rules whatever the draws: the `floors_only` verdict is red exactly when the detections left over the runs fall under the number of runs; every stable and correct FAIL cell of the fixture that a run lost settles as `regression` or `flip_not_reproduced`, never `unchanged`; and the recording is refused for no stable and correct FAIL cell exactly when none of the fixture's stable FAIL cells survived every run. The exactness of the draws stays with the unit tests of `lose_detections`, and the probabilistic claim (about 0.19 per loss under the replay rule) with its derivation in the method note and the docstring of `evals/gate.py`. The random judge's expectation asserts only what holds whatever the draw order: both modes red on precision, PASS cells flipped. Its exact cells depend on the graph's call order and would break on every refactor.

## The fakes, in `tests/fakes/`

### `ScriptedAuditModel` (the generator)

An `LLMPort` keyed on the output schema, independent of the order of calls, which changes with each fault (retries, completions, chain steps, replays):

- `TestCaseBatch`: one case per category of the prompt's categories, arguments `{}` (the server answers with an error, which is still a response to judge). The test runs at budget 5, so a full batch holds the budget and no retry happens in the healthy state.
- `AttackContext`: empty.
- `ChainPlanBatch`: one goal in `info_leakage`, with an empty first step.
- `StepObservation`: `should_continue=False`, so each chain stops after one step.
- `AuditPayload`: an empty payload in `info_leakage`.

The categories of a `TestCaseBatch` prompt are read from it (the prompt lists the categories to cover, which the completion narrows to the missing ones). The list is the block of `- {category}` lines under `Distribute test cases across these attack categories:` in `build_attack_generation_prompt`, ending at the first blank line: the category guidance further down also starts lines with `- info_leakage:` and must not be read as the list. A prompt without that header raises, like the judge's parser.

### `FixtureJudge` (the healthy judge)

An `LLMPort` answering `Judgment` from the fixture:

- It reads the tool and the category from the prompt: `the tool "{name}" has a **{category}**` in the single-step judge prompt (`build_judge_prompt`, `graph/prompts.py`), `against "{name}"` and `Target category: {category}` in the chain judge prompt (`graph/chain_prompts.py`). A prompt matching neither raises, so a reworded prompt breaks the fake loudly, never silently. The parser has its own unit tests.
- It answers the fixture's observation of that cell for the current run. The run is counted per cell: with one case per category, each single-step cell is judged once per audit, so the n-th single-step judgment of a cell belongs to audit n, taken modulo the number of fixture runs. Replays only observe cells that flipped, which are stable in the fixture, so any run gives the same answer there.
- A cell outside the ground truth is answered PASS: the generator asks for all five categories on every tool, and the ground truth leaves out four cells (`get_user × input_validation`, `project_manager × input_validation`, `project_manager × injection`, `user_directory × input_validation`), so their cases are judged but never observed. Raising there would leave those cases unjudged and lower the distribution coverage under the fixture's 1.00.
- For the chain-only cells (`CHAIN_ONLY_FLAWS`: `project_manager × info_leakage`, `user_directory × info_leakage`), it answers PASS on single-step prompts and the fixture's observation on chain prompts, so that refusing the chains removes exactly those verdicts, as in a real audit. It counts chain judgments per cell the same way. These are the only cells a chain judgment reaches: only the chain honeypot has a chain budget, and the fake plans one `info_leakage` chain per tool. `CHAIN_ONLY_FLAWS` moves from `tests/unit/support/test_eval_fault_injection_given.py` to the `FixtureJudge` module, with its comment, and the two unit given modules import it from there: a fake must not import from a test's support module.
- An uncovered observation in the fixture is answered by raising `ProviderRefusal`, which leaves the cell unjudged.

## `tests/integration/test_gate_fault_injection.py`

- A module-scoped fixture loads `evals/fixtures/fault_injection_baseline.json` and asserts `fixture_refusals` is empty.
- **The healthy run first**: the harness with no fault (a `Fault` with no wrapper, its `Expectation` both modes green, recording accepted, no reason) reproduces the fixture: `PAIRED` green with every gated cell unchanged, and the observations of each run equal to the fixture's. This is the test that shows the fakes stand for the fixture; every fault test rests on it.
- **One parametrized test per fault** in `FAULTS`, asserting its `Expectation` on the `FaultResult`.
- The given/then support modules follow the project's pattern where they abstract something: `tests/integration/support/test_gate_fault_injection_given.py` and `..._then.py`, next to the test as `tests/unit/support/` is to the unit tests.

Expected cost: about 130 audits (63 for the runs, about 70 replays, the deterministic faults stopping after 4 replays per flipped server), at about 0.36 s per server spawn plus the graph steps for about 40 cases per server, roughly 1.5 to 2.5 minutes if run one after the other, against about 15 seconds for the integration suite today. That is too slow to add as is. So:

- **The eight scenarios run concurrently.** A module-scoped async fixture builds one `Harness` per scenario, each with its own fresh fakes (the fakes keep per-cell counters, so nothing is shared), and awaits all of them with `asyncio.gather`. The healthy-run test and the parametrized fault tests only assert on the results it returns. The scenarios are independent: each spawns its own server processes and owns its audit counter. The wall time becomes that of the longest scenario, expected around 15 to 25 seconds. With pytest-asyncio in `auto` mode (`pyproject.toml`), a module-scoped async fixture needs `loop_scope="module"`, and the tests that read it the same loop scope, or they run on another event loop than the one the fixture's servers live on.
- **The implementation measures it** (`pytest --durations`) and writes the figure in the method note. If the suite still takes more than about 30 seconds over today's, the next lever, in this order: one connected client per honeypot and scenario, reused across its audits through the injected audit function, instead of a server spawn per audit, provided the honeypots hold no state across calls that a scenario would carry into the next audit (the chain honeypot is checked first).
- **A job timeout in CI**: `.github/workflows/ci.yml` gains `timeout-minutes: 20` on the job that runs the tests, so a server that hangs at spawn cannot hold a runner for GitHub's default of several hours. This is a line of CI configuration, in the same commit as the test.

## `evals/fault_injection_method.md`

Rewritten as the note of the integration test:

- What it proves: a fault planted in the models reaches the gate through a real audit and produces the gate's response on the floors of ADR 022, the fault active in the replays. What it does not prove: what a real model detects (the honeypot evals and the CVE benchmark measure that), and the gate's response at another operating point than the fixture's, recorded on 2026-09-27. When a first confirmed baseline exists, the fixture can move to it.
- The two fakes and why the healthy judge reproduces the fixture instead of the ground truth.
- The faults, the replay rule and its 6/32, as today.
- The expectation table for the floors of ADR 022, which the test asserts. The table for the floors at 0.50 goes: those floors no longer exist, and their expectations are pinned in history by `35aeaec`. The *Recorded runs* section goes: the test runs on every CI build.
- ADR 003 defines the integration level as real MCP servers and no LLM. This test is the first at that level to exercise the eval gate rather than an adapter. The note says so, and `CONTRIBUTING.md` too.

## Living docs

- `CLAUDE.md`, Commands: the `run_fault_injection` line goes. The `pytest tests/integration` line says it includes the fault injection on the gate.
- `CONTRIBUTING.md`: the command line and the paragraph on the harness (lines 26 and 85 at the time of writing) become one paragraph on the integration test, with no key needed.
- The docstring of `evals/gate.py` that points at the method note keeps a valid pointer.
- `CHANGELOG.md`: nothing, the harness was never listed there.
- No labeling log entry: this changes no label, honeypot or scoring code (ADR 020), and the plan says so in its commit message.

## What stays unchanged

- The gate, the floors, the recording condition, the replay rule, the eval runner and CI's eval workflows.
- `evals/fault_injection.py` (the fault wrappers and `lose_detections`), its unit tests, the unit tests on the fixture, the fixture itself.
- The product (`src/`).
- ADRs and past plans.

## Edge cases

- **A reworded judge prompt**: `FixtureJudge` raises, and the healthy-run test fails first with the unmatched prompt in its message.
- **A label revision**: `fixture_refusals` reports the inconsistency and the test fails before any audit, pointing at rebuilding the fixture.
- **A change in how many cases the generator's batch holds per category**: the per-cell count would misread the run. The fake generator is the only source of cases, at one per category, and the healthy-run test catches a drift.
- **A honeypot server that fails to start**: the harness's run fails as any integration test would; no retry is added.

## Test scenarios

- `FixtureJudge` unit tests: parses the single-step and the chain prompt, raises on an unmatched prompt, answers the fixture per run and per cell, answers PASS on single-step prompts for the chain-only cells, raises `ProviderRefusal` on an uncovered observation.
- `ScriptedAuditModel` unit tests: one case per requested category, the completion's narrower category list honored, the other schemas answered.
- The healthy-run integration test, then the seven fault tests.
- `tests/unit/test_eval_fault_harness.py` keeps passing after the move.

## Verification

```bash
uv run pytest tests/unit
uv run pytest tests/integration
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

## Commit messages

The commits say that the fault injection moves from a harness run by hand on a real model to an integration test on fakes, and why: it proves wiring, which a real model does not change. No plan, step or phase named.

## Due diligence record

What the plan-diligence pass concluded about the external facts this plan cites or defers to implementation. Later passes, the implementation-phase fact check included, read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- No external facts to verify: the plan cites and defers no third-party API, library, CI action, version or platform behavior. `gpt-6-luna` appears only as a value to satisfy `Settings`, from which no model is built, and the timings are local measurements.

## Implementation steps

### Step 1: The two fakes and their unit tests

- **Files**:
  - `tests/unit/test_eval_fault_fakes.py` (create), with `tests/unit/support/test_eval_fault_fakes_given.py` only where a helper abstracts something (a single-step and a chain judge prompt built with the production prompt builders, a fixture with a known observation per run)
  - `tests/fakes/scripted_audit_model.py` (create): `ScriptedAuditModel`
  - `tests/fakes/fixture_judge.py` (create): `FixtureJudge` and `CHAIN_ONLY_FLAWS`
  - `tests/unit/support/test_eval_fault_injection_given.py` (modify): `CHAIN_ONLY_FLAWS` and its comment move out, imported from `tests.fakes.fixture_judge`
  - `tests/unit/support/test_eval_fault_harness_given.py` (modify): imports `CHAIN_ONLY_FLAWS` from `tests.fakes.fixture_judge`
- **Do**:
  1. Tests first, in `tests/unit/test_eval_fault_fakes.py` (see Test), run red.
  2. `ScriptedAuditModel`, an `LLMPort` (`generate_structured(prompt, output_schema)`, `total_usage`) dispatching on `output_schema`, independent of call order:
     - `TestCaseBatch`: one case per category read from the prompt, arguments `{}`. The categories are the `- {category}` lines of the block right under `Distribute test cases across these attack categories:` (`build_attack_generation_prompt`, `src/mcp_auditor/graph/prompts.py`), ending at the first blank line. Lines further down such as `- info_leakage: ...` (the guidance) must not be read. A prompt without the header raises `ValueError` with the prompt in the message.
     - `AttackContext`: empty. `ChainPlanBatch`: one goal in `info_leakage` with an empty first step. `StepObservation`: `should_continue=False`. `AuditPayload`: empty payload in `info_leakage`. Build each with the real model constructors (read `src/mcp_auditor/domain/models.py` for required fields).
     - Any other schema raises `TypeError`.
  3. `FixtureJudge(fixture: Baseline)`, an `LLMPort` answering `Judgment`:
     - Parses tool and category: single-step `the tool "{name}" has a **{category}**` (`build_judge_prompt`, `graph/prompts.py`), chain `against "{name}"` plus `Target category: {category}` (`graph/chain_prompts.py`). Neither matches: raise `ValueError` carrying the prompt.
     - Keeps two per-cell counters (single-step, chain). The n-th judgment of a cell of a kind reads `fixture.runs[n % len(fixture.runs)]`.
     - Cell outside `MERGED_GROUND_TRUTH`: `PASS`. Cell in `CHAIN_ONLY_FLAWS` on a single-step prompt: `PASS` (counter not advanced for chain purposes). Chain prompt: fixture's observation for that cell.
     - Observation `FAIL`/`PASS` maps to the `Judgment` verdict. An uncovered observation raises `ProviderRefusal` (check its constructor in `mcp_auditor/domain/ports.py`).
     - Read how the fixture stores observations (`evals/baseline.py`, `evals/gate.py` `Observation`, `cell_key`) before choosing the lookup.
  4. Move `CHAIN_ONLY_FLAWS` (with its comment on the chain honeypot) into `tests/fakes/fixture_judge.py`, update both unit given modules to import it. Keep `test_eval_fault_harness_given`'s `__all__` re-export only if the unit test still reads it through `given`.
- **Test** (`tests/unit/test_eval_fault_fakes.py`):
  - `ScriptedAuditModel`: a full attack prompt from `build_attack_generation_prompt` yields one case per listed category (5), and not an extra one from the guidance lines. A completion prompt listing fewer categories yields exactly those. A prompt with no header raises. `AttackContext`, `ChainPlanBatch`, `StepObservation`, `AuditPayload` are answered as specified.
  - `FixtureJudge`: parses a real single-step and a real chain judge prompt (built with the production builders). Raises on an unmatched prompt. Successive single-step judgments of one cell follow the fixture's runs in order, wrapping after the last. A cell outside the ground truth is PASS. A chain-only cell is PASS on single-step prompts and the fixture's observation on chain prompts. An uncovered observation raises `ProviderRefusal`.
  - Use the committed fixture `evals/fixtures/fault_injection_baseline.json` or a small `Baseline` built in the given module, whichever keeps the expectation readable.
- **Verify**: new tests red first, then green. `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` all pass.

### Step 2: Move the harness to `evals/fault_harness.py` and structure the expectations

- **Files**:
  - `tests/unit/test_eval_fault_harness.py` (modify), `tests/unit/support/test_eval_fault_harness_given.py` (modify)
  - `evals/fault_harness.py` (create), `evals/run_fault_injection.py` (delete)
  - `evals/fault_catalog.py` (modify)
  - `CLAUDE.md`, `CONTRIBUTING.md` (modify: command lines only)
- **Do**:
  1. Tests first: `test_eval_fault_harness.py` imports `fixture_refusals` from `evals.fault_harness`. `test_the_harness_accepts_the_fixture_at_the_current_conditions` becomes `test_the_harness_accepts_the_fixture` calling `fixture_refusals(fixture)`. `test_the_harness_refuses_a_fixture_recorded_at_other_conditions` is deleted. `test_the_harness_refuses_a_fixture_whose_runs_miss_a_cell` drops its conditions argument. In the given module, delete `the_current_conditions`, `the_current_conditions_at_budget`, `HARNESS_CONDITIONS_OPTIONS` and the imports only they used.
  2. `evals/fault_harness.py` as in the plan's section: `FIXTURE_PATH`, `FaultResult` (fields of today minus `expected`), `fixture_refusals(fixture: Baseline) -> list[str]` (only `baseline_integrity(fixture, MERGED_GROUND_TRUTH)`, docstring kept), `Harness(fixture, base_models, budget)` with `inject(fault)`, `_session(mode)`, `_recording_refusals(...)`, and `FaultedAudit(fault, models, budget, audits)`.
     - Conditions: `self.fixture.conditions` for `EvalSession` and `Recording`, `DEFAULT_RUNS` for runs and `completed_all`.
     - Settings: `Settings.model_construct(provider="openai", model="gpt-6-luna", reasoning="none")` (never reads the env), as in `ci_condition_mismatches`.
     - `FaultedAudit.runs` no longer catches: an exception propagates. The "no run completed" check goes. `_report` does not print and passes `self.budget` to `audit_honeypot`.
     - `Replayer(audit.replay, HONEYPOTS, announce=_ignore, warn=_ignore)` with a no-op.
     - Delete everything the plan lists as going (`inject_all`, `main`, `_parse_args`, `_harness_or_refused`, `_refuse`, `_warn`, printing, `FaultInjectionReport`, `REPORT_PATH`, `REFUSED_EXIT`). Update the module docstring (no command, no "real calls", points at `evals/fault_injection_method.md`).
  3. `evals/fault_catalog.py`: add `Expectation(paired: GateVerdict, floors_only: GateVerdict, recording_refused: bool, reasons: tuple[str, ...])`, frozen. `Fault.expected: str` becomes `Fault.expectation: Expectation | None`, `None` for the half-loss fault only (its assertions are computed in the test, see step 3). Fill each fault from the prose it replaces, the reasons being short substrings of the gate's and recording's actual reason strings: read `evals/gate.py`, `evals/gate_verdict.py`, `evals/recording.py` for their wording (for example `recall`, `precision`, `distribution_coverage`, `regression`, and the recording's "no stable and correct" wording). Per fault:
     - `judge_passes_everything`: both red, refused, recall + regression + no stable and correct FAIL cell.
     - `judge_fails_everything`: both red, refused, precision + regression + no stable and correct PASS cell.
     - `judge_fails_at_random`: both red, refused, precision only (the PASS-cell flip is asserted in the test, not pinned per cell).
     - `no_verdict`: both red, refused, recall + distribution_coverage + regression.
     - `generator_drops_error_handling`: PAIRED red, FLOORS_ONLY green, accepted, regression.
     - `provider_refuses_chain_steps`: both green, accepted, no reason.
     The module docstring states the expectations are the integration test's assertions.
  4. `CLAUDE.md`: delete the `run_fault_injection` line, and the `uv run pytest tests/integration` comment says it includes the fault injection on the gate. `CONTRIBUTING.md`: delete the command at line 26. Leave the paragraph at line 85 for step 3, but remove its command sentence so no doc points at a deleted module.
- **Test**: the three kept/changed `fixture_refusals` tests and every other test of `tests/unit/test_eval_fault_harness.py` and `tests/unit/test_eval_fault_injection.py` pass. `grep -rn run_fault_injection --include=*.py --include=*.md . | grep -v plans/` returns nothing.
- **Verify**: `uv run pytest tests/unit`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` pass. The harness is not run in this step.

### Step 3: The integration test, CI timeout and the method note

- **Files**:
  - `tests/integration/support/__init__.py` (create), `tests/integration/support/test_gate_fault_injection_given.py` (create), `tests/integration/support/test_gate_fault_injection_then.py` (create)
  - `tests/integration/test_gate_fault_injection.py` (create)
  - `.github/workflows/ci.yml` (modify)
  - `evals/fault_injection_method.md` (rewrite), `CONTRIBUTING.md` (modify), `evals/gate.py` (docstring pointer only, if it no longer holds)
- **Do**:
  1. Given module: loads `FIXTURE_PATH` with `load_baseline`. `a_harness(fixture) -> Harness` with fresh `AuditModels(llm=ScriptedAuditModel(), judge_llm=FixtureJudge(fixture))` and budget 5. `HEALTHY = Fault("healthy", Expectation(GREEN, GREEN, False, ()))`. A module-scoped async fixture (`@pytest_asyncio.fixture(scope="module", loop_scope="module")`) asserts `fixture_refusals(fixture) == []`, then builds one `Harness` per scenario (healthy + each of `FAULTS`) and awaits `asyncio.gather` of their `inject`, returning results by fault name. Tests reading it use `pytestmark = pytest.mark.asyncio(loop_scope="module")` (or the equivalent that keeps them on the fixture's loop).
  2. Then module: `expectation_met(result, expectation)` asserting both verdicts, the recording decision, and that each expected reason substring appears among `paired.reasons + floors_only.reasons + recording_refusals`, with a message printing the observed result. `the_fixture_reproduced(result, fixture)`: `PAIRED` green, every gated cell `unchanged`, each run's observations equal to the fixture's (read `RunsOutcome`/`FaultResult`/`GateResult` to find where the observations and cell outcomes are exposed, and extend `FaultResult` in `evals/fault_harness.py` with the observations only if nothing already exposes them). `the_half_loss_obeys_the_rules(result, fixture)`: `floors_only` red iff the detections left over the runs fall under the number of runs; every stable and correct FAIL cell of the fixture that a run lost settles `regression` or `flip_not_reproduced`, never `unchanged`; the recording is refused for no stable and correct FAIL cell iff none of the fixture's stable FAIL cells survived every run. For `judge_fails_at_random`, also assert that some PASS cells flipped.
  3. Test file: `test_the_healthy_audit_reproduces_the_fixture`, then `test_the_gate_answers_each_fault` parametrized over `FAULTS` with an `expectation` (ids = fault names), and `test_losing_half_the_detections_obeys_the_gate_rules`. Run with `uv run pytest tests/integration/test_gate_fault_injection.py --durations=10`. If the healthy test fails, fix the fakes (step 1's modules), never the fixture or the gate. If a fault's expectation fails, check first whether the expectation of step 2 misread the gate's wording; a real disagreement with the method note is reported, not fitted.
  4. Measure the suite's duration (`uv run pytest tests/integration --durations=10`). If it adds more than about 30 seconds over today's ~15, apply the plan's next lever (one connected client per honeypot and scenario, checking the chain honeypot holds no state across calls first) and remeasure.
  5. `.github/workflows/ci.yml`: `timeout-minutes: 20` on the `check` job.
  6. `evals/fault_injection_method.md` rewritten per the plan's section: what the test proves and does not, the two fakes and why the judge reproduces the fixture, the faults, the replay rule and its 6/32, the ADR 022 expectation table (the 0.50 table and *Recorded runs* go, pointing at `35aeaec`), the first integration test on the gate rather than an adapter (ADR 003), and the measured duration. `CONTRIBUTING.md`: the fault-injection paragraph becomes one paragraph on the integration test, no key needed, first at that level to exercise the eval gate. Check `evals/gate.py`'s docstring pointer still reads true.
  7. Commit message (for whoever commits): the fault injection moves from a harness run by hand on a real model to an integration test on fakes because it proves wiring, which a real model does not change. No labeling log entry: no label, honeypot or scoring code changes (ADR 020). No plan, step or phase named.
- **Test**: the healthy-run test, the six fault tests with an `Expectation`, the half-loss rule test.
- **Verify**: `uv run pytest tests/unit`, `uv run pytest tests/integration` (duration recorded), `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` all pass.
