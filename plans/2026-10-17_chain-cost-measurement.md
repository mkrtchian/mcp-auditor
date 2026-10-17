# Chain cost measurement on the acceptance benchmark

## Context

The holdout rule makes the chain settings (chains per tool, steps per chain) and the tool call timeout run conditions, the same for every target, set in `docs/holdout-log.md` before the first run that uses them. `evals/holdout_conditions.json` carries them as `null`, and `require_ready` refuses a holdout run until they are set. They are to be set on cost alone, from a run of the acceptance benchmark under the holdout's conditions.

No tool runs that measurement today:

- `run_cve_benchmark` takes each target's chain settings from its launch (0 everywhere but the git target) and its tools filter from the target. A holdout run audits every tool with the same chain settings for every target, so the acceptance conditions say nothing of a holdout run's cost.
- `RunOverrides` (`evals/cve_audit.py`) already carries chain settings and timeout, but only the holdout run mode builds one.
- The CVE report gives one token total for the whole session, no split by target or phase, and no dollars.
- The audit report splits usage by role (`judge_usage`), not by phase. With chains on, one run at the highest chain setting considered is enough to estimate lower settings only if the chain share is known: chains per tool are independent sequences, so their cost scales roughly with their count.

Already settled elsewhere, not redone here: a call that fails (refusal, unreadable answer, exhausted 429) is a missed step that carries its usage (`graph/missed_steps.py`), the audit goes on, and `SessionThrottles` bills every report counted, replayed attempts included.

## Approach

Three pieces, one per commit:

1. **Chain usage in the audit report** (`src/`, additive). A `chain_usage` channel beside `judge_usage`: every chain step, and every missed chain step, adds its usage to it. The chain judgment is both a judge step and a chain step, so it counts in both channels, as it already counts in `judge_usage`. Each split is exact on its own (role: generator against judge; phase: single-step against chains); the four-way cross is not, since the chain judgments alone are not isolated. Nothing needs that cross today: extrapolating to fewer chains needs the whole chain cost, judgments included (one per chain), and pricing by role needs only `judge_usage`.
2. **Measurement flags and per-target cost in the CVE benchmark** (`evals/`). Four flags, accepted only with `--ungated`: `--chains N`, `--chain-steps M`, `--tool-call-timeout T`, `--no-tools-filter`. Any of them makes the run a measurement run, which builds a `RunOverrides` for every target. The report records the forced settings in a field of its own, never in `CVERunConditions`, so no baseline comparison reads them. Every ungated run whose models all have a price in `evals/holdout_conditions.json` reports, per target, the usage of single-step tests, chains and judge summed over every attempt, and their cost in dollars; a measurement run whose models lack a price is refused before any container starts.
3. **Haiku 5.5 in the holdout conditions** (data), and the living docs. The cost run and the tooling-phase holdout run under Haiku 5.5, so its price and its published cutoff go into `evals/holdout_conditions.json`, with a line in `docs/holdout-log.md`.

After implementation, out of this plan: the cost run itself and the chain values written to `holdout_conditions.json` and the log (procedure at the end).

## Changes

### 1. `chain_usage` (commit `feat: split chain usage in the audit report`)

- `src/mcp_auditor/domain/models.py`:
  - `CHAIN_STEPS = frozenset({AuditStep.CHAIN_PLANNING, AuditStep.CHAIN_STEP_OBSERVATION, AuditStep.CHAIN_STEP_PLANNING, AuditStep.CHAIN_JUDGMENT})` and `is_chain_step(step: AuditStep) -> bool`, beside `JUDGE_STEPS` / `is_judge_step`.
  - `AuditReport.chain_usage: ProviderUsage = ProviderUsage()`, with a field comment saying the chain judgment counts here and in `judge_usage`.
  - `AuditReport.single_step_usage` property: `provider_usage.sub(chain_usage)` (single-step generation, context extraction and single-step judgments).
- `src/mcp_auditor/domain/models.py`, `ProviderUsage.largest_input_tokens: int = 0`: the input tokens of the largest single request. `add` keeps the larger of the two, `sub` keeps the minuend's (a maximum does not subtract, so `generator_usage` and `single_step_usage` carry the total's). The adapter (`src/mcp_auditor/adapters/llm.py`) sets it to the attempt's `input_tokens` wherever it builds an attempt's usage. Why: some vendors bill a request by its own size (Haiku 5.5 charges five times more above 100,000 input tokens per request), and usage summed before pricing cannot show it.
- `src/mcp_auditor/graph/state.py`: `chain_usage: Annotated[list[ProviderUsage], operator.add]` in `GraphState` and `ChainAuditState`, so the chain subgraph's updates reach the parent like `judge_usage` does. `AuditToolState` is unchanged.
- `src/mcp_auditor/graph/chain_nodes.py`: every node that returns `provider_usage` (`plan_chains`, `observe_step`, `plan_step`, `judge_chain`) also returns `chain_usage: [usage]` on its success path. Their missed paths already go through `Missed.state_update()`.
- `src/mcp_auditor/graph/missed_steps.py`: `Missed` gains `is_chain: bool`, set from `is_chain_step(call.step)`, and `state_update` adds `chain_usage` when it is set, as it does for `judge_usage`.
- `src/mcp_auditor/graph/nodes.py`, `generate_report`: sums `chain_usage` into the report.

The report JSON gains one field with a default, so reports and checkpoints written before keep loading. No verdict, prompt or graph route changes, so no eval number moves and no fingerprint moves (the graph is not fingerprinted).

### 2. Measurement flags and per-target cost (commit `feat(evals): measure chain cost on the acceptance benchmark`)

- `evals/cve_audit.py`: `RunOverrides` gains `audit_every_tool: bool = False`, and its three settings become `int | None`, `None` meaning the launch's own (`launch.chain_budget`, `launch.max_chain_steps`, `TOOL_CALL_TIMEOUT`): today they are required ints and `_audit` / `_silent_client` replace all three at once, so a measurement run with `--no-tools-filter` alone could not keep each launch's chains. `_audit` resolves each setting on its own, and passes `tools_filter=None` when `audit_every_tool` is set, `target.tools_filter` otherwise. The holdout keeps building `RunOverrides(chain, steps, timeout)` positionally with three ints, as today (its targets carry no filter, refused up front).
- `evals/cve_audit.py`, `audit_target(budget, throttles, places)`: gains `overrides: RunOverrides | None = None` and passes it to `attempt_once`, which already takes it. Today `audit_target` passes none, so without this the CVE benchmark's harness (`run_cve_benchmark._harness`) cannot apply the flags.
- `evals/metrics.py`, `SessionThrottles`: keeps its role, the session's billing record. `count(report, target_id: str | None = None)`: with an id, it also adds the report's phase usage to `by_target[target_id]`, a `PhaseUsage` (total, chain, judge, each a `ProviderUsage`, with `add`). `run_evals` keeps calling `count(report)`.
- `evals/cve_audit.py`, `attempt_once`: calls `throttles.count(report, target.cve_id)`, so every attempt of a target is billed to it, discarded and replayed attempts included. The replay against the patched version calls no model and bills nothing.
- `evals/cve_costs.py` (new, pure): `TargetCost`, a pydantic `BaseModel` since it is serialized in `CVEBenchmarkReport` (cve id, `PhaseUsage`, dollars for single-step, chains, judge and total), and `target_costs(by_target, generator_prices, judge_prices) -> list[TargetCost]`, built on `call_cost` (`evals/probe.py`). `PhaseUsage` is a pydantic `BaseModel` too for the same reason. Total and judge dollars are exact by role, as `holdout_run._run_cost` computes them: generator usage (total minus judge) at the generator's price, judge usage at the judge's. The single-step and chain columns cannot be split by role, since the chain judgments are not isolated (see piece 1): they are priced at the shared price when the generator and judge prices are equal, as in every current run, and left `None` otherwise. Decided by the maintainer on 2026-10-17: the single-step and chain columns stay `None` when the judge is priced apart; a `chain_judge_usage` channel waits for the day generator and judge run on different models.
- `evals/cve_oracle.py`: `CVEBenchmarkReport` gains `measurement: MeasurementSettings | None = None` (chains, chain steps, tool call timeout, every tool audited) and `costs: list[TargetCost] = []`, with `prices_as_of` when costs are present. `render_markdown` adds a cost table when `costs` is not empty (target, tokens in and out, single-step, chains, judge, total in dollars) and a line with the forced settings when `measurement` is set. The table's lines come from `render_cost_table(costs) -> list[str]` in `evals/cve_costs.py`, and `render_markdown` only splices them in, as it does `_render_gate`: `cve_oracle.py` is at 254 lines and `render_markdown` already past 20. `CVERunConditions` and the baseline files are untouched.
- `evals/cve_measurement.py` (new, pure): `MeasurementSettings` (pydantic, serialized in `CVEBenchmarkReport`), `run_overrides(measurement) -> RunOverrides`, and `missing_price(prices, models) -> str | None`, the refusal text when the generator or judge model has no price. `run_cve_benchmark.py` is at 285 lines, so the measurement logic lives here and the runner only parses the flags and wires these in.
- `evals/run_cve_benchmark.py`:
  - `_parse_args`: the four flags. `--chains` takes a non-negative int (a new small parser beside `positive_int` in `evals/concurrency.py`), `--chain-steps` and `--tool-call-timeout` a positive int (`positive_int`: a chain of 0 steps runs nothing), `--no-tools-filter` is a switch.
  - `_flag_refusal`: a measurement flag without `--ungated`, or with `--calibrate`, `--survey` or `--record-baseline`, is refused (`a measurement run is ungated: its conditions match no baseline`). `--chain-steps` without `--chains` above 0 is refused too.
  - A measurement run reads the prices from `evals/holdout_conditions.json` (`load_conditions(CONDITIONS_PATH).prices`, keyed by `Settings.resolve_model()` and `resolve_judge_model()`) and refuses, by raising `Refused` from `_run_graded` (exit 3), before any audit when the generator or judge model has none. An ungated run without measurement flags reports costs when both prices exist and says in one line that it does not otherwise. A gated run reports no cost.
  - `_harness` builds the session's `RunOverrides` from the flags (`None` for a flag not given) and passes it to `audit_target`.
  - Every cost table also gives each target's largest request in input tokens, and the run prints a warning naming the targets with a request over 100,000 input tokens: above that size the flat `Prices` under-reports a tiered vendor such as Anthropic (decided by the maintainer on 2026-10-17).
  - Settings missing from the flags take the launch's own: a measurement run with `--no-tools-filter` alone keeps each launch's chains and timeout.
  - `CVERunConditions.tools_filtered` stays `True`: the record of the forced settings lives in `measurement`.

### 3. Haiku 5.5 conditions and living docs (commit `docs: chain cost measurement and Haiku 5.5 run conditions`)

- `evals/holdout_conditions.json`: `claude-haiku-5-5` under `cutoffs` (date `2026-06-30`, type `reliable knowledge cutoff and training data cutoff, both June 2026, month only`, note `the last day of the month is taken, the vendor gives the month`) and under `prices` (list prices, verified at the vendor on the commit's date, with `cached_input` at the cache-read price: `input` 0.10, `cached_input` 0.01, `output` 0.50, the tier for prompts up to 100,000 tokens, as listed on 2026-10-17). `prices_as_of` moves to the date both models' prices are verified.
- `docs/holdout-log.md`: an entry for the Haiku 5.5 conditions, saying it runs the tooling-phase holdout and the cost run and that the chain settings stay deferred.
- `CLAUDE.md` Commands: `uv run python -m evals.run_cve_benchmark --ungated --chains N --chain-steps M --tool-call-timeout T --no-tools-filter`, one line on what it measures and that it never gates.
- `README.md`, `CONTRIBUTING.md` where they list the CVE benchmark modes, and `CHANGELOG.md` `[Unreleased]`: the measurement flags, the chain usage in the audit report, the per-target cost.

## What stays unchanged

- Every verdict, prompt, route and default of the auditor, the CLI's output (the console usage line keeps its total).
- `CVERunConditions`, the CVE baselines, the gate, the grammar and fixture fingerprints, the calibration and the survey.
- The holdout run mode and its report (`run_cost` keeps pricing `generator_usage` and `judge_usage`).
- The honeypot e2e eval and the judge eval (they call `count(report)` and see no difference).

## Edge cases

- A target whose every attempt is refused or crashes before an audit: no report, so no cost line; the markdown lists it with no cost.
- An attempt that raises mid-audit (`_audit` wraps any exception in `LaunchError`): no report comes back, so the tokens it spent are billed nowhere, in `by_target` as in the session total today. The cost table under-reports such a target; the console already prints the skip.
- A run with `--chains 0`: `chain_usage` is zero and the chain columns read 0.
- `--no-tools-filter` on a target with many tools (kubernetes, 21): only the cost grows; the run is ungated.
- A prices file that has the generator's price but not the judge's (different judge model): refused like a missing generator price.
- The chain judgment counted in both `judge_usage` and `chain_usage`: `TargetCost.total` is computed from the total usage, never by adding the three phase columns, which overlap.

## Tests

Unit (fakes), given/then files in `tests/unit/support/` as the existing ones:

- `tests/unit/test_graph.py`: an audit with chains on (fake LLM) reports a `chain_usage` equal to the sum of the chain calls' usage, chain judgment included; an audit with chains off reports a zero `chain_usage`; `single_step_usage` equals the total minus the chain usage.
- `tests/unit/test_chain_nodes.py`: a missed chain step (refused, unreadable) adds its usage to `chain_usage`.
- `tests/unit/test_nodes.py`: a missed single-step judgment adds no `chain_usage` (beside the existing `judge_usage` cases there).
- `tests/unit/test_cve_audit.py`: with `audit_every_tool`, the graph receives no tools filter; without it, the target's filter; an override with a `None` setting keeps the launch's own for that setting only; two attempts of one target are both billed to it.
- `ProviderUsage` (domain unit tests beside the existing ones): `add` keeps the larger `largest_input_tokens`, `sub` keeps the minuend's; the adapter's attempt usage carries the attempt's input tokens as its largest request (fake chat model).
- `tests/unit/test_cve_costs.py` (new): phase dollars and total from known usage and prices; generator and judge priced apart when they differ. `render_cost_table` lists one row per target.
- `tests/unit/test_cve_oracle.py`: `render_markdown` shows the cost table when `costs` is set and the forced settings line when `measurement` is set, neither otherwise; a report JSON without the two fields still loads.
- `tests/unit/test_run_cve_benchmark.py`: each measurement flag without `--ungated`, or with `--calibrate`, `--survey`, `--record-baseline`, is refused; `--chain-steps` without chains is refused; a measurement run with a model missing from the prices is refused before any audit.
- `tests/unit/test_holdout_conditions.py`: the committed file loads with the Haiku entry, and `require_ready` still refuses on the null chain settings.

Integration: none new; the existing CVE benchmark integration tests run unchanged.

## Verification

- `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`.
- A dry check of the flags with no model call: `uv run python -m evals.run_cve_benchmark --chains 3` exits 3 with the refusal.
- The gated evals are not run for this change: no verdict path changes.

## After implementation (not in this plan)

1. The cost run, under Haiku 5.5 with reasoning (the tooling-phase model), at the product's chain setting as the highest value considered: `--ungated --chains 3 --chain-steps 3 --tool-call-timeout 30 --no-tools-filter`, 3 runs, budget 10, the four acceptance targets. Other values can be run with the same flags.
2. From the per-target chain share, estimate a holdout run (20 targets, 3 runs) at that setting and below, on cost alone, never on the detections the report also shows.
3. Write the chosen chain settings and the 30 s timeout into `evals/holdout_conditions.json` and `docs/holdout-log.md`, in their own commit.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, as of 2026-10-17, read by the implementation-phase fact check. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `claude-haiku-5-5` is the Claude API model id (verified against platform.claude.com/docs/en/models/overview)
- SETTLED: Haiku 5.5 cutoffs: reliable knowledge cutoff "Jun 2026" and training data cutoff "Jun 2026", month only, so `"date": "2026-06-30"` by the last-day convention (verified against platform.claude.com/docs/en/models/overview)
- SETTLED: `claude-haiku-5-5` prices `"input": 0.10`, `"cached_input": 0.01`, `"output": 0.50`, for prompts up to 100,000 tokens (verified against platform.claude.com/docs/en/about-claude/pricing)
- SETTLED: `gpt-6-luna` prices `"input": 0.10`, `"cached_input": 0.01`, `"output": 0.50`, Standard tier, input up to 272K tokens, unchanged from the committed file (verified against developers.openai.com/api/docs/pricing)
- SETTLED by the plan's check (maintainer, 2026-10-17): Haiku 5.5 bills prompts over 100,000 tokens at `input` 0.50, `cached_input` 0.05, `output` 2.50, per request, and 5-minute cache writes at 1.25x input. The flat `Prices` shape cannot carry either, so a cost run with such requests is under-reported; the largest request per target and the warning above make it visible.
- OPEN (deferred): `prices_as_of`, the date the implementing commit re-checks both prices at the vendors.


## Implementation steps

Verification commands (from `CLAUDE.md`): short loop `uv run pytest tests/unit -n auto --maxprocesses 4`, `uv run pyright <changed files>`, `uv run ruff check .`. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .` and `uv run pyright` with no file argument, all green.

### Step 1: chain usage and largest request in the audit report

Commit: `feat: split chain usage in the audit report` (piece 1 of Changes).

- **Files**: `tests/unit/test_models.py` (+ `support/test_models_given.py` if setup grows), `tests/unit/test_llm_adapter.py`, `tests/unit/test_graph.py` (+ `support/test_graph_given.py`, `support/test_graph_then.py`), `tests/unit/test_chain_nodes.py` (+ its given/then), `tests/unit/test_nodes.py` (+ its given/then); then `src/mcp_auditor/domain/models.py`, `src/mcp_auditor/adapters/llm.py`, `src/mcp_auditor/graph/state.py`, `src/mcp_auditor/graph/chain_nodes.py`, `src/mcp_auditor/graph/missed_steps.py`, `src/mcp_auditor/graph/nodes.py`.
- **Do** (tests first, see them red):
  - Tests per the Tests section, the `src/` lines: `ProviderUsage.add` keeps the larger `largest_input_tokens`, `sub` keeps the minuend's; the adapter's attempt usage carries the attempt's `input_tokens` as `largest_input_tokens` (fake chat model, both usage builders at `adapters/llm.py` around lines 268 and 289); chains-on audit reports `chain_usage` equal to the sum of the chain calls' usage, chain judgment included; chains-off audit reports a zero `chain_usage`; `single_step_usage == provider_usage.sub(chain_usage)`; a missed chain step (refused, unreadable) adds its usage to `chain_usage`; a missed single-step judgment adds none.
  - `domain/models.py`: `CHAIN_STEPS` frozenset (`CHAIN_PLANNING`, `CHAIN_STEP_OBSERVATION`, `CHAIN_STEP_PLANNING`, `CHAIN_JUDGMENT`) and `is_chain_step(step: AuditStep) -> bool` beside `JUDGE_STEPS` / `is_judge_step`. `ProviderUsage.largest_input_tokens: int = 0`, `add` takes the max, `sub` keeps self's. `AuditReport.chain_usage: ProviderUsage = ProviderUsage()` with a field comment that the chain judgment counts here and in `judge_usage`, and a `single_step_usage` property. The file is at 353 lines already: keep the addition tight, do not split the module in this step.
  - `adapters/llm.py`: set `largest_input_tokens` to the attempt's `input_tokens` in both places an attempt's usage is built.
  - `graph/state.py`: `chain_usage: Annotated[list[ProviderUsage], operator.add]` in `GraphState` and `ChainAuditState` (not `AuditToolState`).
  - `graph/chain_nodes.py`: `plan_chains`, `observe_step`, `plan_step`, `judge_chain` return `chain_usage: [usage]` beside `provider_usage` on their success path.
  - `graph/missed_steps.py`: `Missed.is_chain: bool` from `is_chain_step(call.step)`, `state_update` adds `chain_usage` when set, as for `judge_usage`.
  - `graph/nodes.py`, `generate_report`: sum `chain_usage` into the report.
- **Test**: about 8 cases above. Existing report and checkpoint loading must keep passing (new fields have defaults).
- **Verify**: closing commands green. No eval runs (no verdict, prompt or route changes).

### Step 2: per-target billing and per-setting overrides in the CVE audit

Commit: `feat(evals): bill CVE attempts per target, override each run setting on its own`. Split from piece 2 only for the context budget: this is the audit and billing half, step 3 the report and runner half.

- **Files**: `tests/unit/test_cve_audit.py` (+ `support/test_cve_audit_given.py`), `tests/unit/test_eval_metrics.py` (+ `support/test_eval_metrics_given.py`); then `evals/cve_audit.py`, `evals/metrics.py`.
- **Do** (tests first):
  - Tests: with `audit_every_tool`, the graph receives no tools filter, without it the target's filter; an override with a `None` setting keeps the launch's own for that setting only (chains from `launch.chain_budget`, steps from `launch.max_chain_steps`, timeout `TOOL_CALL_TIMEOUT`) while the others take the override; two attempts of one target are both billed to `by_target[cve_id]`; `SessionThrottles.count(report)` without an id leaves `by_target` empty and keeps the throttle count as today; `PhaseUsage.add` sums its three channels.
  - `evals/metrics.py`: `PhaseUsage` pydantic `BaseModel` (`total`, `chain`, `judge`, each `ProviderUsage`, default zero) with `add(other) -> PhaseUsage` and a `from_report(report)` constructor (or equivalent) reading `provider_usage`, `chain_usage`, `judge_usage`. `SessionThrottles.by_target: dict[str, PhaseUsage]`, `count(report, target_id: str | None = None)` adds the report's phase usage to it when an id is given. `run_evals` callers unchanged.
  - `evals/cve_audit.py`: `RunOverrides` gains `audit_every_tool: bool = False`, its three settings become `int | None` (positional order kept, the holdout keeps building `RunOverrides(chain, steps, timeout)` with ints). `_audit` and `_silent_client` resolve each setting on its own, `None` meaning the launch's own, and pass `tools_filter=None` when `audit_every_tool`, `target.tools_filter` otherwise. `audit_target(budget, throttles, places, overrides: RunOverrides | None = None)` passes it to `attempt_once`. `attempt_once` calls `throttles.count(report, target.cve_id)`. The patched replay bills nothing (unchanged). Keep `cve_audit.py` under ~300 lines.
- **Test**: about 6 cases above. The holdout tests (`tests/unit/test_holdout*`) must pass unchanged.
- **Verify**: closing commands green, plus `uv run pytest tests/integration -n auto -k cve` for the CVE integration files that import `cve_audit` (they skip without Docker).

### Step 3: measurement flags and cost table in the CVE benchmark

Commit: `feat(evals): measure chain cost on the acceptance benchmark` (the rest of piece 2).

- **Files**: `tests/unit/test_cve_costs.py` (new, + `support/test_cve_costs_given.py` if setup is more than one-liners), `tests/unit/test_cve_oracle.py` (+ `support/test_cve_oracle_given.py`), `tests/unit/test_run_cve_benchmark.py`; then `evals/cve_costs.py` (new), `evals/cve_measurement.py` (new), `evals/cve_oracle.py`, `evals/run_cve_benchmark.py`, `evals/concurrency.py`.
- **Do** (tests first):
  - Tests: `target_costs` gives single-step, chain, judge and total dollars from known `PhaseUsage` and equal prices, total computed from the total usage (never the sum of the overlapping phase columns); with generator and judge priced apart, total and judge stay exact by role (generator usage = total minus judge at the generator's price) and the single-step and chain columns are `None`; `render_cost_table` lists one row per target with tokens in and out and the largest request; `render_markdown` shows the cost table when `costs` is set and the forced settings line when `measurement` is set, neither otherwise; a report JSON without `measurement` and `costs` still loads; each measurement flag without `--ungated`, or with `--calibrate`, `--survey`, `--record-baseline`, is refused; `--chain-steps` without `--chains` above 0 is refused; a measurement run with a generator or judge model missing from the prices is refused (`Refused`, exit 3) before any audit.
  - `evals/cve_costs.py` (pure): `TargetCost` pydantic model (cve id, `PhaseUsage`, `single_step`, `chains`, `judge`, `total` dollars, single-step and chains `float | None`, largest request in input tokens). `target_costs(by_target, generator_prices, judge_prices) -> list[TargetCost]` on `evals.probe.call_cost`. `render_cost_table(costs) -> list[str]`. The 100,000 input-token threshold as a named constant and a pure function naming the targets above it, for the runner's warning.
  - `evals/cve_measurement.py` (pure): `MeasurementSettings` pydantic (chains, chain steps, tool call timeout, all `int | None`, `every_tool: bool`), `run_overrides(measurement) -> RunOverrides`, `missing_price(prices, models) -> str | None`.
  - `evals/cve_oracle.py`: `CVEBenchmarkReport.measurement: MeasurementSettings | None = None`, `costs: list[TargetCost] = []`, `prices_as_of: date | None = None`. `render_markdown` splices in `render_cost_table` lines and the forced-settings line, keeping each function near 20 lines (extract a helper as `_render_gate` does). A target with no report has no cost row. `CVERunConditions` untouched.
  - `evals/concurrency.py`: a `non_negative_int` parser beside `positive_int`.
  - `evals/run_cve_benchmark.py`: the four flags in `_parse_args` (`--chains` non-negative, `--chain-steps` and `--tool-call-timeout` `positive_int`, `--no-tools-filter` switch). `_flag_refusal` adds the refusals (`a measurement run is ungated: its conditions match no baseline`). `_run_graded` loads `load_conditions(CONDITIONS_PATH).prices`, keyed by `Settings.resolve_model()` and `resolve_judge_model()`, and raises `Refused` via `missing_price` before any audit on a measurement run. An ungated run without measurement flags reports costs when both prices exist and prints one line that it does not otherwise; a gated run reports none. `_harness` builds `run_overrides(...)` (`None` for each flag not given) and passes it to `audit_target`. After the run, costs come from `throttles.by_target`, go into the report with `prices_as_of`, and the runner prints a warning naming targets with a request over 100,000 input tokens. The file is at 285 lines: keep logic in the two new modules, the runner only parses and wires.
- **Test**: about 12 cases above.
- **Verify**: closing commands green. Dry check with no model call: `uv run python -m evals.run_cve_benchmark --chains 3` exits 3 with the refusal (`echo $?`).

### Step 4: Haiku 5.5 run conditions and living docs

Commit: `docs: chain cost measurement and Haiku 5.5 run conditions` (piece 3).

- **Files**: `tests/unit/test_holdout_conditions.py`; then `evals/holdout_conditions.json`, `docs/holdout-log.md`, `CLAUDE.md`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do** (test first):
  - Test: the committed file loads with a `claude-haiku-5-5` cutoff and price, and `require_ready` still refuses on the null chain settings.
  - `evals/holdout_conditions.json`: `claude-haiku-5-5` under `cutoffs` and `prices` exactly as piece 3 states. Re-check both models' list prices at the vendors on the commit's date (the due diligence record leaves `prices_as_of` open) and set `prices_as_of` to that date. If a price differs from the plan, stop and report rather than write it.
  - `docs/holdout-log.md`: an entry for the Haiku 5.5 conditions (runs the tooling-phase holdout and the cost run, chain settings stay deferred).
  - `CLAUDE.md` Commands: the `--ungated --chains N --chain-steps M --tool-call-timeout T --no-tools-filter` line, what it measures, that it never gates.
  - `README.md`, `CONTRIBUTING.md` where they list CVE benchmark modes, and `CHANGELOG.md` `[Unreleased]`: the measurement flags, the chain usage in the audit report, the per-target cost.
- **Test**: 1 to 2 cases above.
- **Verify**: closing commands green.
