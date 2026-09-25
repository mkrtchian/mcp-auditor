# Retest of `gpt-6-luna` at low reasoning: what the probe must record, and the generator's literal sizes

## Context

[ADR 019](../docs/adr/019-default-model-selection.md) admitted no challenger. `gpt-6-luna` was measured at reasoning effort `medium` only, because at `none` and `low` it looped on calls made before the probe (`evals/probe_method.md`, *Observations before the ADR 019 revision*): writing a resource-abuse case, it repeated one character in a string argument for over a million characters. At `medium`, its nine failed calls in the report of the ADR 019 run (`output/probe_report.json`, gitignored, committed by this plan) are all `TestCaseBatch` calls:

- Two errors on the honeypot corpus, `ValueError: Exceeds the limit (4300 digits) for integer string conversion`, on integers of 18,582 and 20,541 digits.
- Seven parse failures on the CVE corpus, each lasting 150 to 185 seconds over three attempts, recorded with zero tokens.

Two lines of the generator prompt (`src/mcp_auditor/graph/prompts.py`, `build_attack_generation_prompt`) ask for values with no size: `input_validation` asks for "extremely large values" on integer fields, and `resource_abuse` for "extremely large limits". Nothing bounds the size of the literal a model writes to honour them.

The retest of `gpt-6-luna` at `none` and `low` comes before the first honeypot baseline is recorded, and iterates only against defects that can be seen call by call, without any label: a loop, an answer cut at the output cap, a batch that does not parse, a giant integer, an incomplete batch. Never against the judge F1 or the honeypot metrics. This plan builds what that retest needs and fixes the prompt. It does not run the retest, recapture the corpus, change the probe's challengers or bars, or record a baseline.

**The corpus holds the prompt as captured.** Every `TestCaseBatch` call of `evals/fixtures/probe_corpus.json` still says "extremely large", so a subset run on it would replay the prompt this plan replaces. The retest therefore runs on a debugging corpus recaptured after the prompt commit, on the reference settings, and recaptured again if the debugging changes the prompt once more. The admission run gets its own recapture, taken after the last prompt change and distinct from the debugging one, so the honeypot calls a prompt was debugged on, which come from a stochastic audit, are not the ones it is admitted on. The CVE generation prompts are built from the tool definitions alone and come out the same in both corpora: that part of the separation does not hold, and is stated here rather than engineered around. Both recaptures are done by hand after this plan (see *After this plan*).

Three gaps stand in the way today:

1. **A parse failure loses its usage.** `LLM.generate_structured` (`src/mcp_auditor/adapters/llm.py`) accumulates the usage of every attempt, then raises `UnparseableOutput` without it. The probe records zero tokens, so the cost of a candidate that fails to parse is understated (the method note states it as a limit), and the seven failures above cost nothing on paper.
2. **A truncated attempt looks like non-conforming JSON.** `_was_truncated` detects an answer cut by the 8,192-token cap and retries, but the fact is lost when the last attempt fails. Truncation and malformed JSON call for different remedies (a smaller reasoning setting or prompt, against a strict schema), and the probe cannot tell them apart.
3. **The probe only runs whole.** Every candidate on every call of the corpus. Debugging `gpt-6-luna` at `none` and `low` on the `TestCaseBatch` calls alone would replay the reference, the three challengers and the fallback on the whole corpus each time.

## Approach

Four commits, in this order. The prompt change is alone in its commit, since it is the only change to the system under test.

0. **The report of the ADR 019 run is committed.** `output/probe_report.json` is copied as is to `evals/probe_runs/2026-09-25_adr-019.json`. It is the evidence the *Outcome* of ADR 019 rests on and the only record of the `medium` failures above, and `output/` is gitignored, so the next full probe run would overwrite it. It holds statistics and observations (candidate, call id, usage, outcome, error message), no prompt and no response, about 370 KB. The `.jsonl` twin is not committed: the JSON holds every one of its observations.
1. **Failed attempts keep their usage and their truncation.** `UnparseableOutput` carries the usage accumulated over all attempts and the number of attempts cut by the output cap. The probe records both on the observation, so failed attempts count in the weighted cost, and a parse failure says whether truncation caused it.
2. **A subset run of the probe.** `run_probe` takes `--candidates` and `--schema`. Either one makes the run a subset run: it replays the named candidates on the calls of that schema, writes the observations as they come, prints a table of defects per candidate, and computes no admission. Two candidates are declared for it, `gpt-6-luna` at `none` and at `low`, outside the challengers of ADR 019.
3. **The generator bounds the size of its literals.** One rule in the generator prompt: an integer beyond any plausible limit needs at most 10 digits, a string argument stays under 1,000 characters, and resource exhaustion is probed by what the argument asks the tool to do, not by the size of the argument. The two category lines lose "extremely large".

### Why the prompt rule holds with every measurement deleted

A literal of thousands of digits or of a million characters proves nothing a 10-digit integer or a short string does not: 2^31 is already 10 digits and exceeds any limit a tool plausibly sets on a count, an ID or a page size. Such a literal costs output tokens at the model's price, can be cut by the output cap and fail the batch, cannot be converted to a Python integer past 4,300 digits, and is sent to the audited server as a payload whose transport, not whose logic, is tested. A resource-abuse test is about asking the tool for unbounded work (a huge limit, a wildcard, a cross-join), which a short argument does.

Why not have the model describe a large payload and expand it in code: that changes the `TestCase` schema of the domain, for a need no audit has shown yet. It stays available if a bounded literal proves too weak.

## Files to modify

### `src/mcp_auditor/domain/ports.py`

```python
class UnparseableOutput(ValueError):
    """The model answered, but no attempt matched the requested schema."""

    def __init__(self, attempts: int, truncated_attempts: int, usage: TokenUsage):
        super().__init__(f"LLM returned unparseable output after {attempts} attempts")
        self.truncated_attempts = truncated_attempts
        self.usage = usage
```

The message keeps its current wording, which a test matches.

### `src/mcp_auditor/adapters/llm.py`

`generate_structured` counts truncated attempts and passes the accumulated usage to the exception. `_unpack_raw_response` returns the truncation flag alongside the parsed output and the usage, instead of turning a truncated answer into `None`:

```python
async def generate_structured[T: BaseModel](self, prompt, output_schema) -> tuple[T, TokenUsage]:
    structured = self._bind(output_schema)
    accumulated_usage = TokenUsage()
    truncated_attempts = 0
    for _attempt in range(self._max_parse_attempts):
        raw_response = await structured.ainvoke(prompt)
        parsed, usage, truncated = self._unpack_raw_response(raw_response)
        accumulated_usage = accumulated_usage.add(usage)
        if truncated:
            truncated_attempts += 1
            continue
        output = _validated(parsed, output_schema)
        if output is not None:
            return output, accumulated_usage
    raise UnparseableOutput(self._max_parse_attempts, truncated_attempts, accumulated_usage)
```

If the function passes 20 lines, the truncation bookkeeping moves to a small private helper. No change to `_was_truncated`, `_validated`, the providers or the output cap.

### `evals/probe.py`

- `ProbeObservation` gains `truncated_attempts: int = 0`, the number of attempts cut by the output cap on a parse failure (0 on any other outcome). The default keeps `output/probe_report*.jsonl` files written before this change readable.
- A pure function for the subset run's table, below `summarize`:

```python
class DefectCounts(BaseModel):
    candidate: str
    calls: int
    parse_failures: int
    parse_failures_with_truncation: int  # at least one attempt cut by the output cap
    refusals: int  # same rule as the admission, _is_refusal
    errors: int


def count_defects(candidate: str, observations: list[ProbeObservation]) -> DefectCounts: ...
```

`summarize`, `admit` and the bars do not change. The weighted cost now includes failed attempts because the observations carry their usage, not because the formula changes.

### `evals/probe_candidates.py`

A new list, after `FALLBACK`, commented as measured only in a subset run and never admitted by the probe:

```python
RETEST_CANDIDATES = [
    Candidate(
        name="gpt-6-luna none",
        settings=Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none"),
        prices=Prices(input=0.10, cached_input=0.01, output=0.50),
        reasoning_expected=False,
    ),
    Candidate(
        name="gpt-6-luna low",
        settings=Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="low"),
        prices=Prices(input=0.10, cached_input=0.01, output=0.50),
        reasoning_expected=True,
    ),
]
```

`CHALLENGERS`, `REFERENCE` and `FALLBACK` do not change. Moving a retest candidate into the challengers is the decision of the admission run, outside this plan.

### `evals/run_probe.py`

- `observe` records `usage=error.usage` and `truncated_attempts=error.truncated_attempts` on `UnparseableOutput`.
- `_progress_line` appends `(N truncated)` when `truncated_attempts > 0`.
- `main` parses `--candidates NAME [NAME ...]` (names looked up in `[REFERENCE, *CHALLENGERS, FALLBACK, *RETEST_CANDIDATES]`) and `--schema NAME` (one of the six corpus schemas). With neither flag, the run is unchanged. With either one, `main` calls a subset run:
  - candidates: the named ones, or every candidate of `CANDIDATES` when `--candidates` is absent;
  - calls: the corpus calls of that schema, or all of them when `--schema` is absent, in corpus order;
  - replay through the existing `_replay`, with its rotation, on a copy of the corpus holding only the filtered calls (`corpus.model_copy(update={"calls": calls})`, since `_replay` reads `corpus.calls` and `corpus.budget`);
  - the JSONL sink is `--report` with the `.jsonl` suffix, and a subset run defaults `--report` to `output/probe_subset.json`, not `DEFAULT_REPORT_PATH`, so a debugging run never empties the full run's sink (`_replay` empties its sink first);
  - only the named candidates' models are built (`_build_models` on the subset), so a subset run on the two retest candidates needs `OPENAI_API_KEY` only;
  - print one table row per candidate from `count_defects`, and write no JSON report and no admission.
- An unknown candidate name or schema stops before any call, with the known names, exit 1.
- `main` stays a thin composition root: the subset run's orchestration (model building, `_replay`, printing) stays here, since it uses the module's private `_build_models` and `_replay`, and the pure parts live in `evals/probe_subset.py` below.

<!-- Standards: run_probe.py is 272 lines today, and the flags, the subset orchestration and the defect table take it past the 300-line bound of CLAUDE.md. The split is decided now rather than left conditional: the pure functions go to a module that run_probe imports, so nothing imports run_probe's private helpers (pyright strict, reportPrivateUsage) and there is no import cycle. -->

### `evals/probe_subset.py` (new)

Pure functions of the subset run, imported by `run_probe`:

- the candidate lookup: the named candidates among `[REFERENCE, *CHALLENGERS, FALLBACK, *RETEST_CANDIDATES]`, deduplicated in the order given, refusing an unknown name with the known names;
- the call filter: the corpus calls of a schema, in corpus order, or all of them without a schema;
- the defect table, one row per candidate from `count_defects`.

### `src/mcp_auditor/graph/prompts.py`

In `build_attack_generation_prompt`:

- `input_validation`: "For integer fields: zero, negative numbers and values beyond any plausible limit, the classic boundary values."
- `resource_abuse`: "Craft inputs designed to cause unbounded resource consumption: limits or counts beyond any plausible bound, wildcard queries, cross-joins."
- One paragraph after the category list, before the context section:

```
Keep every literal short. An integer beyond any plausible limit needs at most 10 digits (2^31 already has 10). A string argument stays under 1,000 characters. Resource exhaustion is probed by what the argument asks the tool to do, not by the size of the argument itself.
```

No other prompt changes (chain prompts, judge prompt, category guidance).

### Living docs

- `evals/probe_method.md`: the *Cost* section no longer says a parse failure counts 0: its cost is the usage of all its attempts. An error raised inside the provider client (the giant integer is one) still carries no usage, stated once in *Limits*, which loses *Parse failures carry no cost*. A new short section, *Subset runs*, gives the flags, says a subset run computes no admission and serves debugging only, names the two retest candidates and their expected reasoning, and defines *parse failure with truncation*.
- `CONTRIBUTING.md`, *Model admission probe*: one command line for a subset run, e.g. `uv run python -m evals.run_probe --candidates "gpt-6-luna none" "gpt-6-luna low" --schema TestCaseBatch`.
- `CLAUDE.md`, Commands: the same line, with "debugging only, no admission, needs the keys of the named candidates only".
- `CHANGELOG.md`, `[Unreleased]`, *Changed*: the generator keeps integers to 10 digits and strings under 1,000 characters, and probes resource exhaustion by what it asks the tool rather than by argument size. Not the probe changes, which are eval tooling.

## What stays unchanged

- The bars, their values, `admit`, `reference_failures`, the admission table and the full probe run.
- `CHALLENGERS`, `REFERENCE`, `FALLBACK`, the corpus (`evals/fixtures/probe_corpus.json`) and `capture_probe_corpus`.
- ADR 019 and every other ADR, past plans.
- The adapter's output cap, timeouts, structured-output modes and `_was_truncated`.
- How the graph reacts to `UnparseableOutput` (it does not catch it today).
- The honeypots, the ground truth, the judge prompt, the category guidance, the chain prompts.
- The classification of an exception raised inside the provider client as an error: the giant integer stays an error carrying its message.

## Edge cases

- **Every attempt truncated**: `truncated_attempts == attempts`, usage is the sum of all three.
- **Some attempts truncated, the last one malformed**: counted as a parse failure with truncation.
- **A truncated attempt followed by a valid one**: parsed, usage includes the truncated attempt (already the case today).
- **An old JSONL line without `truncated_attempts`**: reads as 0.
- **`--schema` with a name outside the six schemas, or a schema with no call in the corpus**: the first is refused before any call. The second cannot happen with the committed corpus, and would print an empty table.
- **`--candidates` naming the same candidate twice**: deduplicated, in the order given.
- **A subset run with the whole list of candidates and no schema**: it is still a subset run (no admission), by construction of the flags.

## Test scenarios

Test-first, in the existing files and their given/then modules.

`tests/unit/test_llm_adapter.py`:
- Three malformed attempts raise `UnparseableOutput` carrying the usage of all three and `truncated_attempts == 0`.
- Two truncated attempts (`max_parse_attempts=2`) raise with `truncated_attempts == 2` and the usage of both.
- One truncated then two malformed raise with `truncated_attempts == 1`.
- The existing retry and truncation tests keep passing unchanged.

`tests/unit/test_run_probe.py`:
- An `UnparseableOutput` carrying usage and one truncated attempt gives a `PARSE_FAILURE` observation with that usage and `truncated_attempts == 1`.
- The existing tests construct `UnparseableOutput` with the new signature.

`tests/unit/test_probe_subset.py` (new, setup inline unless a given actually abstracts something, per CLAUDE.md):
- The candidate lookup returns the named candidates, retest ones included, deduplicated in the order given, and refuses an unknown name.
- The call filter keeps only the calls of the schema, in corpus order, and keeps them all without a schema.

`tests/unit/test_probe.py`:
- `count_defects` counts parse failures, those with truncation, refusals (a parse failure and a coverage gap on `TestCaseBatch`) and errors, over a mixed list.
- `summarize` weights the usage of a parse failure into the cost like any other call. `summarize` already sums over every observation, so this test pins existing behavior and is green from the start: the red test for the cost change is the `observe` one in `test_run_probe.py`.

`tests/unit/test_prompts.py`:
- The generation prompt bounds integers to 10 digits and strings to 1,000 characters, and no longer says "extremely large".
- The fixture contamination test (`tests/unit/test_fixture_contamination.py`) keeps passing: the test checks every string constant of `src/`, f-string parts of the prompt included, against whole honeypot literals and against any shared run of three words. The three new sentences were run through that check at review time and match nothing.

## Verification

```bash
uv run pytest tests/unit
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

After the prompt commit, by hand and outside the implementation steps, since it costs API calls: an exploratory run of the honeypot suite on the default model, `uv run python -m evals.run_evals --ungated`, compared with the exploratory figures of 2026-09-25 on Gemini 3.5 Flash-Lite. No cell of the ground truth is a positive `resource_abuse` cell, so only precision can move, and a delta below the instrument's resolution is inconclusive. The number is exploratory and confirms nothing.

## After this plan

By hand, in this order, each outside the implementation steps:

1. The exploratory honeypot run above.
2. A debugging corpus recaptured on the reference settings (`uv run python -m evals.capture_probe_corpus`), then subset runs of `gpt-6-luna none` and `gpt-6-luna low` on `TestCaseBatch`. The debugging corpus overwrites `evals/fixtures/probe_corpus.json` in the working tree and is not committed. Debugging iterates only against defects seen call by call, never against the judge F1 or the honeypot metrics, and each further prompt change is its own commit, justified without a measurement, followed by a new recapture.
3. The admission run, on a corpus recaptured after the last prompt change, with the bars of ADR 019 unchanged. Adding the retest candidates to the challengers is decided then, not here.

## Commit messages

- The commit of the ADR 019 report is an evidence commit: no code, no label, no prompt changes.
- The prompt commit answers the questions of ADR 016 that apply: the change lands in the system under test, its justification is the paragraph *Why the prompt rule holds with every measurement deleted*, and it was written from the probe's failed calls, which carry no label, before any eval run on it.
- No commit message names a plan, a step or a phase.

## Due diligence record

What the due-diligence pass concluded, on 2026-09-25, about the external facts this plan cites, for the passes that come after it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `model="gpt-6-luna"` exists, and `reasoning="none"` and `reasoning="low"` are accepted efforts (verified against developers.openai.com/api/docs/models/gpt-6-luna: `none`, `low`, `medium` (default), `high`, `xhigh`, `max`)
- SETTLED: `Prices(input=0.10, cached_input=0.01, output=0.50)` for `gpt-6-luna` (verified against developers.openai.com/api/docs/models/gpt-6-luna)
- SETTLED: `gpt-6-luna` has a 128,000-token output limit, as *Context* and `evals/probe_method.md` state (verified against developers.openai.com/api/docs/models/gpt-6-luna)
- SETTLED: CPython refuses integer string conversion past 4,300 digits by default, with `ValueError: Exceeds the limit (4300 digits) for integer string conversion` (verified by running the project's interpreter, CPython 3.13.12)
- SETTLED: 2^31 has 10 digits (2147483648, computed)

## Implementation steps

Verification commands (from `CLAUDE.md`): `uv run pytest tests/unit`, `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`. Each step ends with all of them green, and is one commit. No commit message names a plan, a step or a phase.

### Step 1: Commit the report of the ADR 019 run

- **Files**: `evals/probe_runs/2026-09-25_adr-019.json` (new, copied as is from `output/probe_report.json`).
- **Do**: `mkdir -p evals/probe_runs && cp output/probe_report.json evals/probe_runs/2026-09-25_adr-019.json`. Do not modify, reformat or pretty-print it. Do not copy the `.jsonl` twin or the `*-partial.jsonl` files. Check it is not caught by `.gitignore` (`git check-ignore`) and that ruff/pyright ignore it (JSON, so they do). Evidence commit: no code, no label, no prompt change.
- **Test**: none (no code).
- **Verify**: `git status` shows only the new file; `python -c "import json; json.load(open('evals/probe_runs/2026-09-25_adr-019.json'))"` succeeds; `cmp output/probe_report.json evals/probe_runs/2026-09-25_adr-019.json` is silent.

### Step 2: Failed attempts keep their usage and their truncation

- **Files**: `tests/unit/test_llm_adapter.py`, `tests/unit/test_run_probe.py`, `tests/unit/test_probe.py`, `src/mcp_auditor/domain/ports.py`, `src/mcp_auditor/adapters/llm.py`, `evals/probe.py`, `evals/run_probe.py`, `evals/probe_method.md`.
- **Do** (tests first, run them red):
  - `tests/unit/test_llm_adapter.py` (existing helpers `_raw_response`, `_truncated` at line ~152): add the three raising scenarios below. The existing `test_dicts_failing_validation_on_every_attempt_raise` keeps its `match="unparseable output after 3 attempts"` unchanged.
  - `tests/unit/test_run_probe.py`: change `UnparseableOutput("unparseable output after 3 attempts")` at line 39 to the new signature (`UnparseableOutput(attempts=3, truncated_attempts=0, usage=TokenUsage())`), and add the observe scenario below.
  - `tests/unit/test_probe.py`: add the `summarize` scenario below (green from the start, it pins existing behavior).
  - `src/mcp_auditor/domain/ports.py`: `UnparseableOutput.__init__(self, attempts: int, truncated_attempts: int, usage: TokenUsage)`, message `f"LLM returned unparseable output after {attempts} attempts"`, stores `truncated_attempts` and `usage` (see *Files to modify*).
  - `src/mcp_auditor/adapters/llm.py`: `_unpack_raw_response` returns `tuple[object, TokenUsage, bool]` (parsed, usage, truncated) instead of mapping a truncated answer to `None`. `generate_structured` counts truncated attempts, `continue`s on them, and raises `UnparseableOutput(self._max_parse_attempts, truncated_attempts, accumulated_usage)`, as in the plan's snippet. If it passes 20 lines, move the bookkeeping into a small private helper. `_was_truncated`, `_validated`, providers and output cap unchanged.
  - `evals/probe.py`: `ProbeObservation` gains `truncated_attempts: int = 0` (comment: attempts cut by the output cap on a parse failure). `summarize`, `admit`, bars unchanged.
  - `evals/run_probe.py`: in `observe`, `except UnparseableOutput as unparseable:` sets `outcome = PARSE_FAILURE`, `usage = unparseable.usage`, and passes `truncated_attempts=unparseable.truncated_attempts` to the observation (0 otherwise). `_progress_line` appends ` (N truncated)` when `truncated_attempts > 0`.
  - `evals/probe_method.md`: *Cost* no longer says a parse failure counts 0, its cost is the usage of all its attempts. *Limits* loses the bullet *Parse failures carry no cost*, and states once that an error raised inside the provider client (the giant integer is one) carries no usage.
- **Test**:
  - Adapter: three malformed attempts (dicts failing validation) raise `UnparseableOutput` with `usage` equal to the sum of the three and `truncated_attempts == 0`. With `max_parse_attempts=2`, two truncated attempts raise with `truncated_attempts == 2` and the usage of both. One truncated (`finish_reason="length"`) then two malformed raise with `truncated_attempts == 1`. Existing retry/truncation tests pass unchanged.
  - `observe`: an `UnparseableOutput(attempts=3, truncated_attempts=1, usage=TokenUsage(input_tokens=100, output_tokens=8192))` gives a `PARSE_FAILURE` observation carrying that usage and `truncated_attempts == 1`.
  - `summarize`: a `PARSE_FAILURE` observation with nonzero usage contributes `call_cost(usage, prices)` to `weighted_cost` like a parsed one.
  - An old JSONL line without `truncated_attempts` validates to 0 (one assertion in `test_probe.py` or `test_run_probe.py`, via `ProbeObservation.model_validate_json`).
- **Verify**: `uv run pytest tests/unit` (new adapter and observe tests red before the production change, all green after), then `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` clean.

### Step 3: A subset run of the probe

- **Files**: `tests/unit/test_probe_subset.py` (new), `tests/unit/test_probe.py`, `evals/probe.py`, `evals/probe_candidates.py`, `evals/probe_subset.py` (new), `evals/run_probe.py`, plus docs `evals/probe_method.md`, `CONTRIBUTING.md`, `CLAUDE.md`.
- **Do** (tests first, run them red):
  - `tests/unit/test_probe.py`: `count_defects` scenario below.
  - `tests/unit/test_probe_subset.py` (setup inline unless a given actually abstracts something): lookup and filter scenarios below. Build a small `ProbeCorpus` inline (see `tests/unit/test_probe_corpus.py` for its construction).
  - `evals/probe.py`: below `summarize`, `class DefectCounts(BaseModel)` (candidate, calls, parse_failures, parse_failures_with_truncation, refusals, errors) and `count_defects(candidate: str, observations: list[ProbeObservation]) -> DefectCounts`. Refusals use the existing `_is_refusal`. It counts the observations it is given (the caller filters by candidate).
  - `evals/probe_candidates.py`: `RETEST_CANDIDATES` after `FALLBACK`, exactly as in *Files to modify*, commented as measured only in a subset run and never admitted by the probe. `CHALLENGERS`, `REFERENCE`, `FALLBACK` unchanged.
  - `evals/probe_subset.py` (pure, short module docstring pointing at `evals/probe_method.md`): `KNOWN_CANDIDATES = [REFERENCE, *CHALLENGERS, FALLBACK, *RETEST_CANDIDATES]`; a lookup `select_candidates(names: list[str]) -> list[Candidate]` deduplicating in the order given and raising a `ValueError` (or a dedicated exception) listing the known names on an unknown name; `select_calls(corpus: ProbeCorpus, schema: str | None) -> list[ProbeCall]` keeping corpus order; the defect table (a `rich` `Table` built from a list of `DefectCounts`, one row per candidate). Pick the exact names, keep them domain-readable.
  - `evals/run_probe.py`: `main` adds `--candidates NAME [NAME ...]` (`nargs="+"`) and `--schema NAME` (`choices` = the six corpus schema names, from `evals/probe_corpus.py`, so an unknown schema exits before any call). `--report` default becomes `None`, resolved to `DEFAULT_REPORT_PATH` for a full run and `output/probe_subset.json` for a subset run. With neither flag, the full run is unchanged. With either, a `_run_subset(corpus, args)`: candidates from the lookup (or `CANDIDATES` when `--candidates` is absent; an unknown name prints the known names and `sys.exit(1)` before `_build_models`), calls from the filter, `_build_models` on the selected candidates only, `_replay` on `corpus.model_copy(update={"calls": calls})` with sink `Path(report).with_suffix(".jsonl")`, then prints the defect table from `count_defects` per candidate (observations filtered by candidate name). No JSON report, no admission. Keep `run_probe.py` under ~300 lines; the pure parts live in `probe_subset.py` so nothing imports `run_probe`'s private helpers.
  - `evals/probe_method.md`: new short section *Subset runs*: the two flags, the subset default report path, no admission and debugging only, the two retest candidates and their expected reasoning (`none`: no, `low`: yes), and the definition of *parse failure with truncation* (a parse failure where at least one attempt was cut by the output cap).
  - `CONTRIBUTING.md`, *Model admission probe*: one command line, `uv run python -m evals.run_probe --candidates "gpt-6-luna none" "gpt-6-luna low" --schema TestCaseBatch`.
  - `CLAUDE.md`, Commands: the same line, commented "debugging only, no admission, needs the keys of the named candidates only". No `CHANGELOG.md` entry (eval tooling).
- **Test**:
  - `count_defects` over a mixed list: a parsed `Judgment`, a `TestCaseBatch` parse failure with `truncated_attempts=0`, a `Judgment` parse failure with `truncated_attempts=2`, a parsed `TestCaseBatch` with a coverage gap, and an error, gives `calls=5, parse_failures=2, parse_failures_with_truncation=1, refusals=2` (the `TestCaseBatch` parse failure and the coverage gap, per `_is_refusal`), `errors=1`.
  - Lookup: `["gpt-6-luna low", "gpt-6-luna none", "gpt-6-luna low"]` returns the two retest candidates in that order, once each. A name from `CHALLENGERS` or `REFERENCE` is found. An unknown name raises, and the message names the known candidates.
  - Filter: on a corpus with calls of two schemas interleaved, `schema="TestCaseBatch"` keeps only those, in corpus order. `schema=None` keeps every call.
- **Verify**: new tests red before the production code, then `uv run pytest tests/unit`, `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` clean. `uv run python -m evals.run_probe --candidates nope` exits 1 listing the known names without any API call. `uv run python -m evals.run_probe --schema Nope` exits with argparse's error. Do not run a real subset or full probe (API cost).

### Step 4: The generator bounds the size of its literals

- **Files**: `tests/unit/test_prompts.py`, `src/mcp_auditor/graph/prompts.py`, `CHANGELOG.md`.
- **Do** (test first, run it red):
  - `tests/unit/test_prompts.py`: one test in the attack generation prompt tests, asserting the prompt contains "10 digits" and "1,000 characters" and does not contain "extremely large".
  - `src/mcp_auditor/graph/prompts.py`, `build_attack_generation_prompt`: replace the `input_validation` integer sentence with "For integer fields: zero, negative numbers and values beyond any plausible limit, the classic boundary values." Replace the `resource_abuse` line with "Craft inputs designed to cause unbounded resource consumption: limits or counts beyond any plausible bound, wildcard queries, cross-joins." Add, after the category list and before the context section, the paragraph: "Keep every literal short. An integer beyond any plausible limit needs at most 10 digits (2^31 already has 10). A string argument stays under 1,000 characters. Resource exhaustion is probed by what the argument asks the tool to do, not by the size of the argument itself." No other prompt change.
  - `CHANGELOG.md`, `[Unreleased]`, *Changed*: one bullet, the generator keeps integers to 10 digits and strings under 1,000 characters, and probes resource exhaustion by what it asks the tool rather than by argument size.
  - This is the only change to the system under test and is alone in its commit. The commit message answers the ADR 016 questions that apply: it lands in the system under test, its justification is the paragraph *Why the prompt rule holds with every measurement deleted* (restated, not referenced as a plan), and it was written from the probe's failed calls, which carry no label, before any eval run on it.
- **Test**: the new prompt test above. `tests/unit/test_fixture_contamination.py` keeps passing.
- **Verify**: new test red first, then `uv run pytest tests/unit`, `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` clean. Do not run the evals (API cost, done by hand after this plan).
