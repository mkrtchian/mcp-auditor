# The probe reports defects, without an admission verdict

## Context

[ADR 021](../docs/adr/021-gpt-6-luna-default.md) (Accepted, `2cd755f`) supersedes the section *How the default is chosen* of ADR 019: a model is chosen on a written judgment, not on admission bars. The probe keeps recording what a candidate does on the corpus (loops, answers that do not parse, errors, incomplete batches, cost and latency), and its Consequences say: "The probe's method note loses its admission verdict. Its bars become the list of defects the probe reports."

The code still computes and prints that verdict:

- `evals/probe.py` defines `Bars` (latency ratio 3.0, cost ratio 1.0), `Admission` (with an `admitted` boolean, `reasons` and `latency_notes`), `admit()` and `reference_failures()`.
- `evals/run_probe.py` builds `admissions` for the challengers, prints a *Verdict* column ("admitted" / "not admitted", "reference (exempt)", "fallback (recorded)"), writes `bars`, `admissions`, `reference_failed_bars_recorded_only` and `fallback_against_the_bars_recorded_only` to the report, and its docstring speaks of an admitted challenger.
- `evals/probe_candidates.py` splits the measured models into `REFERENCE`, `CHALLENGERS` and `FALLBACK`, the roles of the ADR 019 procedure. `FALLBACK` carries a comment about ADR 019 moving to it when no challenger is admitted.
- `evals/probe_method.md` has a section *Bars written before measurement* with an admission rule, exemptions and the judge and honeypot thresholds applied as admission steps.

Left as is, the next probe run would print "not admitted" in red beside `gpt-6-luna none`, the default ADR 021 just chose.

This plan removes the verdict and keeps every measurement. It does not change the default model (a separate plan), the corpus, the prices, the reference, what is observed per call, or the subset run's behavior.

## Approach

One commit.

1. **A list of defects replaces the admission.** `probe.py` keeps `summarize`, `call_cost`, `count_defects` and `CandidateStats` as they are. `Bars`, `Admission`, `admit` and `reference_failures` go. A new pure function lists a candidate's defects from its statistics: parse failures per schema, refusals, errors, and a reasoning-token count at odds with the setting. Cost and latency are no longer judged against a threshold: the table already shows each candidate's weighted cost, its ratio to the reference and its median latency per role, and those numbers feed the written judgment.
2. **Every measured model is treated alike.** No candidate is exempt and none is a challenger or a fallback. The reference keeps one role only: it is the model the corpus is captured on (`capture_probe_corpus` reads `REFERENCE`) and the denominator of the cost ratio. `CHALLENGERS` and `FALLBACK` merge into one list, `CANDIDATES`, in `probe_candidates.py`.
3. **The report and the table follow.** The table's last column is *Defects* (their count), and each defect is printed below it as `candidate: defect`, the reference's included. The JSON report holds the statistics and the defects of every measured model, without `bars`, `admissions`, `challengers`, `fallback` or the two "recorded only" entries.
4. **The method note follows.** It describes what the probe reports and how it serves a written judgment (ADR 021).

Why the cost and latency thresholds go rather than becoming defects: "more expensive than the reference" and "3 times slower" are not defects of a model, they are the numbers a judgment weighs, and each ADR that chooses a model states how it weighs them. A reasoning-token count at odds with the setting stays a defect, because it means the setting did not reach the API and the candidate was not measured as configured.

Why `CHALLENGERS` and `FALLBACK` merge: both roles belong to the ADR 019 procedure, a fallback is only a fallback when an admission can fail, and a split that nothing reads is dead structure. The measured models are then the reference and the candidates.

## Files to modify

### `evals/probe_candidates.py`

`CHALLENGERS` and `FALLBACK` become one list, `CANDIDATES`, in this order: `gpt-6-luna none`, `gpt-6-luna low`, `gemini-3.5-flash-lite minimal`. The comment about ADR 019 moving to the fallback goes. `REFERENCE`, prices and `PRICES_DATE` do not change. A one-line comment on `REFERENCE` says what it is for: the settings the corpus is captured on, and the denominator of the cost ratio.

### `evals/probe.py`

- Module docstring: per-candidate statistics and the defects the probe reports, pointing at `evals/probe_method.md`.
- Removed: `Bars`, `Admission`, `admit`, `reference_failures`, `_latency_notes`, `_cost_reasons`.
- Kept as they are: `CallOutcome`, `ProbeObservation`, `CandidateStats`, `summarize`, `call_cost`, `DefectCounts`, `count_defects`. Only the comment on `DefectCounts.refusals`, "same rule as the admission", becomes "same rule as `summarize`".
- New, where `admit` was:

```python
def list_defects(stats: CandidateStats) -> list[str]:
    return [*_count_defects(stats), *_reasoning_defects(stats)]
```

`_count_defects` is today's `_count_reasons` and `_reasoning_defects` today's `_reasoning_reasons`, renamed, same messages. The error message keeps "not measured on the whole corpus, rerun". The name `list_defects` avoids a clash with `count_defects`, which counts defects per call for the subset run.

### `evals/run_probe.py`

- Docstring: replays the corpus against the reference and every candidate, and reports per model the statistics and the defects. It exits 0 whatever it finds.
- `_run_subset` docstring: "computes no admission" becomes "computes no statistics".
- `CANDIDATES = [REFERENCE, *CHALLENGERS, FALLBACK]` becomes `MEASURED = [REFERENCE, *CANDIDATES]`, and every use follows (`main`, `_analyze`, `_write_report`, the subset run's default candidates).
- `ProbeResult`: `reference: CandidateStats`, `candidates: list[CandidateStats]` (reference excluded, in `CANDIDATES` order), no `admissions`, no `fallback`. `_analyze` slices `stats[0]` and `stats[1:]`.
- `_write_report`: `corpus`, `prices_date`, `candidates` (the settings entries of `MEASURED`, as today), `statistics` (the reference first, then the candidates), `defects` (a mapping from model name to its list, every measured model included, an empty list for a clean one), `observations`. No `bars`, `admissions`, `challengers`, `fallback`, `reference_failed_bars_recorded_only`, `fallback_against_the_bars_recorded_only`.
- `_print_table`: title "Probe". The last column is *Defects*, holding the number of defects. Every row is built the same way, the reference first. Under the table, each defect is printed as `candidate: defect`, for every model. `_print_reasons` becomes `_print_defects`.
- The file is 312 lines today and should shrink. If it does not end under 300, move the report writing and the printing to `evals/probe_report.py`, pure functions of a `ProbeResult`.

### `evals/probe_subset.py`

`KNOWN_CANDIDATES = [REFERENCE, *CANDIDATES]`, import updated. The module docstring and the table title drop "no admission" ("debugging only" stays). Nothing else.

### Tests

- `tests/unit/test_probe.py`: `TestAdmit` and `TestReferenceFailures` go. A new `TestListDefects`:
  - a clean candidate lists no defect;
  - a parse failure is listed with its count and its schema;
  - a refusal is listed with its count;
  - an error is listed with its count and "rerun";
  - reasoning tokens where the setting expects none are listed with their count;
  - no reasoning token where the setting expects some is listed;
  - no expectation means no reasoning check;
  - cost and latency do not appear, whatever their values (a candidate 10 times the reference's cost and latency lists no defect).
- `tests/unit/support/test_probe_then.py`: `admitted`, `rejected_for` and `latency_noted` go. One helper, `lists_defects(defects, *words)`, asserts that one defect holds every word, and prints the list on failure. It stays in `then`: the nested `any(all(...))` with its failure message is an abstraction, not a one-liner wrapper, and it is used by five of the new tests (the same shape as today's `rejected_for`). A clean candidate is asserted inline (`== []`).
- `tests/unit/support/test_probe_given.py`: `challenger_stats` becomes `candidate_stats`, its docstring "clean apart from the changes". `reference_stats` stays if a test still reads it, and goes otherwise (it can fold into `candidate_stats`). The candidate name `"challenger"` in `a_candidate` and `an_observation` becomes `"candidate"`, and so does the name passed to `count_defects` and asserted in `TestCountDefects`.
- `tests/unit/test_probe.py` imports: `Bars`, `admit` and `reference_failures` go, `list_defects` comes in.
- `tests/unit/test_probe_subset.py`: `CHALLENGERS` becomes `CANDIDATES`, and `test_finds_the_reference_and_the_challengers` becomes `test_finds_the_reference_and_the_candidates`. The two `gpt-6-luna` entries keep indexes 0 and 1, so the assertions and the `luna_none, luna_low = ...` unpacking change only the name (`CANDIDATES[:2]` for the unpacking).

### `evals/probe_method.md`

- Title: "Model probe: method note". The intro says the probe replays a frozen corpus against the reference and each candidate, and reports per model its statistics and its defects, which feed the written judgment an ADR takes when it chooses a model (ADR 021). The candidates are those of `evals/probe_candidates.py`. The pointer to the ADR 019 run (`evals/probe_runs/2026-09-25_adr-019.json`) stays, without the word "challengers". The sentences on the bar values and the defaults of `Bars` go.
- *The corpus*: "the one the next admission run replays" becomes "the one the next probe run replays".
- *What the probe measures, and what it does not*: unchanged, except that detection quality is measured by the judge isolation eval and the e2e evals, whose results also feed the judgment (no "for an admitted challenger only").
- *Bars written before measurement* becomes *What the probe reports*:
  - the defects: parse failures after the adapter's 3 attempts, per schema; refusals; errors, with "on an error, rerun the probe rather than read it as a fact about the model"; reasoning tokens at odds with the setting;
  - the numbers: weighted corpus cost and its ratio to the reference, median latency per call and per role, reasoning tokens;
  - the documented fact per provider on training on API data, as today.
  The latency bar paragraph, the exemption paragraph and the paragraph on the judge threshold and honeypot floors applied after the probe go. Its sentence on the resolution of the judge F1 moves to `evals/run_judge_eval.py` (below), since the judge eval's results still feed the judgment.
- *Reasoning check per candidate*: the check becomes a defect (the setting did not reach the API), same table, with the row label "Gemini 3.5 Flash-Lite (fallback)" becoming "Gemini 3.5 Flash-Lite".
- *Cost*: the same label in the price table loses "(fallback)". "and fails the parse bar anyway" becomes "and counts as a parse failure anyway". "the cost bar cannot be read until it is explained" becomes "the cost cannot be read until it is explained". The rest is unchanged.
- *Running it*: the report holds the observations, the statistics and the defects of every measured model, and the command exits 0 whatever it finds.
- *Subset runs*: "it computes no statistics against the bars, no admission and no JSON report" becomes "it computes no statistics and writes no JSON report". "A subset run names its candidates among the reference, the challengers and the fallback" becomes "among the reference and the candidates".
- *Limits*: "A loop that a retry recovers from passes the parse bar" becomes "is not counted as a parse failure".
- *Observations before the ADR 019 revision*, *The refusal rule*, *Data retention per provider*, *Order of calls*: unchanged.

### `evals/run_judge_eval.py`

A comment above `F1_THRESHOLD` keeps what one case is worth: with 8 FAIL cases among the 32 of the judge fixture, one misjudged case moves F1 by about 0.06, so the threshold admits one error and rejects two. The sentence leaves `evals/probe_method.md` in the same commit. No code change.

### Living docs

- `CLAUDE.md`, Commands: the `run_probe` line reads "Model probe: replay the corpus against the reference and every candidate, report statistics and defects (needs GOOGLE_API_KEY and OPENAI_API_KEY, see evals/probe_method.md)". The subset line: "Subset run: debugging only, no statistics, needs the keys of the named candidates only".
- `CONTRIBUTING.md`: heading *Model admission probe* becomes *Model probe*, its first sentence says the probe reports defects, cost and latency to inform the choice of a model, and "What it measures, the bar values and the limits" becomes "What it measures, what it reports and its limits".
- `CHANGELOG.md`, `README.md`: nothing, eval tooling only.

## What stays unchanged

- `summarize`, `call_cost`, `CandidateStats`, `ProbeObservation`, `CallOutcome`, `count_defects`, `DefectCounts`, the subset run's behavior and table.
- `REFERENCE`, the prices, `PRICES_DATE`, the candidates' settings and expected reasoning.
- The corpus, `capture_probe_corpus`, `observe`, the rotation, the JSONL sink.
- `config.py`, the adapters, the default model and provider (the next plan).
- The committed reports in `evals/probe_runs/`: they keep the format of their day.
- ADR 019, ADR 021, past plans.

## Edge cases

- **A report file written before this change**: not read by any code, so the format change breaks nothing. The committed reports stay as they are.
- **A candidate with no observation in a role** (no judge call measured): the table prints "-" for that median, as today.
- **The reference has defects**: listed like any other model's, no longer "recorded only".
- **A subset run naming `gemini-3.5-flash-lite minimal`**: still accepted, it is now one of `CANDIDATES`.

## Test scenarios

Listed under *Tests*. The unit suite passes, and neither `grep -rni "admission\|admit\|challenger\|reference_failures\|(fallback)\|\(parse\|cost\|latency\) bar\|the bars" evals tests CLAUDE.md CONTRIBUTING.md` nor `grep -rn "\bBars\b\|FALLBACK" evals tests CLAUDE.md CONTRIBUTING.md` finds anything outside `evals/probe_runs/` and the dated section *Observations before the ADR 019 revision* of `evals/probe_method.md`. The first grep is case-insensitive so the lowercase "admission" and bar wording in docstrings, titles and the method note is caught too.

## Verification

```bash
uv run pytest tests/unit
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run python -m evals.run_probe --candidates nope   # exits 1 listing the reference and the three candidates, no API call
```

No probe run with API calls.

## Commit message

Names ADR 021, says the probe reports defects and numbers without an admission verdict, that no measurement, price, corpus or default changes, and that the committed reports keep their format. No plan, step or phase named.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, read by the implementation-phase fact check. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, on 2026-09-26, not what is true now. A human who edits the corresponding fact by hand deletes its line rather than updating it.

- No external facts to verify: the plan cites no new API, library, version, price or model name, and defers none. The model names, prices and `PRICES_DATE` it mentions are existing constants of `evals/probe_candidates.py` that it keeps unchanged.

## Implementation steps

### Step 1: Replace the admission verdict with a list of defects

One step, one commit, as the plan asks. The edits span about 12 files, but all except `probe.py` and `run_probe.py` are renames or wording changes, and there are 8 new test cases. That fits one agent session.

**Files**

- Tests first: `tests/unit/test_probe.py`, `tests/unit/support/test_probe_then.py`, `tests/unit/support/test_probe_given.py`, `tests/unit/test_probe_subset.py`
- Production: `evals/probe_candidates.py`, `evals/probe.py`, `evals/run_probe.py` (and `evals/probe_report.py` only if `run_probe.py` does not end under 300 lines), `evals/probe_subset.py`
- Docs: `evals/probe_method.md`, `evals/run_judge_eval.py` (comment only), `CLAUDE.md`, `CONTRIBUTING.md`

**Do**

1. Tests, and confirm they fail:
   - `tests/unit/support/test_probe_then.py`: delete `admitted`, `rejected_for` and `latency_noted`, and the `Admission` import. Add `lists_defects(defects: list[str], *words: str) -> None`, which asserts `any(all(word in defect for word in words) for defect in defects)` and passes `defects` as the failure message.
   - `tests/unit/support/test_probe_given.py`: rename `challenger_stats` to `candidate_stats`, with the docstring "Clean, apart from the changes.". Fold `reference_stats` into it if no test reads it any more (the clean `CandidateStats` built inline, `candidate="candidate"`). Replace the name `"challenger"` with `"candidate"` in `a_candidate` and `an_observation`.
   - `tests/unit/test_probe.py`: remove the imports of `Bars`, `admit` and `reference_failures` and import `list_defects`. Delete `TestAdmit` and `TestReferenceFailures`. In `TestCountDefects`, the name passed to `count_defects` and the one asserted become `"candidate"`. Add `TestListDefects` with the 8 scenarios under **Test**.
   - `tests/unit/test_probe_subset.py`: import `CANDIDATES` instead of `CHALLENGERS`. Replace `CHALLENGERS[i]` with `CANDIDATES[i]`, write the unpacking as `luna_none, luna_low = CANDIDATES[:2]`, and rename the test to `test_finds_the_reference_and_the_candidates`.
2. `evals/probe_candidates.py`: merge `CHALLENGERS` and `FALLBACK` into `CANDIDATES = [gpt-6-luna none, gpt-6-luna low, gemini-3.5-flash-lite minimal]`, keeping their current settings, and drop the comment about ADR 019 moving to the fallback. Add a one-line comment on `REFERENCE`: the settings the corpus is captured on, and the denominator of the cost ratio. Prices and `PRICES_DATE` do not change.
3. `evals/probe.py`: rewrite the module docstring (per-candidate statistics and the defects the probe reports, see `evals/probe_method.md`). Delete `Bars`, `Admission`, `admit`, `reference_failures`, `_latency_notes` and `_cost_reasons`. Put `def list_defects(stats: CandidateStats) -> list[str]: return [*_count_defects(stats), *_reasoning_defects(stats)]` where `admit` was, with the helpers directly below it (newspaper rule). The helpers are today's `_count_reasons` and `_reasoning_reasons`, renamed, with the same messages. The error message keeps "not measured on the whole corpus, rerun". On `DefectCounts.refusals`, the comment "same rule as the admission" becomes "same rule as `summarize`". `summarize`, `call_cost`, `count_defects`, `CandidateStats`, `ProbeObservation` and `CallOutcome` stay as they are.
4. `evals/run_probe.py`:
   - The docstring says it replays the corpus against the reference and every candidate, reports each model's statistics and defects, and exits 0 whatever it finds.
   - In the `_run_subset` docstring, "computes no admission" becomes "computes no statistics".
   - `MEASURED = [REFERENCE, *CANDIDATES]` replaces the local `CANDIDATES`. Update every use: `main`, `_analyze`, `_write_report`, and the subset's default candidates.
   - `ProbeResult` loses `challengers`, `admissions` and `fallback`, and gains `candidates: list[CandidateStats]`. `_analyze` sets `reference=stats[0]` and `candidates=stats[1:]`.
   - `_write_report` writes these keys: `corpus`, `prices_date`, `candidates` (the settings entries of `MEASURED`, as today), `statistics` (reference first), `defects` (`{name: list_defects(stats)}` for every measured model, `[]` when a model is clean) and `observations`.
   - `_print_table` is titled "Probe", and its last column, *Defects*, holds `len(list_defects(stats))`. Every row is built the same way, reference first. `_print_reasons` becomes `_print_defects` and prints `candidate: defect` for every model, the reference included.
   - Check `wc -l`. If the file is not under 300 lines, move `_write_report`, `_print_table` and `_print_defects` to `evals/probe_report.py` as pure functions of a `ProbeResult` (the console printing is presentation, so it may stay there).
5. `evals/probe_subset.py`: `KNOWN_CANDIDATES = [REFERENCE, *CANDIDATES]`, with the import updated. The module docstring and the table title drop "no admission" and keep "debugging only".
6. `evals/probe_method.md`: rewrite it section by section, as listed under the plan's `### evals/probe_method.md`. That covers the title, the intro, *The corpus*, *What the probe measures*, *What the probe reports* (replacing *Bars written before measurement*), *Reasoning check per candidate*, *Cost*, *Running it*, *Subset runs* and *Limits*. Leave *Observations before the ADR 019 revision*, *The refusal rule*, *Data retention per provider* and *Order of calls* untouched.
7. `evals/run_judge_eval.py`: above `F1_THRESHOLD`, add a comment moved from the method note. With 8 FAIL cases among the 32 of the judge fixture, one misjudged case moves F1 by about 0.06, so the threshold admits one error and rejects two. No code change.
8. `CLAUDE.md` and `CONTRIBUTING.md`: use the exact wording given in the plan's *Living docs*, for the two probe command lines and the *Model probe* section.
9. Run the two greps from the plan's *Test scenarios*. Their only hits may be in `evals/probe_runs/` and in the dated section *Observations before the ADR 019 revision* of `evals/probe_method.md`.
10. Commit with the message described in the plan's *Commit message*. It must name no plan, step or phase.

**Test** (`TestListDefects`, all built with `given.candidate_stats(...)`)

- A clean candidate: `list_defects(...) == []`.
- `parse_failures={"StepObservation": 1}`: `then.lists_defects(defects, "1", "StepObservation")`.
- `refusals=1`: a defect lists the count and the word for refusal (use the words in today's message).
- `errors=1`: a defect lists the count and "rerun".
- `reasoning_expected=False, reasoning_tokens=120`: a defect lists "120".
- `reasoning_expected=True, reasoning_tokens=0`: a reasoning defect is listed.
- `reasoning_expected=None, reasoning_tokens=120`: `== []`.
- `weighted_cost=10.0` and `median_seconds={"main": 10.0, "judge": 10.0}`: `== []`.

The existing `TestCountDefects`, `summarize`, `call_cost`, subset and `test_run_probe.py` tests keep passing, with only the renames.

**Verify**

```bash
uv run pytest tests/unit                  # green, the new TestListDefects included (red before step 3)
uv run pytest                             # green
uv run ruff check .                       # clean
uv run ruff format --check .              # clean
uv run pyright                            # 0 errors
uv run python -m evals.run_probe --candidates nope   # exits 1, lists the reference and the 3 candidates, no API call
```

The two greps from *Test scenarios* show no hits outside the allowed places. Make no probe run with API calls.
