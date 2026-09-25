# Admission probe for `gpt-6-luna` at `none` and `low`: the corpus and the challengers ADR 021 sets

## Context

[ADR 021](../docs/adr/021-gpt-6-luna-default.md) (Proposed, `e4d2165`) runs the probe of ADR 019 again, with `gpt-6-luna` at reasoning effort `none` and at `low` as its only challengers, bars unchanged, on "the corpus recaptured after the second change, the one the debugging runs used, committed before the run". A setting that clears the probe then goes through the judge isolation eval (F1 0.90) and the honeypot floors (0.50). `none` is preferred when both are admitted.

The code does not match that yet:

- `CHALLENGERS` in `evals/probe_candidates.py` still holds the three challengers of ADR 019 (Qwen3.8-Flash thinking off, GLM-5.3-Flash `medium`, `gpt-6-luna medium`). A full run would measure them, need the Fireworks and Alibaba keys, and last one to two hours.
- The two `gpt-6-luna` settings live in `RETEST_CANDIDATES`, which the probe never admits.
- `evals/probe_method.md` and the living docs describe the ADR 019 candidates, the four keys, and the two retest candidates as subset-only.
- The debugging corpus (`evals/fixtures/probe_corpus.json`, captured at `8fd8294` on the reference settings, 153 calls, 55 of them `TestCaseBatch`) sits uncommitted in the working tree.

This plan makes the probe run what ADR 021 says, and commits the corpus before the run. It does not run the probe, run the evals, change the default provider or model, or fill the Outcome of ADR 021: those depend on the run.

## Approach

Two commits.

1. **The corpus the admission replays.** Commit the working-tree `evals/fixtures/probe_corpus.json` as is, alone. It is an instrument change: no code, no label, no prompt.
2. **The challengers of ADR 021.** `CHALLENGERS` becomes the two `gpt-6-luna` settings, `RETEST_CANDIDATES` disappears, and the three ADR 019 challengers leave the code. Their measurements stay in ADR 019 and in the committed report `evals/probe_runs/2026-09-25_adr-019.json`, whose `candidates` entries record their settings and prices. The reference (Gemini 3.1 Flash-Lite `minimal`) and the fallback (Gemini 3.5 Flash-Lite `minimal`) do not change, so the cost bar still compares with the reference ADR 019 used, and the fallback stays recorded without a verdict.

Why the ADR 019 challengers leave the code rather than staying declared: a declared candidate that no run measures is dead code, and the probe's full run measures every declared challenger. Their providers (`alibaba`, `fireworks`) stay supported: `config.py`, `adapters/llm.py` and their tests do not change.

## Files to modify

### `evals/fixtures/probe_corpus.json` (commit 1)

Committed as it is on disk. Before committing, check that its header reads `commit` `8fd829402283f13d31d6f6a6bce3f674af16b750`, the reference settings (`google`, `gemini-3.1-flash-lite`, `minimal` for both roles), budget 10, and that all 55 `TestCaseBatch` prompts contain "never from one character repeated". No other file in that commit.

### `evals/probe_candidates.py`

```python
CHALLENGERS = [
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

`REFERENCE`, `FALLBACK`, `Prices`, `Candidate` and `PRICES_DATE` unchanged. `RETEST_CANDIDATES` and its comment are deleted, as are the Qwen, GLM and `gpt-6-luna medium` entries and their comments. The module docstring stays true.

### `evals/probe_subset.py`

`KNOWN_CANDIDATES = [REFERENCE, *CHALLENGERS, FALLBACK]`, and the import drops `RETEST_CANDIDATES`. Nothing else.

### `tests/unit/test_probe_subset.py`

Replace `RETEST_CANDIDATES` by `CHALLENGERS` (same two candidates, same order: `none` first, `low` second). `test_finds_the_reference_and_the_challengers` keeps its assertion with `CHALLENGERS[0]`, now `gpt-6-luna none`. No new test: the lookup, the filter and the counts behave as before, only the candidate list moved.

### `evals/probe_method.md`

- Intro: the probe replays the corpus against the reference and each challenger, the challengers being those of ADR 021 (`gpt-6-luna` at `none` and `low`). The ADR 019 run, with its own three challengers, is reported in ADR 019 and in `evals/probe_runs/2026-09-25_adr-019.json`.
- *The corpus*: the corpus is recaptured when the generation prompt changes, and the committed one is the one the next admission run replays (ADR 021). One sentence.
- *Cost*, the price table: keep the reference, `gpt-6-luna` and the fallback. The Qwen and GLM rows and the Alibaba cached-input sentence go, since no candidate uses them, as does "Fireworks does not document it." at the end of the output-tokens paragraph. The billing-console check paragraph stays: it has not been done yet and applies to the next run.
- *Reasoning check per candidate*: rows for the reference, `gpt-6-luna` `none` (0), `gpt-6-luna` `low` (more than 0), the fallback. The GLM sentence goes.
- *Observations before the ADR 019 revision*: unchanged. It is dated evidence ADR 019 points to.
- *Data retention per provider*: unchanged. The providers stay supported.
- *Running it*: the keys become `GOOGLE_API_KEY` and `OPENAI_API_KEY`.
- *Subset runs*: the paragraph naming the two subset-only candidates goes. A subset run names candidates among the reference, the challengers and the fallback.
- *Limits*: unchanged. The bullet "A loop that a retry recovers from passes the parse bar" already states that a cut attempt recovered by a later one leaves `truncated_attempts` at 0 and shows only in cost and latency.

### Living docs

- `CLAUDE.md`, Commands: the `run_probe` line needs `GOOGLE_API_KEY` and `OPENAI_API_KEY`. The subset line keeps its example.
- `CONTRIBUTING.md`, *Model admission probe*: same keys.
- `CHANGELOG.md`: nothing. The probe is eval tooling, and no user-facing behavior changes until the default does.
- `README.md`: nothing. The defaults do not change in this plan.

## What stays unchanged

- The bars, `Bars`, `admit`, `summarize`, `reference_failures`, the report format, `_analyze` (it slices the stats by position, reference first, fallback last, which the new list keeps).
- `REFERENCE`, `FALLBACK`, prices and `PRICES_DATE`.
- `config.py` defaults (provider `google`, `openai` at `medium`), `adapters/llm.py`, the providers and their tests.
- The prompts, the honeypots, the ground truth, the evals.
- ADR 019, ADR 021 (its Outcome is written after the run), past plans, `evals/probe_runs/2026-09-25_adr-019.json`.

## Edge cases

- **A subset run naming `qwen3.8-flash thinking off` or another removed name**: refused before any call, as any unknown name, with the known names listed.
- **The corpus header does not match the checks of commit 1**: stop, do not commit, report. The corpus would have to be recaptured on the reference settings at a commit carrying `8fd8294`'s prompt.
- **`reasoning_expected=False` for `none`**: the debugging runs recorded 0 reasoning tokens at `none` on every call, and more than 0 at `low`, so the check reads the setting that reached the API.

## Test scenarios

- `tests/unit/test_probe_subset.py` passes with `CHALLENGERS` in place of `RETEST_CANDIDATES`.
- The whole unit suite passes unchanged otherwise. `test_config.py` and `test_llm_adapter.py` keep their Qwen and GLM tests, since the providers stay.
- `uv run python -m evals.run_probe --candidates "qwen3.8-flash thinking off"` exits 1 listing the known names, without any API call.

## Verification

```bash
uv run pytest tests/unit
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

## After this plan

By hand, in this order, each outside the implementation steps:

1. The admission run: `uv run python -m evals.run_probe`, keys `GOOGLE_API_KEY` and `OPENAI_API_KEY`. Its report is copied to `evals/probe_runs/` and committed, as the ADR 019 one was.
2. The billing-console check of the method note, for Google and OpenAI, over the run's window.
3. For each admitted setting: the judge isolation eval and the honeypot floors, run with `MCP_AUDITOR_PROVIDER=openai`, `MCP_AUDITOR_MODEL=gpt-6-luna`, `MCP_AUDITOR_JUDGE_MODEL=` and `MCP_AUDITOR_REASONING` set to the setting. Exploratory under ADR 016.
4. The Outcome of ADR 021, then its acceptance or not. The change of default (provider, `openai` setting, README, CHANGELOG, `.env` example, tests of `config.py`) is a separate change, made only if ADR 021 is accepted.

## Commit messages

- The corpus commit says it is the corpus ADR 021's admission run replays, captured at `8fd8294` on the reference settings, and that no code, label or prompt changes.
- The challengers commit names ADR 021, says the ADR 019 challengers are recorded in ADR 019 and in the committed report, and that no bar, price, reference or default changes.
- No commit message names a plan, a step or a phase.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, read by the later passes. It records what was concluded once, on 2026-09-25, not what is true now: no pass may treat a line here as a reason to skip a verification. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `Settings(provider="openai", model="gpt-6-luna", judge_model="", reasoning="none")` and the same with `reasoning="low"`: `none` and `low` are accepted reasoning efforts of `gpt-6-luna` (verified against https://developers.openai.com/api/docs/models/gpt-6-luna, which lists none, low, medium, high, xhigh, max)
- SETTLED: `prices=Prices(input=0.10, cached_input=0.01, output=0.50)` for both `gpt-6-luna` settings (verified against https://developers.openai.com/api/docs/models/gpt-6-luna)
- OPEN (unverified): `reasoning_expected=False` for `gpt-6-luna none`, OpenAI's model page does not state that `none` yields 0 reasoning tokens, the plan rests on the debugging runs and the admission run's own reasoning check will test it

## Implementation steps

Verification commands (from `CLAUDE.md`): `uv run pytest tests/unit`, `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`.

### Step 1: Commit the corpus the admission replays

- **Files**: `evals/fixtures/probe_corpus.json` (already modified in the working tree, committed as is).
- **Do**:
  1. Check the header of the working-tree corpus, without editing the file: `commit` is `8fd829402283f13d31d6f6a6bce3f674af16b750`, `reference` is `provider` `google`, `model` and `judge_model` `gemini-3.1-flash-lite`, `reasoning` and `judge_reasoning` `minimal`, `budget` is 10. Check that there are 153 calls, 55 of them with `schema_name` `TestCaseBatch`, and that every `TestCaseBatch` prompt contains "never from one character repeated". A short `python -c` over the JSON is enough.
  2. If any check fails: stop, commit nothing, report which check failed (see *Edge cases*).
  3. Otherwise stage `evals/fixtures/probe_corpus.json` alone (the untracked plan file stays out of this commit).
- **Test**: no code change, no test to write.
- **Verify**: `git diff --cached --name-only` lists only `evals/fixtures/probe_corpus.json`. `uv run pytest tests/unit` passes (the corpus loader tests do not read the committed fixture, but the suite must stay green).
- **Commit message**: see *Commit messages*, the corpus commit (instrument change, captured at `8fd8294` on the reference settings, no code, label or prompt change).

### Step 2: The challengers of ADR 021

- **Files**: `tests/unit/test_probe_subset.py`, `evals/probe_candidates.py`, `evals/probe_subset.py`, `evals/probe_method.md`, `CLAUDE.md`, `CONTRIBUTING.md`.
- **Do**:
  1. `tests/unit/test_probe_subset.py` first: the import drops `RETEST_CANDIDATES`. `test_returns_the_named_candidates_once_each_in_the_order_given` asserts `[CHALLENGERS[1], CHALLENGERS[0]]`. `TestDefectCounts` unpacks `luna_none, luna_low = CHALLENGERS`. `test_finds_the_reference_and_the_challengers` is unchanged (its `CHALLENGERS[0]` is now `gpt-6-luna none`). Run it and confirm red: `CHALLENGERS` still holds the ADR 019 challengers, so the order and defect-count tests fail.
  2. `evals/probe_candidates.py`: `CHALLENGERS` becomes the two `gpt-6-luna` entries exactly as in the plan's *Files to modify* snippet (`none` with `reasoning_expected=False`, then `low` with `True`, both `Prices(input=0.10, cached_input=0.01, output=0.50)`). Delete the Qwen, GLM and `gpt-6-luna medium` entries with their comments, and delete `RETEST_CANDIDATES` with its comment. `REFERENCE`, `FALLBACK`, `Prices`, `Candidate`, `PRICES_DATE` and the module docstring unchanged.
  3. `evals/probe_subset.py`: import without `RETEST_CANDIDATES`, `KNOWN_CANDIDATES = [REFERENCE, *CHALLENGERS, FALLBACK]`. Nothing else. `evals/run_probe.py` needs no change (`CANDIDATES = [REFERENCE, *CHALLENGERS, FALLBACK]` already).
  4. `evals/probe_method.md`, per the plan's bullets: intro names the ADR 021 challengers and points to ADR 019 and `evals/probe_runs/2026-09-25_adr-019.json` for the ADR 019 run. *The corpus*: one sentence on recapture when the generation prompt changes and the committed corpus being the one the next admission run replays. *Cost*: drop the Qwen and GLM price rows, the Alibaba cached-input sentence and "Fireworks does not document it.", keep the billing-console paragraph. *Reasoning check per candidate*: rows for the reference, `gpt-6-luna none` (0), `gpt-6-luna low` (more than 0), the fallback, and drop the GLM sentence. *Running it*: keys `GOOGLE_API_KEY` and `OPENAI_API_KEY`. *Subset runs*: drop the paragraph on the two subset-only candidates, say a subset run names candidates among the reference, the challengers and the fallback. *Observations before the ADR 019 revision*, *Data retention per provider* and *Limits* unchanged.
  5. `CLAUDE.md` Commands: the `run_probe` line needs `GOOGLE_API_KEY` and `OPENAI_API_KEY` only. `CONTRIBUTING.md` *Model admission probe* (line with the four keys): same two keys. Keep the subset example (`"gpt-6-luna none" "gpt-6-luna low" --schema TestCaseBatch`) in both. The general key sentence of `CONTRIBUTING.md` (providers you can use) stays, the providers remain supported.
  6. Do not touch `config.py`, `adapters/llm.py`, `test_config.py`, `test_llm_adapter.py`, `README.md`, `CHANGELOG.md`, ADRs, past plans, the committed probe report.
- **Test**:
  - `test_probe_subset.py`: selection order with the two challengers, lookup of the reference and `CHALLENGERS[0]`, unknown name refused with known names listed, defect counts per candidate. All green after the change.
  - Manual: `uv run python -m evals.run_probe --candidates "qwen3.8-flash thinking off"` exits 1 listing the known names (reference, `gpt-6-luna none`, `gpt-6-luna low`, fallback) without any API call. Check the exit code with `echo $?`, no key needed.
  - `grep -rn "RETEST_CANDIDATES\|qwen3.8-flash thinking off\|glm-5p3-flash medium\|gpt-6-luna medium" evals tests CLAUDE.md CONTRIBUTING.md` finds nothing outside `evals/probe_runs/` and the unchanged dated sections of `probe_method.md`.
- **Verify**: `uv run pytest tests/unit`, `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all clean.
- **Commit message**: see *Commit messages*, the challengers commit (names ADR 021, ADR 019 challengers recorded in ADR 019 and the committed report, no bar, price, reference or default change).
