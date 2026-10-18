# Holdout rule version 7 in code

## Context

Version 7 of the holdout rule (ADR 032, `docs/holdout-rule.md`, committed in `e67971b`) draws the 20 targets by one walk of the salted order, without sides, and moves the sides to each run: a run splits its targets on the latest cutoff of its models, a model whose vendor declares no knowledge cutoff taking its release date with the page that records it. The code is still on version 6. The log entry of version 7 lists what lags behind: the draw-order printer tallies two sides on a cutoff, the draw record carries a cutoff and a side per walk step and caps a side at 10 targets, the holdout target and the calibration kit carry a side, the run report does not name the cutoff of the run and its type, `evals/holdout_conditions.json` holds the placeholder `<vendor wording, confirmed at draw>` for the type of the `gpt-6-luna` cutoff, its loader does not refuse it, and the file has no field for the page a cutoff is taken from. The entry also notes that the census carries a single date bound, so the loader cannot read an extension.

This plan brings the code in line with version 7 before the draw. No target is drawn, `HOLDOUT_TARGETS` stays empty and `evals/holdout_census.json` has no `draw`, so no stored artifact needs a migration.

## Decisions

1. **Extensions, additions and replacements are not built here.** The census keeps its single bound, and `DrawRecord` keeps one walk, the draw. Under version 7 an extension of the census and an addition of targets open no version of the rule, so their code can arrive with the first extension, addition or replacement, which will give it real data to be checked against. Building segments now would mean a format no record has ever exercised. The log entry of this plan corrects the statement of the version 7 entry that all of it is brought in line before the draw, on this point only.
2. **The statistic of a paired comparison between two runs is out of scope.** The rule already fixes its form (targets gained and lost on the targets both ran, never by the overlap of intervals). Choosing an interval, a test and a treatment of multiple comparisons is a decision of method that bears on the choice of model, and belongs to the ADR of that choice, together with the winner's curse. No comparison command is built.
3. **Every cutoff carries a source page**, not only a release date. The rule demands the page for a release date. Requiring it for every cutoff costs two URLs today and makes each cutoff checkable from the file.
4. **`HoldoutTarget` is removed.** Without `side` it wraps one field and adds only an `identifier` alias of `cve_id`. `HOLDOUT_TARGETS` becomes a `tuple[CVETarget, ...]`. The module `evals/holdout_targets.py` stays, since the import isolation test pins that no instrument module imports it.
5. **`Side` and `side_of` move to `evals/holdout_statistic.py`.** Sides are now a notion of the run alone, and the statistic is the only module that computes them. `evals/census_draw.py` keeps the draw-time schema only.
6. **Readiness, not loading, refuses an incomplete cutoff.** `load_conditions` keeps its contract (loading never checks readiness). `require_ready` refuses, for each model of the run, a cutoff with no type or no source.
7. **The report computes the run cutoff from the run itself.** `HoldoutRunResult.cutoffs` already holds exactly the cutoffs of the run's models, generator then judge (`holdout_run.py`, built from `model_ids`). `build_report(run)` takes the latest of them, so the cutoff the split uses cannot disagree with the cutoffs the report lists. `HoldoutConditions.run_cutoff` goes, and no `RunCutoff` type is added.

## Approach

Remove the sides from everything the draw touches, give the conditions file a source per cutoff and refuse an incomplete one at readiness, make the run report name the run's cutoff, then fill the `gpt-6-luna` cutoff type and both sources, update the living docs and log the alignment.

## Files to modify

### `evals/census_draw.py`

- Module docstring: drop "the side of a flaw on the cutoff". It holds the draw record and the calibration cards.
- Remove `Side`, `side_of`, and the `date` import if it becomes unused (it stays used by `draw_problems`'s `disclosure_dates: Mapping[str, date]` signature).
- `DrawWalkStep`: remove `side`. Fields left: `identifier`, `outcome`, `reason`.
- `DrawRecord`: remove `cutoff`, `cutoff_type`, `cutoff_note`. Fields left: `rule_commit`, `grammar_fingerprint`, `settlements`, `walk`, `cards`, `card_checks`, `give_ups`, `drawn`.
- `draw_problems`: `_count_problems` takes the draw only and keeps the single check `len(draw.drawn) > 20` with its message unchanged. The per-side `Counter` and its message go. `disclosure_dates` stays a parameter of `draw_problems`, still used for membership.
- `Counter` import goes if unused.

### `evals/holdout_draw.py`

- Docstring: "the backbone of the walk" instead of both sides' walks, and the per-walk state is the skips and the stop at 20 targets.
- `DrawEntry`: remove `side`. Fields: `digest`, `identifier`, `disclosure_date`.
- `draw_order(census: HoldoutCensus) -> list[DrawEntry]`: the `cutoff` parameter goes. Sort key unchanged.

### `evals/run_holdout.py`

- `draw-order` subparser: remove `--cutoff`, `--cutoff-type`, `--cutoff-note`. `--census` stays.
- `_draw_order`: prints `"{n} candidates in draw order:"` then one line per entry, `f"  {entry.digest[:12]}  {entry.identifier}  {entry.disclosure_date}"`. No cutoff line, no tally. `Counter` and `Side` imports go.
- `_run`: `build_report(run)`, the run cutoff coming from the run (Decision 7).
- Help text of `draw-order`, if it mentions a tally, follows.

### `evals/holdout_targets.py`

- Remove `HoldoutTarget` and the `Side` import. `HOLDOUT_TARGETS: tuple[CVETarget, ...] = ()`.
- Docstring: a drawn target is an acceptance `CVETarget`, which every reused instrument takes unchanged. Keep the paragraphs about `mcp_auditor` cleanliness, the empty tuple until the draw session, and the import isolation. Drop the sentence "Nothing imports it yet: the holdout run mode is a later plan", which is already false (`run_holdout` imports it).

### `evals/holdout_run.py`

- Replace `HoldoutTarget` by `CVETarget` in every signature (`run_holdout`, `_refuse_tools_filter`, the disclosure-date refusal, `_refuse_unknown_places`, the vetting, `_run_targets`, the assembly, and the tuples `tuple[CVETarget, HoldoutTargetResult]`). `entry.target` becomes the target itself, `entry.identifier` becomes `target.cve_id`. Variable names `entry` become `target` where the old `target = entry.target` alias existed (line 256), so no shadowing remains. No behaviour change.
- The `cutoffs` field of the run result (line 318) is unchanged.

### `evals/holdout_kit/kit_target.py`

- Remove the kit-local `Side` enum and the `side` field of `KitTarget`.
- Docstring: the transplant wraps the authored `KitTarget` into a `CVETarget` and appends it to `HOLDOUT_TARGETS`. Drop "and the draw side of evals/census_draw.Side", "plus `side`", "into HoldoutTarget(target, side)", and `Side` from the list of kit-local copies.
- Any kit file that sets or reads `side` follows. Today only `kit_target.py` does under `evals/holdout_kit/` (the `host-side` comment of `kit_client.py` is unrelated). In `evals/calibration_dossier.py`, the `_FIXTURE_FORMAT` text drops "and into `HoldoutTarget(target, side)`" (the transplant ends at the `CVETarget`) and the `side` bullet of the `KitTarget` fields.

### `evals/holdout_statistic.py`

- Gains `Side` (`StrEnum` with `PRE_CUTOFF = "pre_cutoff"`, `POST_CUTOFF = "post_cutoff"`, values unchanged so the report JSON keeps its values) and `side_of(disclosure_date: date, cutoff: date) -> Side` (on or before the cutoff is pre-cutoff, unchanged). The import from `census_draw` goes. Docstring: drop "passed in rather than imported" if it referred to the cutoff only, keep the sentence that the run's own cutoff is passed in.

### `evals/holdout_conditions.py`

```python
@dataclass(frozen=True)
class Cutoff:
    date: date
    type: str | None
    source: str | None
    note: str | None
```

- `_cutoff(entry)` reads `entry["source"]` beside the other keys. A file without the key fails on load with a `KeyError`, like the other keys today.
- `require_ready(model_ids)`: for each model with a logged cutoff, append `f"no cutoff type for {model}"` when `type` is `None` or blank, and `f"no cutoff source for {model}"` when `source` is `None` or blank. Existing reasons unchanged, all reasons gathered in one `Refused`.
- `run_cutoff` is removed (Decision 7). If `require_ready` grows past about 20 lines, the per-cutoff reasons move to a private helper just below it.

### `evals/holdout_conditions.json`

- Each cutoff gains `"source"`.
- `gpt-6-luna`: `"type": "knowledge cutoff"` as OpenAI words it on the model's page ("May 18, 2026 knowledge cutoff", under "Model details"), `"source": "https://developers.openai.com/api/docs/models/gpt-6-luna"`. Wording and URL checked by the diligence pass on 2026-10-18, the maintainer confirms before the commit. The date 2026-05-18 stays, the version 7 entry keeps it as the model's cutoff.
- `claude-haiku-5-5`: `"source": "https://platform.claude.com/docs/en/models/haiku-5-5/overview"`, whose Capabilities table gives "Reliable knowledge cutoff | Jun 2026" and "Training data cutoff | Jun 2026", checked the same way. Type and note unchanged.

### `evals/holdout_report.py`

- `CutoffModel` gains `source: str | None`, `of` copies it.
- New model:

```python
class RunCutoffModel(BaseModel):
    model: str
    date: date
    type: str | None
    source: str | None
    note: str | None
```

- `HoldoutReport` gains `run_cutoff: RunCutoffModel`, placed beside `sides`.
- `build_report(run: HoldoutRunResult) -> HoldoutReport`: a private `_run_cutoff(cutoffs: Mapping[str, Cutoff]) -> tuple[str, Cutoff]` right below its caller takes the model with the latest date, the first in `run.cutoffs` order on a tie (`max` keeps the first), so the generator is named when generator and judge share a date. A one-line comment states the tie rule. The split uses that date, and the pair fills `run_cutoff`. A run always has at least one model, so `run.cutoffs` is never empty.
- Markdown: `_split_section` opens with `f"- run cutoff: {date} ({type}), {model}, {source}"`, followed by `f", note: {note}"` when the note is set, before the side lines. The section title stays "Split by cutoff side".
- `Side` is imported from `evals.holdout_statistic`.

### Tests

The behaviour tests below replace or extend the existing ones in `tests/unit/test_census_draw.py`, `test_holdout_draw.py`, `test_holdout_conditions.py`, `test_holdout_report.py`, `test_holdout_statistic.py`, `test_holdout_run.py`, `test_holdout_targets.py`, `test_holdout_kit_isolation.py` and `test_run_holdout.py`, with their `_given` and `_then` files. A test that only asserted the per-side cap, a `side` on a walk step, a draw entry or a target, or the cutoff arguments of `draw-order` is deleted, not adapted. Fixtures and builders that set `side=`, `cutoff=`, `cutoff_type=` or `cutoff_note=` drop those arguments. Specific spots:

- Every `Cutoff(...)` built in a test gains `source` (`test_holdout_conditions.py`, positional `Cutoff(date, type, None)` calls included, `test_holdout_report.py`, `test_holdout_run.py`), and every conditions payload dict in `test_holdout_conditions.py` gains a `"source"` key, or it fails to load.
- `test_side_of_counts_the_cutoff_day_itself_as_pre_cutoff` moves from `test_holdout_draw.py` to `test_holdout_statistic.py`, importing `side_of` from `evals.holdout_statistic`.
- `test_run_holdout.py`: the malformed-census test drops `--cutoff` from its argv (it would otherwise exit 2 on argparse, not 3), `test_draw_order_without_a_cutoff_is_an_argparse_error` is deleted.
- `test_holdout_kit_isolation.py`: `test_kit_target_mirrors_the_drawn_cve_target_fields` asserts `kit_names == _DRAWN_TARGET_FIELDS` (no `"side"` assertion), and the comment above `_DRAWN_TARGET_FIELDS` drops `HoldoutTarget` and `side`.
- `test_holdout_targets.py`: every test that reads `entry.target.*` or `entry.identifier` iterates the targets directly (`target.cve_id`, `target.tools_filter`, `target.ci_skip_reason`), the four structural guards of lines 85 to 118 included. With an empty tuple they pass at runtime, but pyright strict refuses the attribute access on `CVETarget`.
- `test_holdout_conditions.py`: `test_run_cutoff_returns_the_latest_cutoff` and `test_run_cutoff_takes_the_latest_among_the_run_models` are deleted with `run_cutoff`, their behaviour moving to the report tests. `test_holdout_report.py`: the `build_report(_run_result(), RUN_CUTOFF)` calls (lines 91 and 98) become `build_report(run)`, the run's `cutoffs` setting the cutoff, and `RUN_CUTOFF` goes.
- `test_run_holdout.py::test_run_refuses_the_incomplete_committed_conditions_once_a_target_is_in_play` already refuses today on the tools filter of CVE-2025-53109, not on the conditions. Renamed in step 1 after the reason it refuses for, and kept as a check that the run refuses without reaching Docker or an LLM.

### Living docs

- `CLAUDE.md`, Commands: `uv run python -m evals.run_holdout draw-order  # CVE holdout: print the salted-SHA draw order of the draw-order candidates with each one's disclosure date (--census defaults to evals/holdout_census.json, no LLM, no network)`. The `run` line (line 39) adds to its requirements a cutoff with its type and source page for each model of the run in `evals/holdout_conditions.json`.
- `CONTRIBUTING.md` (line 54): the same command without `--cutoff`, no per-side tally, and the draw described as one walk to 20 targets. The list of what `run_holdout run` needs ("the drawn targets, the chain and timeout run conditions …, Docker and an LLM key") gains "a cutoff with its type and source page for each of its models in `evals/holdout_conditions.json`".
- `CHANGELOG.md`, `[Unreleased]`: amend the existing `run_holdout` entry (line 16) so it no longer advertises `--cutoff` and a per-side tally, and add a line: the holdout run report names the run's cutoff (the model that gives it, its date, type and source), and a run refuses to start when a model's cutoff has no type or no source in `evals/holdout_conditions.json`.
- `README.md`: only if it describes the draw-order command or the conditions file in terms this plan changes; the implementer greps `draw-order`, `per-side` and `cutoff` and updates what is stale, nothing else.
- `evals/holdout_census_method.md`: same grep, same rule.

### `docs/holdout-log.md`

One entry, dated the day of the commit: the code brought in line with version 7. The draw-order printer prints the order without sides, the draw record holds no cutoff and no side and caps the draw at 20 targets, the holdout target and the calibration kit carry no side, the run report names the cutoff of the run with its model, type and source, and `evals/holdout_conditions.json` gives each cutoff a type and a source page, a run refusing a model whose cutoff lacks either. The cutoffs it records: `gpt-6-luna` at 2026-05-18, of type `knowledge cutoff` as OpenAI words it ("May 18, 2026 knowledge cutoff"), from https://developers.openai.com/api/docs/models/gpt-6-luna, which settles the type the version 7 entry left to confirm, and `claude-haiku-5-5` at 2026-06-30, type and note as its 2026-10-17 entry gives them, from https://platform.claude.com/docs/en/models/haiku-5-5/overview. Loading an extension of the census and walking an addition or a replacement are not built: they are built with the first extension, addition or replacement, which opens no version of the rule, so the statement of the version 7 entry that all of it is brought in line before the draw holds except on this point. No target is drawn, so no target changes. The entry is written in the last commit of the implementation, and a follow-up commit records the range of the implementation's commits, as previous entries record their commit (`afafda1` for `e67971b`).

## What stays unchanged

- The rule, the ADRs, `evals/holdout_places.json` and the deployment layout: no version opens.
- The salt, the digest, the draw order and its sort key, `draw_order_flaws` and the criteria of the draw order.
- `evals/holdout_census.json`, the census model (`HoldoutCensus`, its single `bound` and `bound_commit`, `rule_version` 3), `load_census` apart from what `draw_problems` checks.
- The walk outcomes (`drawn`, `skipped`, `given_up`, `excluded`) with their free-text reason: a skip because the server gives a census flaw to the acceptance layer is recorded as any other skip.
- The statistic: the split, the contrast and its 5-targets threshold, the conclusion check, the intervals.
- `CVETarget`, `cve_targets.py`, every acceptance instrument, the fixture and grammar fingerprints, every baseline.
- The calibration cards, settlements, give-ups and their checks in `census_draw.py`.
- The refusal policy, the retries, the cost, the tracing refusal and every other part of `run_holdout run`.

## Edge cases

- Generator and judge are the same model: the run's `cutoffs` holds it once and the report names it.
- Generator and judge have the same cutoff date and different types: the generator is named, its type and source shown. The report's `cutoffs` field still lists both models.
- A model of the run has no cutoff entry: refused as today, with `no logged cutoff for {model}`; the type and source checks are not added for it (no double reason).
- A cutoff with `type` set and `source` missing (`null` or `""`): `require_ready` refuses with `no cutoff source for {model}`.
- A conditions file without the `source` key in a cutoff: `load_conditions` fails, as for any missing key.
- A draw record with more than 20 drawn flaws: refused, message unchanged.
- A draw record whose 20 drawn flaws are all on one side of any date: valid.

## Test scenarios

- `draw_problems`, called directly, returns `[]` for a draw of 20 consistent drawn flaws all disclosed after one date (formerly over the per-side cap). A builder in the test's `_given` file makes N consistent drawn flaws: N census flaws that are draw-order candidates, each with a `drawn` walk step, a card, a card check, and CALIBRATOR and CARD_CHECKER agent records, generalising the existing one-flaw `_a_draw` and `_census_of`. The refusal of 21 stays covered by the existing `test_a_drawn_list_over_twenty_fails`, not duplicated.
- `draw_order(census)` returns every draw-order candidate in digest order, each with its disclosure date, for a census given by the existing builders.
- `run_holdout draw-order` prints the candidate count and one line per candidate with digest prefix, identifier and disclosure date, and no `pre_cutoff` or `post_cutoff` text.
- `require_ready` on a conditions file whose run model has a `null` type refuses with `no cutoff type for {model}`; with an empty source, `no cutoff source for {model}`; with both missing, both reasons in one refusal; with both present and the chain settings set, passes.
- `build_report(run)` with cutoffs `{"a": earlier, "b": later}` names `b` in `run_cutoff` with its date, type, source and note and splits the targets on `b`'s date. With equal dates it names `a`. The markdown's split section opens with the run cutoff line, with the note when set.
- `split_by_side` and `side_of` keep their behaviour from their new module (existing statistic tests, import path updated).
- `run_holdout` on fake services runs a tuple of `CVETarget` as it ran the wrapped targets (existing run tests, wrapper removed).
- The kit isolation test's field parity between `KitTarget` and `CVETarget` holds without `side`.
- The committed `evals/holdout_conditions.json` loads, and `require_ready` passes for `["gpt-6-luna"]` and for `["claude-haiku-5-5"]` (extends the existing test of the committed file).

## Verification

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run python -m evals.run_holdout draw-order | head -5
uv run python -m evals.run_holdout run   # prints that no holdout target is drawn, exit 0
grep -rnE "\b([Ss]ide|side_of|cutoff_type|cutoff_note|HoldoutTarget)\b" evals/census_draw.py evals/holdout_draw.py evals/holdout_targets.py evals/holdout_run.py evals/holdout_kit/ evals/run_holdout.py evals/calibration_dossier.py | grep -v "host-side"
```

The last grep returns nothing (`\bHoldoutTarget\b` leaves `HoldoutTargetResult` alone, and the `host-side` comment of `kit_client.py` is filtered).

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, kept here so the implementation-phase fact check can read it. A line records what was concluded once, on 2026-10-18, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `"type": "knowledge cutoff"` for `gpt-6-luna`, date `2026-05-18` (verified against https://developers.openai.com/api/docs/models/gpt-6-luna, "May 18, 2026 knowledge cutoff" under "Model details")
- SETTLED: `"source": "https://developers.openai.com/api/docs/models/gpt-6-luna"` (page fetched, model ID `gpt-6-luna`)
- SETTLED: `"source": "https://platform.claude.com/docs/en/models/haiku-5-5/overview"` for `claude-haiku-5-5` (page fetched, model ID `claude-haiku-5-5`, "Reliable knowledge cutoff | Jun 2026", "Training data cutoff | Jun 2026", consistent with the committed type, note and date `2026-06-30`)

## Implementation steps

Commands (from `CLAUDE.md`): short loop `uv run pytest tests/unit -n auto --maxprocesses 4` and `uv run pyright <changed files>`, closing check `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (no file argument). Each step ends green and is one commit. No step touches the rule, the ADRs, `evals/holdout_places.json` or `evals/holdout_census.json`.

### Step 1: Remove `HoldoutTarget`, the holdout target becomes a `CVETarget`

- **Files**: `tests/unit/test_holdout_targets.py`, `tests/unit/test_holdout_run.py`, `tests/unit/test_holdout_kit_isolation.py`, `tests/unit/test_run_holdout.py` (the one test that builds a `HoldoutTarget`), `evals/holdout_targets.py`, `evals/holdout_run.py`, `evals/holdout_kit/kit_target.py`, `evals/calibration_dossier.py`.
- **Do**:
  - Tests first. `test_holdout_targets.py`: drop the `Side` and `HoldoutTarget` imports, the empty-tuple test asserts `HOLDOUT_TARGETS == ()` and that every entry is a `CVETarget`, delete `test_identifier_reads_from_the_composed_target` (it only asserted the wrapper and its `side`), and every test that reads `entry.target.*` or `entry.identifier` iterates targets directly (`target.cve_id`, `target.tools_filter`, `target.ci_skip_reason`), the disjointness and tools-filter tests and the four structural guards of lines 85 to 118 included (pyright strict fails on them otherwise). `test_holdout_run.py`: `_entry` becomes a builder returning a `CVETarget` (rename it `_target`), line 303 likewise, `targets: list[CVETarget]`, drop the `Side` and `HoldoutTarget` imports. `test_run_holdout.py`: `monkeypatch.setattr("evals.holdout_targets.HOLDOUT_TARGETS", (CVE_TARGETS[0],))`, drop the `HoldoutTarget` import and the `Side` import (its only use, line 42, goes with the wrapper, and ruff F401 would fail otherwise), and rename `test_run_refuses_the_incomplete_committed_conditions_once_a_target_is_in_play` after the reason it refuses for today (the tools filter of the acceptance target), its body still asserting the refusal exit without Docker or an LLM. `test_holdout_kit_isolation.py`: `test_kit_target_mirrors_the_drawn_cve_target_fields` asserts `kit_names == _DRAWN_TARGET_FIELDS`, no `"side"`, and the comment above `_DRAWN_TARGET_FIELDS` drops `HoldoutTarget` and `side`. Run them, confirm red.
  - `evals/holdout_targets.py`: remove `HoldoutTarget` and the `Side` import, `HOLDOUT_TARGETS: tuple[CVETarget, ...] = ()`. Docstring per the plan: a drawn target is an acceptance `CVETarget`, which every reused instrument takes unchanged. Keep the paragraphs on `mcp_auditor` cleanliness, the empty tuple until the draw session and the import isolation, drop "Nothing imports it yet: the holdout run mode is a later plan".
  - `evals/holdout_run.py`: `HoldoutTarget` becomes `CVETarget` in every signature and tuple listed in the plan. `entry.target` becomes the target, `entry.identifier` becomes `target.cve_id`, and where `target = entry.target` aliased (around line 256) the parameter is named `target` so nothing shadows. `deps.rebuild(target_services(list(targets)))` or equivalent. No behaviour change, the `cutoffs` field of the run result is unchanged.
  - `evals/holdout_kit/kit_target.py`: remove the kit-local `Side` enum and the `side` field of `KitTarget`, docstring edits per the plan (no "draw side of evals/census_draw.Side", no "plus `side`", the transplant wraps `KitTarget` into a `CVETarget` appended to `HOLDOUT_TARGETS`, `Side` gone from the kit-local copies list). Check `StrEnum` is still imported only if `LaunchMode`/`FallbackScope` use it.
  - `evals/calibration_dossier.py`: in `_FIXTURE_FORMAT`, drop "and into `HoldoutTarget(target, side)`" and the `side` bullet of the `KitTarget` fields.
  - `Side` and `side_of` stay in `evals/census_draw.py` for this step (step 2 moves them).
- **Test**: existing run tests pass with bare `CVETarget`s (refusals for tools filter, missing census, unknown places, vetting, assembly unchanged). Kit field parity holds without `side`. Empty tuple loads, disjointness and no-tools-filter tests hold. `test_calibration_dossier_writes_an_isolated_kit` still passes (the kit copies `kit_target.py`).
- **Verify**: short loop, `uv run pyright` on the changed files, then the closing check. `grep -rnE "\b(HoldoutTarget|side)\b" evals/holdout_targets.py evals/holdout_run.py evals/holdout_kit/ evals/calibration_dossier.py | grep -v host-side` returns nothing.

### Step 2: The draw without sides, `Side` moves to the statistic

- **Files**: `tests/unit/test_census_draw.py`, `tests/unit/test_holdout_draw.py`, `tests/unit/test_holdout_statistic.py`, `tests/unit/test_run_holdout.py`, `tests/unit/test_holdout_report.py` (import path only), `evals/census_draw.py`, `evals/holdout_draw.py`, `evals/holdout_statistic.py`, `evals/run_holdout.py`, `evals/holdout_report.py` (import only), `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do**:
  - Tests first. `test_census_draw.py`: builders drop `side=`, `cutoff=`, `cutoff_type=`, `cutoff_note=`, delete tests that only asserted the per-side cap or a step's `side`, add: `draw_problems` called directly returns `[]` for a draw of 20 consistent drawn flaws all disclosed after one date, built by a new `_given` builder of N consistent drawn flaws (census flaws that are draw-order candidates, each with a `drawn` walk step, a card, a card check, CALIBRATOR and CARD_CHECKER agent records, generalising `_a_draw` and `_census_of`). Keep `test_a_drawn_list_over_twenty_fails` for the refusal of 21. `test_holdout_draw.py`: `draw_order(census)` without a cutoff returns every draw-order candidate in digest order with its disclosure date, delete side assertions, move `test_side_of_counts_the_cutoff_day_itself_as_pre_cutoff` to `test_holdout_statistic.py` importing `side_of` from `evals.holdout_statistic`. `test_holdout_statistic.py` and `test_holdout_report.py`: import `Side` from `evals.holdout_statistic`. `test_run_holdout.py`: replace the tally test by one asserting `draw-order --census PATH` exits 0, prints the candidate count and one line per candidate with digest prefix, identifier and disclosure date, and no `pre_cutoff`/`post_cutoff` text, delete `test_draw_order_without_a_cutoff_is_an_argparse_error`, drop `--cutoff` from the malformed-census argv (still exit 3). Confirm red.
  - `evals/holdout_statistic.py`: define `Side` (`StrEnum`, `PRE_CUTOFF = "pre_cutoff"`, `POST_CUTOFF = "post_cutoff"`) and `side_of(disclosure_date, cutoff) -> Side` (on or before the cutoff is pre-cutoff), drop the import from `census_draw`, docstring keeps that the run's cutoff is passed in. `Side` is defined above `SideStatistic`, whose annotation uses it. `side_of` goes below its caller or near the top as a public definition, whichever reads best.
  - `evals/census_draw.py`: per the plan, remove `Side`, `side_of`, `DrawWalkStep.side`, `DrawRecord.cutoff`/`cutoff_type`/`cutoff_note`, `_count_problems` takes the draw only and keeps the `len(draw.drawn) > 20` check with its message, remove `Counter`/`StrEnum` imports if unused, `date` stays (used by `draw_problems`). Docstring drops "the side of a flaw on the cutoff", and its sentence that holdout_draw and holdout_census both import from it is updated: after this step only holdout_census imports from it, so the sentence names it alone.
  - `evals/holdout_draw.py`: `DrawEntry` loses `side`, `draw_order(census)` loses `cutoff`, sort key unchanged, docstring per the plan.
  - `evals/run_holdout.py`: `draw-order` loses `--cutoff`, `--cutoff-type`, `--cutoff-note`, `_draw_order` prints `f"{len(entries)} candidates in draw order:"` then `f"  {entry.digest[:12]}  {entry.identifier}  {entry.disclosure_date}"` per entry, no cutoff line, no tally, drop `Counter` and `Side` imports, help text follows.
  - `evals/holdout_report.py`: import `Side` from `evals.holdout_statistic` (nothing else in this step).
  - Living docs: `CLAUDE.md` Commands, the `draw-order` line exactly as the plan gives it. `CONTRIBUTING.md` line 54: the command without `--cutoff`, no per-side tally, the draw described as one walk to 20 targets. `CHANGELOG.md` `[Unreleased]` line 16: amend so it no longer advertises `--cutoff` and a per-side tally.
- **Test**: the scenarios above, plus the existing `split_by_side` and statistic tests unchanged apart from the import.
- **Verify**: short loop, pyright on changed files, then the closing check. `uv run python -m evals.run_holdout draw-order | head -5` prints the count and digest lines. The plan's grep (`\b([Ss]ide|side_of|cutoff_type|cutoff_note|HoldoutTarget)\b` over the listed files, `host-side` filtered) returns nothing.

### Step 3: Cutoff source, readiness refusal, the run cutoff in the report, docs and log

- **Files**: `tests/unit/test_holdout_conditions.py`, `tests/unit/test_holdout_report.py`, `tests/unit/test_holdout_run.py` (`Cutoff(...)` gains `source`), `evals/holdout_conditions.py`, `evals/holdout_conditions.json`, `evals/holdout_report.py`, `evals/run_holdout.py`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CLAUDE.md`, `docs/holdout-log.md` (plus `README.md` and `evals/holdout_census_method.md` only if the grep finds stale text).
- **Do**:
  - Tests first. `test_holdout_conditions.py`: every payload dict cutoff gains `"source"`, every `Cutoff(...)` (positional ones included) gains `source`. Add: `require_ready` refuses with `no cutoff type for {model}` on a `null` type, `no cutoff source for {model}` on an empty source, both reasons in one `Refused` when both are missing, passes when both are present and chain settings set. A model with no cutoff entry gets only `no logged cutoff for {model}` (no type/source reasons). A cutoff missing the `source` key fails to load (`KeyError`). Delete the two `run_cutoff` tests. Extend the committed-file test: `load_conditions(CONDITIONS_PATH)` then `require_ready(["gpt-6-luna"])` and `require_ready(["claude-haiku-5-5"])` pass. `test_holdout_report.py`: `build_report(run)` with cutoffs `{"a": earlier, "b": later}` names `b` in `run_cutoff` (date, type, source, note) and splits on its date, with equal dates names `a`, `CutoffModel` carries `source`, and the markdown split section opens with `- run cutoff: {date} ({type}), {model}, {source}` plus the note when set. The `build_report(_run_result(), RUN_CUTOFF)` calls become `build_report(run)` and `RUN_CUTOFF` goes. `test_holdout_run.py`: the `Cutoff(...)` gains `source`. Confirm red.
  - `evals/holdout_conditions.py`: `Cutoff` gains `source: str | None` (field order `date, type, source, note` as in the plan), `_cutoff` reads `entry["source"]`. `require_ready` adds, per model with a logged cutoff, the type and source reasons (blank counts as missing), all reasons in one `Refused`. `run_cutoff` is removed. Watch the 20-line limit on `require_ready`: extract a small helper for the per-cutoff reasons if it grows past it.
  - `evals/holdout_conditions.json`: each cutoff gains `"source"`. `gpt-6-luna`: `"type": "knowledge cutoff"`, `"source": "https://developers.openai.com/api/docs/models/gpt-6-luna"`, date unchanged. `claude-haiku-5-5`: `"source": "https://platform.claude.com/docs/en/models/haiku-5-5/overview"`, type and note unchanged. Leave the JSON values for the maintainer's confirmation before commit, as the plan says.
  - `evals/holdout_report.py`: `CutoffModel` gains `source`, `of` copies it. New `RunCutoffModel(model, date, type, source, note)`, `HoldoutReport.run_cutoff` beside `sides`. `build_report(run)` computes the run cutoff with the private `_run_cutoff(run.cutoffs)` (latest date, first in order on a tie, one-line comment), splits on its date and fills the field. `_split_section` opens with the run cutoff line, title unchanged. `evals/run_holdout.py`: `_run` calls `build_report(run)`.
  - Living docs: `CHANGELOG.md` `[Unreleased]`, add the line that the holdout run report names the run's cutoff (model, date, type, source) and a run refuses when a model's cutoff has no type or no source in `evals/holdout_conditions.json`. `CONTRIBUTING.md`: the list of what `run_holdout run` needs gains "a cutoff with its type and source page for each of its models in `evals/holdout_conditions.json`". `CLAUDE.md`: the `run_holdout run` line (line 39) gains the same requirement. Grep `README.md` and `evals/holdout_census_method.md` for `draw-order`, `per-side` and `cutoff`, update only what is stale.
  - `docs/holdout-log.md`: one entry dated the commit day, content as the plan's `docs/holdout-log.md` section gives it, the two cutoffs with their type and page included (no hash, the follow-up commit records the range of the three commits). Follow the format of the existing entries and the user's writing preferences (no em dashes, few semicolons).
- **Test**: the scenarios above, plus the full holdout run tests on fakes unchanged.
- **Verify**: closing check (`uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`). `uv run python -m evals.run_holdout run` prints that no holdout target is drawn and exits 0. The plan's final grep returns nothing.
