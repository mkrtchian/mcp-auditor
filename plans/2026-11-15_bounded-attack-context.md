# Bounded attack context, merged in code

## Context

ADR 035 (`docs/adr/035-attack-context-merged-in-code.md`) supersedes the "Context merging" section of ADR 009. Today the context extraction call returns the whole attack context after each tool, the existing content merged with the new, so its answer grows with the number of tools already audited until it is cut at the output limit and the call becomes a missed model call. This plan implements the decision: the call reports what the results of the current tool show, and a pure function in the domain merges that answer into a bounded attack context.

Read ADR 035 before any step. It is the specification, and this plan only adds what the ADR leaves to the code: the bound values, the storage of the notes, and the prompt wording.

## Approach

One change to the system under test, in three places: a new pure merge in the domain, the extraction node that calls it, and the extraction prompt. The shape of `AttackContext` does not change, so the Anthropic wire models, the checkpoint format and the model probe's schema list are untouched. Its docstring does change: it reaches the model as the description of the answer schema, and today it says "Accumulated intelligence from previous tool audits.", which asks for the whole context back, against the new instruction to report only what the current tool's results show. It becomes "What tool audits show about the server.", which fits both the carried context and one answer. The rendering of the context in the generation and chain planning prompts (`format_attack_context`) does not change either: only the extraction prompt gets a new rendering, since it is the only prompt where the model has to copy an item back.

## The merge

New module `src/mcp_auditor/domain/attack_context.py` (`domain/models.py` is already over 300 lines, and `AttackContext` stays there). It holds the four bounds as module constants and one public function:

```python
MAX_LIST_ITEMS = 30
MAX_ITEM_LENGTH = 300
MAX_NOTES = 15
MAX_NOTE_LENGTH = 400


def merge_attack_context(carried: AttackContext, reported: AttackContext, tool_name: str) -> AttackContext: ...
```

The module docstring states the principle that sets the bounds (the merge drops nothing on a server of five to ten tools, ADR 035), the assumption under it for the lists (about three new items per tool and per list, or fewer), and what the order of a list means. Rules, each a small private helper below the public function (newspaper rule):

- **Lists** (`exposed_internals`, `effective_payloads`). The order of a list carries how recently an item was reported: the last item is the most recent. Each reported item has every run of whitespace (newlines included) collapsed to one space and is stripped, and is stored in that form, so an item never holds a newline. A blank one is skipped, and one longer than `MAX_ITEM_LENGTH` is dropped. Two items are the same when they match after `casefold()`. The order of operations is: collapse and strip, skip blank, drop over-long, replace and move to the end, evict from the front. A reported item already in the list takes the place of the earlier occurrence and moves to the end, so a list item stays as long as the results of later tools keep showing it. When the list is longer than `MAX_LIST_ITEMS`, the items at the front are evicted. Carried items go through the same rules, so a context over the bounds, from an audit checkpointed before this change, is trimmed at its first merge.
- **Observations.** The field stays a `str` and holds one note per line. The reported `observations`, with every run of whitespace (newlines included) collapsed to one space and stripped, becomes the note `"<tool_name>: <text>"`, cut at `MAX_NOTE_LENGTH`. A reported text that already starts with `"<tool_name>: "` loses that prefix first, since the prompt shows the notes in that form and the model may imitate it. A report that is blank after the collapse adds no note. The tool name goes through the same collapse. An earlier note of the same tool (a note starting with `"<tool_name>: "`) is removed and the new note goes to the end, so the order of the notes is the order of their last report. A blank report leaves an earlier note of the same tool in place. When there are more than `MAX_NOTES` notes, the oldest are evicted. The carried observations are read as one note per non-blank line, each cut at `MAX_NOTE_LENGTH`, so a single-line block of an earlier checkpoint counts as one note and a multi-line one as one note per line. An empty tool name, or one that is the start of a legacy line, only weakens the replacement of an earlier note, which is accepted.
- **Scalar fields** (`db_engine`, `framework`, `language`). A reported value that is not `None`, not blank and, once stripped, at most `MAX_ITEM_LENGTH` long replaces the carried one, stored stripped. Otherwise the carried value stays, unless it is itself longer than `MAX_ITEM_LENGTH`, in which case it is dropped.

Do not export `merge_attack_context` from `domain/__init__.py`: the graph imports domain functions from their module (`nodes.py` takes `completion_size` and `find_coverage_gap` from `mcp_auditor.domain.coverage`), so `nodes.py` imports it from `mcp_auditor.domain.attack_context`.

## The node

`make_extract_attack_context` in `src/mcp_auditor/graph/nodes.py`: on an answer, the state update carries `merge_attack_context(existing_context, answer_context, tool_report.tool.name)` in place of the answer itself. On a missed model call nothing changes: the existing context is kept and the miss is recorded.

## The extraction prompt

`build_context_extraction_prompt` in `src/mcp_auditor/graph/prompts.py`:

- The existing context is rendered by `_format_existing_context` (already in `prompts.py`, today a wrapper over `format_attack_context` under the header "What we already know:"), rewritten so it no longer calls `format_attack_context`. It keeps the "What we already know:" header, which `test_omits_existing_context_when_empty` reads, and renders the three scalar fields on one line each, each list under its label with one item per line, the observations under their label with one note per line. An empty context still renders nothing.
- The closing instruction ("Preserve all previous findings and add new ones. Do not lose information from earlier audits.") is replaced. The new instructions must say, in plain words: report only what these results show; the answer is added to what is already known by a later step, so items the results do not show are not copied; when the results confirm an item listed above, repeat it in the same words; one fact per item, in one short sentence; in `observations`, one short note about this tool; leave a field empty when these results show nothing for it; set the database engine, the framework or the language only when these results show it, in a few words, and the values listed above are the current ones. The prompt states the two length bounds, `MAX_ITEM_LENGTH` for an item and `MAX_NOTE_LENGTH` for the note, imported from `mcp_auditor.domain.attack_context`, so the model does not write an item the merge would drop on every report.
- The "Look for" list stays as it is.

The word "findings" leaves the prompt with the old instruction. The glossary entry **finding** carries a `Not:` clause about "the findings the context-extraction prompt asks for": remove that clause in the same change, since nothing asks for them any more.

## What stays unchanged

- `AttackContext` (fields, types, `is_empty`; only its docstring changes), `graph/state.py`, the Anthropic wire models and their parity test.
- `format_attack_context`, `build_context_section`, the generation prompt and the chain planning prompt.
- `_MAX_OUTPUT_TOKENS` and everything in `adapters/`.
- The judge prompts and the judge eval.
- `evals/declared_flips.json`: nothing is declared. On the honeypots (two or three tools each) no bound is reached and the generation prompt keeps its template, but the content it receives changes (notes prefixed by the tool name, a union made in code in place of the model's rewrite), and no mechanism is identified by which that costs a gated cell. If a gated cell flips and reproduces, the change is reverted, never declared after the fact.
- `evals/fixtures/probe_corpus.json` is not recaptured here (it needs Docker and `GOOGLE_API_KEY`): its extraction prompts keep the earlier wording until the maintainer recaptures it.
- No baseline is deleted or recorded: this is a change to the system under test, not to an instrument.
- `plans/` and `docs/adr/` other than what is already committed.

## Edge cases

- First tool: the carried context is empty, the merge returns the reported context under the same rules (dedup inside the answer, bounds, the note prefixed by the tool name).
- The answer reports nothing (every field empty): the carried context comes back unchanged, apart from trimming.
- The same fact in two wordings: two items, by design (ADR 035, Consequences).
- A reported item that differs from a carried one by case or spacing only: one item, the reported wording, moved to the end.
- A tool audited twice in one thread (a resumed audit that runs the node again): its note is replaced, not duplicated.
- A redacted audit: the node already applies `with_redaction_notice` to the prompt; the merge reads no value and needs no change.

## Test scenarios

Test-first, each test red before the code. One test file per area, in `tests/unit/auditor/`, with its `support/` given and then (`test_<name>_given.py`, `test_<name>_then.py`) only where they abstract something, one-liners inlined.

- `test_attack_context.py` (new), the merge: merging into an empty context returns the reported items; union of two lists; an item differing by case and whitespace is not added twice and the reported wording is kept; a re-reported item moves to the end and survives an eviction that removes an older one; the list is cut to `MAX_LIST_ITEMS` from the front; an item over `MAX_ITEM_LENGTH` is dropped, one at the bound is kept; a blank item is skipped; a reported scalar replaces, `None` and blank keep, an over-long reported scalar keeps the carried one; one note per tool, prefixed, cut at `MAX_NOTE_LENGTH`, newlines collapsed; a reported text that already starts with the tool's prefix is not prefixed twice; a report made only of whitespace adds no note; an item with an inner newline is stored on one line; a second report of the same tool replaces its note; the notes are cut to `MAX_NOTES` from the oldest; a carried context over every bound comes back within them; merging 300 synthetic reports of distinct items, each item exactly `MAX_ITEM_LENGTH` long and each note over `MAX_NOTE_LENGTH`, keeps every list at `MAX_LIST_ITEMS`, the notes at `MAX_NOTES`, and the length of `format_attack_context(...)` under a bound computed from the constants, the `", "` separators of the lists and the newlines of the notes included.
- `test_prompts.py`: the extraction prompt shows each carried list item on its own line and the carried scalar values; it asks to repeat a confirmed item in the same words; it states the two length bounds; it no longer contains "Preserve all previous findings"; an empty context adds no section.
- `test_nodes.py` (`TestExtractAttackContext`): the node returns the carried context merged with the answer, the note carrying the tool's name; a missed call keeps the existing context.
- `test_graph.py`: on a two-tool audit, an item reported on the first tool is still in the final context when the second tool's answer omits it. The existing givens of `support/test_graph_given.py` answer every extraction with `AttackContext()`, so this needs a new given: a FakeLLM for a two-tool audit with one extraction answer per tool.
- Regenerate the golden of model inputs in the same commit (`uv run python -m tests.unit.auditor.support.test_model_inputs_golden_given`), The golden already holds an extraction case with a full context (`extraction/blocked_only_with_context`, built on `_full_context()` in `support/test_model_inputs_golden_given.py`). Change `_full_context().observations` to two notes in the new form (`"<tool>: <note>"`, one per line) so the golden pins the rendering of several notes, in the extraction prompt and in the entries that share it. The golden keys expected to move are `schema/AttackContext`, `openai_request/AttackContext`, `anthropic_request/AttackContext` (the docstring), `extraction/judged`, `extraction/blocked_only_with_context`, `audit/plain/07`, `audit/redacted/07`, `attack_context/full`, `context_section/full`, `generation/full_context` and `chain_planning/summary`; any other key in the diff is a defect.

## Living docs, in the same change

- `README.md`, the "Cross-tool learning" bullet: say that the context is merged in code and bounded, and add the link to ADR 035 beside ADR 009.
- `CHANGELOG.md`, `[Unreleased]`, under "Changed": the attack context is bounded, so the context extraction call no longer grows with the number of tools.
- `docs/glossary.md`: the `Not:` clause of **finding**, as above. The entry **attack context** already names ADR 035 beside ADR 009 in its `Defined by:`, added with the ADR, and needs no change.

## Commit

The commit that changes the system under test answers the four questions of ADR 016 in its message. Question 1: the change lands in the system under test, and its justification passes the deletion test. Questions 2 to 4 are about a label revision: no label, rubric or instrument is revised, so they do not apply. Its justification holds with no measurement in it: an answer that rewrites the whole context on every tool grows with the number of tools, so on a server with enough tools it passes any output limit.

## Verification

- While a test is red: `uv run pytest <test files> -n 0`. Then `uv run pytest tests/unit -n auto --maxprocesses 6`, `uv run ruff check .`, `uv run pyright <changed files>`.
- Closing a step: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`.
- After the last step, run by the maintainer and not by an implementation step, since they call a model: `uv run python -m evals.run_honeypot_suite` (the honeypot gate, under the baseline's model), then a measurement run of the detection suite under the settings of a holdout run, reading the largest output per model call kind and the number of items per list after ten tools. The figures of that run are exploratory (ADR 016) and confirm nothing. The judge gate is not rerun: nothing the judge reads changes.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers. Later passes, the implementation-phase fact check among them, read this section. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- No external facts to verify: the plan cites and defers no third-party API, library, CI action, version or platform behavior. Its bounds, file paths and commands are internal to the repository and were checked against the source tree.

## Implementation steps

### Step 1: The bounded merge in the domain

- **Files**: create `tests/unit/auditor/test_attack_context.py` (with `tests/unit/auditor/support/test_attack_context_given.py` and `test_attack_context_then.py` only where a helper abstracts something, such as building N synthetic reports or asserting every bound at once), create `src/mcp_auditor/domain/attack_context.py`.
- **Do**: read ADR 035 and the section "The merge" above first.
  1. Write `tests/unit/auditor/test_attack_context.py` first and run it red (`uv run pytest tests/unit/auditor/test_attack_context.py -n 0`).
  2. Create `src/mcp_auditor/domain/attack_context.py` with the constants `MAX_LIST_ITEMS = 30`, `MAX_ITEM_LENGTH = 300`, `MAX_NOTES = 15`, `MAX_NOTE_LENGTH = 400` and the public `merge_attack_context(carried: AttackContext, reported: AttackContext, tool_name: str) -> AttackContext`, followed by its private helpers (newspaper rule): one for a list merge (collapse every run of whitespace and strip, store that form, key by `casefold()`, skip blank, drop over `MAX_ITEM_LENGTH`, a re-reported item replaces the earlier occurrence and moves to the end in the reported wording, evict from the front past `MAX_LIST_ITEMS`, carried items go through the same rules), one for the notes (carried read as one note per non-blank line, each cut at `MAX_NOTE_LENGTH`; reported text whitespace-collapsed and stripped, an existing `"<tool_name>: "` prefix removed, then `"<tool_name>: <text>"`, cut at `MAX_NOTE_LENGTH`; an earlier note starting with `"<tool_name>: "` removed only when the report is not blank; oldest evicted past `MAX_NOTES`; joined with `"\n"`), one for a scalar field (reported, stripped, non-blank and at most `MAX_ITEM_LENGTH` replaces; otherwise carried, dropped to `None` if over `MAX_ITEM_LENGTH`). The module docstring states the principle that sets the bounds (nothing dropped on a server of five to ten tools, ADR 035), its assumption for the lists (about three new items per tool and per list, or fewer) and that the last item of a list is the most recently reported. `AttackContext` stays in `domain/models.py`. Do not export the function from `domain/__init__.py`. Nothing calls the function yet: the node is wired in step 2.
- **Test** (in `test_attack_context.py`):
  - empty carried, reported items: returns them (deduplicated inside the answer, note prefixed by the tool name).
  - union of two lists, carried first then the new reported items.
  - reported item differing from a carried one by case and whitespace only: one item, reported wording, at the end.
  - a re-reported item moves to the end and survives an eviction that removes an older item.
  - a list over `MAX_LIST_ITEMS` is cut from the front.
  - an item of `MAX_ITEM_LENGTH + 1` characters is dropped, one of exactly `MAX_ITEM_LENGTH` is kept; a blank item is skipped.
  - scalars: a reported value replaces (stored stripped); `None` and blank keep the carried value; an over-long reported value keeps the carried one; an over-long carried value with nothing reported becomes `None`.
  - notes: one note per tool, prefixed `"<tool>: "`, newlines collapsed, cut at `MAX_NOTE_LENGTH`; a second report of the same tool replaces its note and moves it to the end; a blank or whitespace-only report keeps the earlier note and adds none; a reported text already starting with the tool's prefix is not prefixed twice; notes cut to `MAX_NOTES` from the oldest.
  - an item with an inner newline is stored on one line.
  - a carried context over every bound (lists, item lengths, a multi-line observations block with long lines, an over-long scalar) merged with an empty report comes back within the bounds.
  - 300 synthetic reports of distinct items on distinct tools, each item exactly `MAX_ITEM_LENGTH` long and each note over `MAX_NOTE_LENGTH`: every list at `MAX_LIST_ITEMS`, the notes at `MAX_NOTES`, and `len(format_attack_context(result))` under a bound computed from the constants (lists times items times length, the `", "` separators, notes times note length with their newlines, the three scalars, and a fixed allowance for labels).
- **Verify**: `uv run pytest tests/unit/auditor/test_attack_context.py -n 0` green, then `uv run pytest tests/unit -n auto --maxprocesses 6`, `uv run pyright src/mcp_auditor/domain/attack_context.py tests/unit/auditor/test_attack_context.py` (and the support files if created), then the closing pass: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`, all green. Commit message: the merge added in the domain, not yet wired (no change to the system under test in this commit).

### Step 2: Wire the merge, rewrite the extraction prompt, update the golden and the living docs

- **Files**: modify `src/mcp_auditor/domain/models.py` (the `AttackContext` docstring only), `tests/unit/auditor/test_nodes.py` (and `support/test_nodes_given.py` / `test_nodes_then.py` if a helper abstracts something), `tests/unit/auditor/test_prompts.py` (and `support/test_prompts_given.py` if needed), `tests/unit/auditor/test_graph.py`, `tests/unit/auditor/support/test_graph_given.py` (and `test_graph_then.py` if needed), `tests/unit/auditor/support/test_model_inputs_golden_given.py`, regenerated `tests/unit/auditor/support/model_inputs_golden.json`; then `src/mcp_auditor/graph/nodes.py`, `src/mcp_auditor/graph/prompts.py`; living docs `README.md`, `CHANGELOG.md`, `docs/glossary.md`.
- **Do**: read ADR 035 and the sections "The node", "The extraction prompt", "Living docs" and "Commit" above.
  1. Tests first, each run red:
     - `test_nodes.py`, `TestExtractAttackContext`: the node's state update carries `merge_attack_context(existing, answer, tool_name)` (an item carried and absent from the answer is still there, the answer's note is prefixed by the tool's name); a missed call keeps the existing context unchanged (existing test, keep it passing).
     - `test_prompts.py`: the extraction prompt shows each carried list item on its own line and the carried scalar values under "What we already know:"; it asks to repeat a confirmed item in the same words; it states the two length bounds; it no longer contains "Preserve all previous findings"; `test_omits_existing_context_when_empty` still passes.
     - `test_graph.py`: a two-tool audit where the first tool's extraction answer reports an item and the second's omits it, the final `attack_context` still holds the item. Add to `support/test_graph_given.py` a FakeLLM given for a two-tool audit with one extraction answer per tool (the existing givens answer every extraction with `AttackContext()`).
  2. `nodes.py`: in `make_extract_attack_context`, return `merge_attack_context(existing_context, new_context, tool_report.tool.name)` in place of the answer, imported from `mcp_auditor.domain.attack_context`. The missed branch is unchanged.
  3. `prompts.py`: rewrite `_format_existing_context` so it no longer calls `format_attack_context`: "What we already know:" header, the three scalars one per line (only those set), each non-empty list under its label with one item per line, the observations under their label with one note per line, empty context renders nothing. Replace the closing "Preserve all previous findings..." instruction with plain-word instructions covering every point listed in "The extraction prompt" (report only what these results show; the answer is added to what is known by a later step so unshown items are not copied; repeat a confirmed item in the same words; one fact per item in one short sentence; in `observations` one short note about this tool; leave a field empty when the results show nothing for it; set db engine, framework or language only when these results show it, in a few words, the values above being current; state `MAX_ITEM_LENGTH` and `MAX_NOTE_LENGTH`, imported from `mcp_auditor.domain.attack_context`). Keep the "Look for" list. The word "findings" leaves the prompt. `format_attack_context`, `build_context_section` and the generation and chain prompts stay untouched.
  4. `domain/models.py`: replace the docstring of `AttackContext` with "What tool audits show about the server." (see "Approach").
  5. `support/test_model_inputs_golden_given.py`: change `_full_context().observations` to two notes in the new form (`"<tool>: <note>"`, one per line), then regenerate with `uv run python -m tests.unit.auditor.support.test_model_inputs_golden_given` and check the diff touches only the keys listed under "Test scenarios" above.
  6. Living docs: `README.md` "Cross-tool learning" bullet says the context is merged in code and bounded, link to ADR 035 beside ADR 009; `CHANGELOG.md` `[Unreleased]` "Changed": the attack context is bounded, so the context extraction call no longer grows with the number of tools; `docs/glossary.md`: remove the `Not:` clause of **finding** about the findings the context-extraction prompt asks for.
  7. Untouched: `AttackContext` apart from its docstring, `graph/state.py`, `adapters/` (Anthropic wire models included), `evals/declared_flips.json`, every baseline, `plans/`, `docs/adr/`.
- **Test**: as in 1; the golden test (`test_model_inputs_golden.py`) green after regeneration.
- **Verify**: while red, `uv run pytest <changed test files> -n 0`; then `uv run pytest tests/unit -n auto --maxprocesses 6`, `uv run pyright <changed files>`; closing pass `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`, all green. The commit message answers the four questions of ADR 016, with the justification of "Commit" above and no measurement in it. The honeypot gate and the detection measurement run are left to the maintainer (they call a model).
