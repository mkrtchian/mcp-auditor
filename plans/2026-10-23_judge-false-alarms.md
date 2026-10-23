# Judge false alarms on honeypot PASS cells

## Context

An exploratory e2e measurement on 2026-10-23, under the default model (`gpt-6-luna`, reasoning `none`, budget 10), ran four points in interleaved passes, 6 runs each, with `run_evals --ungated`: `8e48e1d` (the commit the confirmed honeypot baseline `df41eaa` was recorded at), `921ec03` (after the judge prompts were rewritten on the clauses J0 to J11 in `f263c62`, `51b444e` and `55dcd47`), `87a3c77` (HEAD), and HEAD with the fields of `Judgment` reordered. False alarms over 36 cells × 6 runs: 0, 7, 8, 6. The diff between the first two points touches only the judge prompts (`category_guidance.py`, `JUDGING_RULES` in `graph/prompts.py`, `chain_prompts.py`). The number is exploratory under ADR 016: it was produced by reading eval output and confirms nothing.

The old judge was not free of these alarms. The CI evals run `37449377894` at `02af9f5`, an ancestor of `8e48e1d` with the same prompts and servers, carries 2 false alarms over its 3 runs: `list_items × input_validation` on `limit=0`, and `search_products × error_handling` on the formed refusal behind a configuration path. Before the rewrite, then, 2 false alarms over 9 runs. After it, the 8 CI runs since `921ec03` and the exploratory passes put false alarms in most runs. The rewrite raised the rate, it did not create the mechanisms from nothing.

Three PASS cells carry the false alarms, through three mechanisms read from the judge's justifications:

- `search_products × error_handling`. A successful response that carries an internal path beside its result is judged an error that is not formed, and a formed refusal behind the same path is judged unformed by stretching rule 4 of `JUDGING_RULES` to any text in front of the message. The guidance states that a response carrying the result asked for is not an error, but only as half a sentence inside the definition of an unformed error.
- `delete_record × error_handling`. A deletion reported as done although a valid parameter withheld consent for it is judged "an operation that cannot succeed reported as a success". J2 assigns that defect to input_validation, and the operation could succeed, so the J3 line does not reach it.
- `list_items × input_validation`. The tool answers `Items: books1, books2, ... (showing N)` whatever the limit, so the response itself shows a valid limit contradicted: `limit=1`, valid under any reading, is answered with two names and an ellipsis (J2, second FAIL sentence). The same rendering hides the nearest valid value on `limit=0` and `limit=-1`, J2's PASS instance: about a third of the FAIL verdicts on this cell are on `limit=-1`, the judge writing that nothing shows the value was normalized, since two names are shown. The server departs from ADR 027, which requires that no response behind a PASS cell show a failure under the clauses. Its description ("with an optional limit") states no range either, so `limit=0` keeps a second reading, a valid value asking for no item, which an announced range removes.

`search_users × input_validation`, also labeled PASS, carries 3 false alarms in the exports, all `limit=-1` answered `No users found`. That response reads the same whether the limit was clamped or not, which J11 labels unspecified and rule 1 of `JUDGING_RULES` judges PASS: the judge case `ba6fcad989d97dfd` of `evals/fixtures/judge_cases.json` is exactly this input, labeled unspecified (J11) behind the PASS cell and kept without a repair. No response of `search_users` shows a failure, so it does not depart from ADR 027, and announcing a range would not change how `No users found` reads. These alarms are the judge not applying rule 1, recorded here and left out of this plan.

A fourth observation: in the CI history and the exploratory passes, 6 FAIL verdicts on these cells carry a justification that concludes there is no failure in the category tested. `Judgment` declares `verdict` before `justification`, so under structured output the model writes its verdict before its reasoning, and with reasoning `none` the justification is the only place it reasons.

The paired gate stayed green through all of this: each flip is replayed and not reproduced. That blindness to a regression spread over several cells is an instrument question, out of this plan (ADR 016: an instrument change and a system change do not license each other).

## Approach

Three changes, each alone in its commit and measured at that commit before the next lands (ADR 020, one change at a time):

1. **Judge guidance** (system under test). Restore, from the clauses, the boundaries the rewrite left weak: J3's distinction between an error and a result, stated first and scoped by its mechanism so that it keeps both of J3's FAIL lines reachable; rule 4 narrowed to the literal SDK prefix, as J7 writes it; an action against a valid parameter that declined it kept out of error_handling by its mechanism (the operation could succeed). No exclusion by category: J1 and J3 say the categories overlap.
2. **Justification before verdict** (system under test). Reorder the fields of `Judgment`.
3. **`list_items` answers exactly the clamped number of items and announces its range** (instrument, ADR 027 repair). Baseline reset, two recordings.

### How change 1 is measured, written before any replay

The text of change 1 and the bar below are fixed in this plan, committed alone before any replay. The text is not tuned against eval output. One paired replay checks change 1 on the working tree, before its commit, so the commit message carries the replay's result, then the three gates run at the commit.

**Replay.** A one-off script outside the repository, not committed, judges the cases below under the parent's text and under change 1's text, the same day, alternating case by case, 20 times per case per text, with the default judge (`gpt-6-luna`, reasoning `none`) through the project's own model factory and `build_judge_prompt`. Both texts live in one process: `format_judging_criteria` reads the module globals `JUDGING_RULES` and `CATEGORY_GUIDANCE` of `mcp_auditor.graph.prompts`, so the script swaps those two names before each prompt it builds (the same objects as in `run_judge_eval._judge_prompt`, `input_schema={}`, which `build_judge_prompt` does not send).

**Sources.** The single-step cases of these exports, all under `output/judge-false-alarms-2026-10-23/` (gitignored): the CI evals runs since `921ec03`, by id `37489976872` (`921ec03`), `37800145510` (`000e450`), `38717850615` (`9db0dda`), `38811606465` (`89c2c3f`), `39114281382` (`afafda1`), `39761656390` (`b99395e`), `39840319561` (`6131229`), `39860093722` (`87a3c77`), under `ci/<id>/e2e-eval-report/judged_cases.jsonl`; `local_1022.jsonl`, the local run of 2026-10-22 under the new lock, an export with no report or commit recorded; and `results/{B,C,D}{1,2}_judged_cases.jsonl`, the exploratory passes at `921ec03`, `87a3c77` and HEAD with reordered fields. Left out: `ci/37449377894` (`02af9f5`, the old judge), `results/A*` (the old judge), and the three empty folders `ci/38446008733`, `ci/38718429771`, `ci/39114553407`.

**Cases.** A case is the exact judge input of one judgment: tool name, tool description, category, payload description, arguments (serialized with sorted keys), response, error. Identical inputs are one case.

- **False-alarm set**: every case of `search_products × error_handling` and `delete_record × error_handling` judged FAIL in the sources.
- **Guard set**: every case of `get_user × error_handling` and `delete_record × input_validation`, both cells labeled FAIL, judged FAIL in the sources, plus the three error_handling cases labeled FAIL in `evals/fixtures/judge_cases.json`: `aef906ac6a361f21` and `015b054f8f42d65e` (a bare id behind the SDK prefix, J3), and `5a7557a560ec5eef` (a query on a made-up table reported as executed behind a configuration path, J3). The last one is the case the opening sentence could swallow, an operation that cannot succeed reported as a success, which no e2e export since `921ec03` holds.

`list_items` and `search_users` cases are in neither set.

**Bar.** Pooled over cases and replays:

- conclusiveness: the replay is conclusive only if the parent's text judges the false-alarm set FAIL in at least 10 % of its judgments. Below that, the cases no longer carry the false alarm under replay, and the replay is reported inconclusive: change 1 then ships or not on the three gates alone, and the commit message says so;
- false-alarm set: a FAIL rate under change 1's text at most half the parent's;
- guard set: a FAIL rate under change 1's text no lower than the parent's minus 10 points.

**Attempts.** At most two. Bar met: commit change 1 with the replay's result in its message, then run the three gates. Bar missed: change 1 is discarded uncommitted, and the miss is recorded in the commit of a second attempt or, if none is made, nowhere in the repository. A second attempt is allowed once, written from a rubric reason that is new and named in its commit, without using the first replay's per-case results to choose its wording (they may be read to diagnose, not to phrase), and checked against the same bar. A second miss leaves the guidance at its parent, and the next move is the maintainer's decision, outside this plan.

What this licenses: deciding to ship through the gates, and the exploratory statement that the observed false alarms drop on these cases. What it does not license: choosing between wordings, or any claim about the judge's precision beyond these cases, which needs data the change was not derived from.

## Change 1: judge guidance

### `src/mcp_auditor/graph/prompts.py`

Rule 4 of `JUDGING_RULES` becomes:

```
4. The framework that serves the tool is part of the server. Judge a message from the framework or from its argument validator like any other part of the response. The framework's prefix `Error executing tool <name>:` in front of an exception's text does not make that text a formed error.
```

The first two sentences are unchanged. The third names the SDK prefix literally, as J7 does ("the SDK's `Error executing tool` prefix does not clean the raw exception that follows it"), instead of "a prefix the framework adds", which a judge stretches to any text in front of a message.

### `src/mcp_auditor/domain/category_guidance.py`

`CATEGORY_GUIDANCE[AuditCategory.ERROR_HANDLING]` becomes:

```
What counts as an error_handling failure. First tell an error from a result: a response that carries the result asked for is not an error, whatever it discloses beside it. The first line below still applies to the text of an exception, a stack trace, an errno, an exit code or the raw output of a subprocess it carries, and the second line when the operation could not have succeeded.
- An error the caller receives, in the response or the error, that is not formed. An error is formed when it names the cause in terms of the parameter or the resource, with no errno, no exception class name, no exit code and no raw output of a subprocess. <rest of the current first line, unchanged from "The cause may be stated in general terms" to "or it names no cause.">
- An operation that cannot succeed is reported as a success: <rest of the current second line, unchanged>
What does NOT count:
- A formed error.
- An operation that could succeed, done against a valid parameter that declined it: an action done although a parameter withheld permission or consent for it, a write done although a parameter asked for a dry run. The operation could succeed, so the second line does not apply, and the contradicted parameter is judged under input_validation.
- An invalid input accepted with a success response. That is judged under input_validation, and is an error_handling failure only when the operation asked for could not have succeeded.
- What a response or an error discloses. That is judged under info_leakage: here, only whether an error is formed.
```

The sentence "A response that carries the result asked for is not an error." leaves the first line, where it now opens the guidance. The other categories' guidance is unchanged, input_validation included.

Justification, written to hold without the measurement:

- The opening sentence restates J3 ("An error is formed for the caller when...", "What an error leaks falls under info_leakage") and J5 ("Responses and errors alike") as the first decision the line requires: whether there is an error at all. It sets aside only what a result discloses: J3's first FAIL line still reaches whatever unformed text a result carries, the same list the first line excludes from a formed error, and its other FAIL line, an operation that cannot succeed reported as a success, still reaches a success report.
- The new "does NOT count" line follows J3's line with input_validation, which follows the cause, and J2's second sentence, a valid parameter whose meaning the tool contradicts. Its instances come from no fixture (the dry-run instance already stands in the input_validation guidance, the consent instance follows `d9a84c1`, which put it under input_validation). What is new is that error_handling now says, by the mechanism, that its second line does not reach such an action.
- The last line extends "What an error discloses" to a response, as J5 does ("Responses and errors alike").

Which clauses to bring forward was chosen by reading eval traces, which ADR 016 allows. The commit message says so and answers its four questions. It also says that the line on a contradicted parameter, which ends on "judged under input_validation", follows from J2 and J3 by the mechanism (the operation could succeed), and that it is the line `delete_record × error_handling`, the known R1 disagreement, falls under.

### Docs

`CHANGELOG.md`, `[Unreleased]`, under `### Changed`: the judge tells an error from a result before it judges whether an error is formed, no longer reads an action done against a parameter that declined it as an operation that could not succeed, and names the MCP SDK's `Error executing tool` prefix, instead of any framework prefix, as text that does not make the exception behind it a formed error.

### Tests

None of the guidance wording: its effect is LLM quality, measured by the replay and the evals (CLAUDE.md: never test LLM quality with fakes). Existing tests that must stay green: `tests/unit/test_prompts.py` (the guidance is in the prompt), `tests/unit/test_chain_prompts.py`, `tests/unit/test_fixture_contamination.py` (no honeypot literal in `src/`).

`test_no_constant_of_src_contains_a_honeypot_literal` fails on the new rule 4 as written: the three honeypot servers raise `ToolError(f"Error executing tool {name}: Invalid arguments")`, so `discriminating_literals()` holds `Error executing tool` (two words or more, a capital), and the whole-word match fires on `JUDGING_RULES` (checked against the proposed text). The literal is the MCP SDK's own prefix (`mcp/server/fastmcp/tools/base.py`), which the honeypots copy to imitate the library, not a text planted to discriminate them. `tests/unit/support/test_fixture_contamination_given.py` therefore excludes it from the honeypot literals: a module constant naming the library texts the honeypots reproduce (`{"Error executing tool"}`), subtracted in `discriminating_literals()`, with a comment giving that reason. Order: rule 4 changes first and the test is seen red, then the exclusion turns it green. The excluded-server corpus check stays green on both new texts (checked).

The exclusion is permanent, so a test guards it: every literal in the exclusion constant appears in the installed source of `mcp.server.fastmcp.tools.base`. The source is read in the given file (a helper returning `inspect.getsource` of that module), the test file asserts. The constant can then hold only text the SDK writes, and an SDK upgrade that changes the prefix fails the test, which also tells that rule 4 is stale. Rewriting the honeypots not to copy the prefix would gain nothing: FastMCP puts it in front of any exception a tool raises, so the judge sees it in honeypot runs whatever the honeypots do, and the rewrite would reset the baseline.

Quoting the Python SDK's prefix leaves other frameworks' prefixes (the npm servers of the CVE targets) to the first line's test of a formed error alone, which is what the guidance applies to any text.

### Before the run

The FAIL cells labeled in error_handling and input_validation (`get_user × error_handling`, `delete_record × input_validation`) are read against the new text before any run: the KeyError text behind the SDK prefix still is an unformed error, and a deletion against a declined parameter still is an input_validation failure. `evals/declared_flips.json` stays empty. A red gate at this commit reverts it.

### Verification

Full checks, the replay against the bar, then the three gates under the default model: `uv run python -m evals.run_judge_eval`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark`. The judge isolation fixture holds neighbours of the motifs, all labeled PASS under J3: `6b6a8cc01bf171bc` and `93fec5f1d2b1df1b` (a formed refusal followed by a path, behind the SDK prefix), `3fd29d3533ce58dd` (a deletion reported as done). Its gate guards them, and the three FAIL cases the guard set takes from it.

## Change 2: justification before verdict

### `src/mcp_auditor/domain/models.py`

```python
class Judgment(BaseModel):
    """The judge's verdict, decoupled from the identity fields the code stamps itself."""

    justification: str
    verdict: EvalVerdict
    severity: Severity
```

Pydantic emits the fields in declaration order, so the schema asks for the justification first. Both judges use `Judgment` (`graph/nodes.py`, `graph/chain_nodes.py`), on every provider, the CVE benchmark included. The Anthropic adapter binds `Judgment` natively, with no wire model to mirror. `EvalResult` keeps its order: it is never sent to a model. The judge's output length, and the cost the CVE measurement mode reports, may move.

Justification, without the measurement: a judge running with no reasoning has no other place to reason than the justification, and a verdict generated first cannot depend on it.

### Tests

`tests/unit/test_models.py`, test first: the JSON schema of `Judgment` lists `justification` before `verdict`. It pins the contract the provider sees, not an internal detail. `tests/unit/test_anthropic_structured_output.py` builds `Judgment` by keyword and stays green.

### Does the default provider follow the order

OpenAI documents that outputs follow the schema's key order for Structured Outputs, and `adapters/llm.py` binds the `openai` provider with `strict=False`, which that statement does not cover. Before any effect is attributed to change 2, a one-off check outside the repository calls the default judge on about ten collected cases with the reordered `Judgment`, reading the raw answer the binding already keeps (`include_raw=True`, `adapters/llm.py`), and counts the answers whose JSON opens with `justification`. If the default path does not follow the order, change 2 still ships for the providers that do (Anthropic documents it), and the commit message says it changes nothing on the default judge.

### Docs

`CHANGELOG.md`, `[Unreleased]`, under `### Changed`: the judge writes its justification before its verdict.

The commit message answers the four questions of ADR 016, as for change 1 (a change to the system under test).

### Verification

Full checks, the order check above, then the three gates. No cell is expected to be lost, `evals/declared_flips.json` stays empty, a red gate reverts the commit.

## Change 3: `list_items` answers exactly the clamped number of items

### `tests/honeypot_server.py`

The docstring of `list_items` becomes `"""List items in a given category, with an optional limit from 1 to 100."""`. The clamp is unchanged (`max(1, min(limit, 100))`), and the answer lists exactly the clamped number of items, with no ellipsis: `Items: books1, books2, books3 (showing 3)` for a limit of 3, `Items: books1 (showing 1)` for a limit of -1, 0 or 1, at most 100 names (bounded, so `list_items × resource_abuse` stays a PASS control). The comment above the code keeps its intent (deliberate PASS control) and says the range is announced and the answer holds exactly the clamped number of items.

The rendering is the repair: it stops contradicting a valid limit and shows the nearest valid value on an out-of-range one. The announced range removes the remaining reading of `limit=0` as a valid value asking for no item. The tool docstring is sent to the model, so the fixture fingerprint changes and the baseline resets (ADR 020). Changes 1 and 2 stay out of this commit. `search_users` is not touched (Context).

### `evals/baselines/honeypot_e2e.json`

Deleted in the same commit, recorded again twice at this commit (ADR 020, ADR 023). The honeypot gate must be green at the parent: change 2's commit, or the last kept commit if change 2 was reverted.

### Blind check, before the commit

Two assistants, Claude Opus 5.5 and Claude Fable 5.1, each label every cell of the repaired server (`honeypot_server.py`: the cells of `get_user`, `search_products` and `list_items` in `evals/ground_truth.py`), given the server with its comments and module docstring removed and its FastMCP name neutral, the clauses J0 to J11 and the list of tool and category pairs, with no tool, ground truth, log entry or baseline, as for `288c50c`. Agreement with the labels is recorded in the labeling log entry. A disagreement is settled by the maintainer and recorded.

### `docs/labeling-log.md`

A new entry, `### 2026-10-23, list_items answers exactly the clamped number of items`, in the shape of the `read_file` repair entry:

- commit, and ground truth unchanged (36 cells, 8 FAIL);
- the instrument change, with the baseline deleted and the gate state at the parent;
- why: the rendering contradicts a valid limit and hides the nearest valid value (J2, ADR 027), and the unannounced range leaves `limit=0` a second reading;
- what was known: the audits and exports the author had read (the e2e exports and the exploratory passes of 2026-10-23), and that judge verdicts prompted the reading without establishing it (ADR 027);
- how it was decided: render exactly the clamped number and announce the range the code clamps to, rather than change the clamp, which would open other readings;
- the intent of each changed branch;
- every cell of `honeypot_server.py` read on the repaired server, and the blind check;
- the cells the repair can move in both directions, stated before any run: `list_items × input_validation`, `list_items × resource_abuse` (up to 100 names now), and the other tools of the server through the attack context;
- why `search_users`, with the same limit, is not repaired: its `No users found` shows no failure, the reading is J11 under rule 1 as in `ba6fcad989d97dfd`, and an announced range would not change it. And why two open readings call for no repair there when the rendering of `list_items` does: there no response shows a failure, here the response shows a valid limit contradicted;
- what the reset does: it is recorded under the corrected judge, so cells still unstable then (possibly `search_products × error_handling`, `delete_record × error_handling`, `list_items × input_validation`) can leave the comparison (ADR 020, ADR 022);
- that a refused recording (ADR 022 or ADR 023) reverts change 3 with its recordings (ADR 027);
- what is not touched: `evals/fixtures/judge_cases.json` keeps its `list_items` cases with the old answers and description and their labels (ADR 027), `evals/fixtures/probe_corpus.json` keeps the old ones, the fault injection fixture is untouched;
- the four questions of ADR 016.

### Tests

`tests/integration/test_mcp_client.py`, test first:

- `test_list_items_clamps_limit` asserts the exact answer to a limit of 9999: `"Items: " + ", ".join(f"books{i}" for i in range(1, 101)) + " (showing 100)"`;
- a new test asserts that a limit of 0 is answered with exactly `Items: books1 (showing 1)`;
- a new test asserts that a limit of 3, inside the range, is answered with exactly `Items: books1, books2, books3 (showing 3)`.

`test_list_items_valid_category` only asserts that `book` is in the answer and stays green. The description gets no test: nothing in the code checks that a server conforms (ADR 027).

### Verification

Full checks, then the two recordings: `uv run python -m evals.run_evals --record-baseline` twice at this commit on a clean tree, then the baseline committed alone. The recording is refused unless at least one planted FAIL cell and at least one PASS cell come out stable and correct (ADR 022).

## What stays unchanged

- The input_validation, injection, info_leakage and resource_abuse guidance, rules 1, 2, 3 and 5 of `JUDGING_RULES`, the judge prompt structure, the generator prompt.
- The clauses J0 to J11 and the ground truth (ADR 027: a clause is never revised to fit a server).
- The judge isolation fixture, its labels and its baseline, the CVE fixtures and baselines.
- The gate and the replay rule: the aggregate blindness is a separate instrument change.
- `search_users` and the other tools of `subtle_server.py`, the chain honeypot server, the other tools of `honeypot_server.py`.

## Edge cases

- A success report on a made-up resource stays an error_handling FAIL: the opening sentence leaves the second line in force (`5a7557a560ec5eef` in the guard set).
- A result followed by the text of an exception, a stack trace, an errno, an exit code or a subprocess's raw output stays an error_handling FAIL: the opening sentence leaves the first line in force on it.
- A formed refusal carrying an internal path is formed: rule 4 no longer reaches the path, and the disclosure is judged under info_leakage.
- An unformed exception behind the SDK prefix stays a FAIL (`get_user × error_handling`).
- A deletion against a declined parameter stays an input_validation FAIL (`delete_record × input_validation`).
- `limit=-1` and `limit=0` on `list_items`, answered with exactly one item: out of the announced range, nearest valid value, PASS under J2.
- `limit=1` and `limit=3` on `list_items`, answered with exactly that many items: the valid parameter is honored.

## Verification, every commit

`uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`.

## Due diligence record

What the due-diligence pass concluded on 2026-10-23 about the external facts this plan cites or defers, one line each, read by the later passes (the implementation-phase fact check included). A line records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `Error executing tool {self.name}: {e}` is the MCP SDK's own prefix, raised as `ToolError` in `mcp/server/fastmcp/tools/base.py` (verified against the installed `mcp` 1.30.0 and the `v1.30.0` tag of modelcontextprotocol/python-sdk on GitHub)
- SETTLED: the default judge is `gpt-6-luna` with reasoning `none` on the `openai` provider (verified against `src/mcp_auditor/config.py`)
- SETTLED: pydantic 2.14.1 emits the `properties` of `Judgment.model_json_schema()` in declaration order (verified by generating the schema locally)
- SETTLED: on the `anthropic` provider the output keeps the schema's property order, required properties first, and all three fields of `Judgment` are required, so `justification` comes before `verdict` (verified against platform.claude.com, structured outputs, "Property ordering")
- OPEN (unverified): schema order on the default `openai` path. OpenAI documents "outputs will be produced in the same order as the ordering of keys in the schema" for Structured Outputs, but `adapters/llm.py` binds that provider with `strict=False`, which the docs do not cover
- OPEN (unverified): schema order on the `google` provider, the Gemini structured output and API reference pages fetched say nothing about property order
- SETTLED: `Claude Opus 5.5` and `Claude Fable 5.1` are current models (verified against platform.claude.com, models overview)
- SETTLED: the CI `e2e-eval-report` artifacts of the eight commits the replay draws from are present and unexpired, the earliest expiring on 2027-01-04 (verified with the GitHub Actions artifacts API)
- OPEN (deferred): the local exports of 2026-10-22 and the exploratory passes of 2026-10-23, inputs of the replay's case sets, are not in the repository: they were copied on 2026-10-23 with the downloaded CI exports to `output/judge-false-alarms-2026-10-23/` (gitignored), which the replay reads

## Implementation steps

The plan imposes three commits, each measured at its own commit before the next lands (ADR 020), so each change is its own step, even though each is small. The plan itself is committed alone before step 1. The measurements are run by the maintainer, never by the implementer: the change 1 replay on the working tree before step 1's commit, the order check before step 2's commit, the three gates after steps 1 and 2's commits, the two recordings after step 3's commit. A missed bar discards step 1 uncommitted, a red gate reverts the step's commit, before the next step starts. The implementer does not commit.

Checks that close every step: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all with no file argument. Short loop while working: `uv run pytest tests/unit -n auto --maxprocesses 4` and `uv run pyright <changed files>`.

### Step 1: judge guidance (change 1)

**Files**
- `tests/unit/test_fixture_contamination.py` (modify)
- `tests/unit/support/test_fixture_contamination_given.py` (modify)
- `src/mcp_auditor/graph/prompts.py` (modify, rule 4 of `JUDGING_RULES`)
- `src/mcp_auditor/domain/category_guidance.py` (modify, `CATEGORY_GUIDANCE[AuditCategory.ERROR_HANDLING]`)
- `CHANGELOG.md` (modify)

**Do**, in this order:
1. Replace rule 4 of `JUDGING_RULES` with the text of "Change 1, `src/mcp_auditor/graph/prompts.py`" word for word. Run `uv run pytest tests/unit/test_fixture_contamination.py` and confirm `test_no_constant_of_src_contains_a_honeypot_literal` is red on `Error executing tool`.
2. In `tests/unit/test_fixture_contamination.py`, class `TestShippedConstantsNameNoHoneypotLiteral`, add the guard test first: every literal of the new exclusion constant appears in the SDK source the given file returns (a helper in `test_fixture_contamination_given.py` returning `inspect.getsource(mcp.server.fastmcp.tools.base)`). Add a second assertion that `"Error executing tool"` is not in `given.discriminating_literals()`. Run it red (the constant does not exist yet).
3. In `tests/unit/support/test_fixture_contamination_given.py`, add the module constant (for example `SDK_TEXTS = {"Error executing tool"}`) with a one-line comment giving the reason: the MCP SDK's own prefix, which FastMCP puts in front of any exception a tool raises and the honeypots copy to imitate the library, not a text planted to discriminate them. Subtract it in `discriminating_literals()`. All contamination tests green, the excluded-server corpus check included.
4. Replace `CATEGORY_GUIDANCE[AuditCategory.ERROR_HANDLING]` with the text of "Change 1, `src/mcp_auditor/domain/category_guidance.py`": the new opening paragraph, the first line with the sentence "A response that carries the result asked for is not an error." removed and the rest kept verbatim from "An error is formed when..." to "or it names no cause.", the second line verbatim, then the four "does NOT count" lines (the contradicted-parameter line new, the info_leakage line now "What a response or an error discloses... here, only whether an error is formed."). No other category's guidance changes.
5. `CHANGELOG.md`, `[Unreleased]`, `### Changed` (the first `### Changed` under `[Unreleased]`, line 27): one bullet with the wording of "Change 1, Docs".

**Test**
- Guard test: each literal of the exclusion constant is a substring of the installed `mcp.server.fastmcp.tools.base` source (`Error executing tool` is, from `f"Error executing tool {self.name}: {e}"`).
- `discriminating_literals()` no longer contains `Error executing tool`, and still contains `{"Invalid category", "Alice"}` (existing test).
- `test_no_constant_of_src_contains_a_honeypot_literal`: red after step 1 of Do, green after step 3.
- Must stay green unchanged: `tests/unit/test_prompts.py`, `tests/unit/test_chain_prompts.py`, the rest of `tests/unit/test_fixture_contamination.py`.

**Verify**
- The four closing checks above, all green.
- Report, for the commit message the orchestrator writes: the choice of clauses brought forward came from reading eval traces (ADR 016 allows it), the four questions of ADR 016 answered, the contradicted-parameter line follows from J2 and J3 by the mechanism (the operation could succeed) and is the line `delete_record × error_handling` (R1) falls under, and `evals/declared_flips.json` stays empty.
- Before the commit, maintainer only, on the working tree once the checks are green: the replay against the bar ("How change 1 is measured"). Bar missed: the change is discarded uncommitted (a second attempt follows "Attempts"). Bar met or replay inconclusive: the commit message carries the replay's result.
- After the commit, maintainer only: `uv run python -m evals.run_judge_eval`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark`. A gate red: revert.

### Step 2: justification before verdict (change 2)

**Files**
- `tests/unit/test_models.py` (modify)
- `src/mcp_auditor/domain/models.py` (modify, `Judgment`)
- `CHANGELOG.md` (modify)

**Do**
1. Test first in `tests/unit/test_models.py`: a new class (for example `TestJudgmentSchema`) with one test asserting that `list(Judgment.model_json_schema()["properties"])` puts `justification` before `verdict`. Import `Judgment` from `mcp_auditor.domain.models`. Run it red.
2. Reorder the fields of `Judgment` to `justification`, `verdict`, `severity`, as in "Change 2". `EvalResult` keeps its order.
3. `CHANGELOG.md`, `[Unreleased]`, `### Changed`: one bullet, the judge writes its justification before its verdict.

**Test**
- `Judgment`'s JSON schema lists `justification` before `verdict`.
- `tests/unit/test_anthropic_structured_output.py` (builds `Judgment` by keyword) and every judge node test stay green unchanged.

**Verify**
- The four closing checks above, all green.
- Before the commit, maintainer only: the order check ("Does the default provider follow the order"), a one-off script outside the repository on about ten cases from `output/judge-false-alarms-2026-10-23/`, prompts built by `build_judge_prompt`, the raw answer read from the existing `include_raw=True` binding. If the default path does not follow the order, the commit message says the change makes no difference on the default judge and ships for the providers that do. The commit message answers the four questions of ADR 016.
- After the commit, maintainer only: the three gates. A red gate reverts. `evals/declared_flips.json` stays empty.

### Step 3: `list_items` answers exactly the clamped number of items (change 3)

**Files**
- `tests/integration/test_mcp_client.py` (modify)
- `tests/honeypot_server.py` (modify, `list_items`)
- `evals/baselines/honeypot_e2e.json` (delete)
- `docs/labeling-log.md` (modify, new entry at the end of `## Entries`)

**Do**
1. Test first in `tests/integration/test_mcp_client.py`: `test_list_items_clamps_limit` asserts the exact answer to `limit=9999`, `"Items: " + ", ".join(f"books{i}" for i in range(1, 101)) + " (showing 100)"`. Two new tests in `TestErrorPaths` assert that `limit=0` is answered with exactly `Items: books1 (showing 1)` and `limit=3` with exactly `Items: books1, books2, books3 (showing 3)`. Run them red with `uv run pytest tests/integration/test_mcp_client.py`.
2. `tests/honeypot_server.py`, `list_items`: docstring `"""List items in a given category, with an optional limit from 1 to 100."""`, clamp unchanged (`max(1, min(limit, 100))`), answer `Items: {category}1, ..., {category}N (showing N)` with exactly N = clamped names and no ellipsis. The comment keeps "deliberate PASS control" and says the range is announced and the answer holds exactly the clamped number of items (at most 100, bounded).
3. Delete `evals/baselines/honeypot_e2e.json` (ADR 020 reset). Do not touch `tests/subtle_server.py`, `evals/fixtures/judge_cases.json`, `evals/fixtures/probe_corpus.json`, `evals/fixtures/fault_injection_baseline.json` or `evals/declared_flips.json`.
4. Blind check before the commit, as for `288c50c` (see the "Blind check" paragraph of the `2026-10-06, fixtures aligned on the judge-case clauses` entry): prepare in a temporary directory outside the repository the repaired `honeypot_server.py` with its tool docstrings kept, comments and module docstring removed and FastMCP name neutral, the clauses J0 to J11 (from `docs/labeling-log.md`, `## Rubric`, `### Judge cases`), and the list of the cells of `get_user`, `search_products` and `list_items` from `evals/ground_truth.py`. Two labelers, Claude Opus 5.5 and Claude Fable 5.1, each label every cell with no tool and no ground truth, log entry or baseline. If the implementer cannot launch both, stop after preparing the inputs and report their path, so the orchestrator runs them. Report agreement with the ground truth, and any disagreement for the maintainer to settle.
5. `docs/labeling-log.md`: new entry `### 2026-10-23, list_items answers exactly the clamped number of items`, in the shape of the `2026-10-06, read_file of the chain honeypot` entry, with every item listed in "Change 3, `docs/labeling-log.md`", the gate state at the parent included (green required, the maintainer confirms the last run at the parent). No CHANGELOG entry (a fixture, not user-facing).

**Test**
- `limit=9999` on `list_items`: exactly 100 names, `showing 100`.
- `limit=0` on `list_items`: exactly `Items: books1 (showing 1)`.
- `limit=3` on `list_items`: exactly `Items: books1, books2, books3 (showing 3)`.
- Existing integration tests stay green: `test_list_items_valid_category`, `test_list_items_rejects_invalid_category`, `test_list_items_refuses_a_non_integer_limit`, `test_list_items_publishes_a_plain_integer_limit`. `tests/unit/test_fixture_contamination.py` stays green on the new docstring.

**Verify**
- The four closing checks above, all green.
- After the commit, maintainer only: `uv run python -m evals.run_evals --record-baseline` twice at this commit on a clean tree (exploratory, then confirmed), then `evals/baselines/honeypot_e2e.json` committed alone. The recording is refused unless at least one planted FAIL cell and one PASS cell come out stable and correct (ADR 022). A refused recording reverts change 3 with its recordings.
