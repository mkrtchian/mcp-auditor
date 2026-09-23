# Prompt decontamination

## Context

The shipped prompts were tuned in March 2026 by reading the output of the honeypot evals and of the judge isolation eval, and some of what that tuning wrote names the fixtures it was read on. The generator prompt tells the model to use `"Alice"` as first choice for name searches (`src/mcp_auditor/graph/prompts.py:51`), which is the PII record planted in all three honeypot servers. The judge's category guidance quotes `"Invalid category"` (`src/mcp_auditor/domain/category_guidance.py:31`, the exact error of `list_items` in `tests/honeypot_server.py:39`), `"user_id must be positive"` (`category_guidance.py:21`, the start of the planted leak at `honeypot_server.py:21`) and a clamping example read off `list_items`' `"showing 1"` output (`category_guidance.py:25`).

Those are the half a string test can catch. The same commits, and two others, also wrote technique-level lines that map one to one onto the honeypots' tools without copying a string. The judge's resource_abuse guidance lists "delete one record, look up one user, execute one query that returns a fixed number of rows" (`category_guidance.py:42`), which are `delete_record`, `get_user` and `execute_query` (whose response always reads `Results: 3 rows`). Rule 3 of the judge prompt names "execute queries, search text, or delete records" (`prompts.py:172`), which are `execute_query`, `search_users` and `delete_record`. The chain planning prompt spells out the exact walk of `tests/chain_honeypot_server.py`, "enumerate entities, inspect their metadata, then use discovered field names or IDs" (`src/mcp_auditor/graph/chain_prompts.py:55-58`). The generator prompt tells the model to "ALWAYS test zero first" and to "use negative IDs" for error-path leakage, the two inputs on which `get_user` fails.

ADR 016 sets the rule these lines are held to: a change to the system under test found by reading eval output may ship only if its written justification holds once every mention of the measurement is deleted, the deletion test. ADR 014 covers the half a test can catch with a test that today checks one prompt constant against three CVE fixture names, and ADR 016 records that extending it "beyond the one prompt line it covers is work this decision does not do". This plan does that work and applies the deletion test to every `src/` hunk of the five commits that were written from eval output.

It lands before the first baseline is recorded. A baseline recorded now would freeze these lines, their removal would flip the cells they fit, and the gate would stay red with no legal exit, since re-recording on a red run is forbidden and the flip is exactly the change meant to happen.

## Approach

Two commits to the system under test, then one exploratory measurement that is not committed.

1. `fix(prompts)`, the literals. A new unit test derives the discriminating string literals of the three honeypot servers by AST and asserts that no string constant of `src/` contains one. It is red on the current tree (it finds `Alice`, `Invalid category` and `user_id must be positive`). The same commit removes those three literals and the `"showing 1"` example, which the test cannot see because its shared part is a number, and rewrites each line generically.
2. `fix(prompts)`, the techniques. Every other hunk of the audited commits gets the verdict recorded in the table below, applied as written. No test can catch these (ADR 014, Consequences: "The test catches a copied fixture name, not a copied technique"), so the verdicts are written here, before any measurement, and the commit applies them without reading eval output.
3. Exploratory measurement: one `uv run python -m evals.run_evals --ungated` at CI conditions (3 runs, budget 10) and one `uv run python -m evals.run_judge_eval`, after both commits. The numbers are reported to the maintainer at the end of the implementation. They confirm nothing and nothing in this plan reacts to them (see "Bars written before measurement").

Commit 2 also carries the `CHANGELOG.md` and `CONTRIBUTING.md` updates.

### Commits audited

Every hunk under `src/` of these commits, as they survive in the current tree:

- `4a24b8e` feat: improve judge prompt with category-specific guidance (judge F1 0.71 → 0.93 in its message).
- `d2b6a98` feat(evals): refine judge prompt and add edge-case eval fixtures.
- `53e525a` feat(evals): improve generator and judge prompts from e2e eval analysis.
- `26f49bc` feat(evals): tune generator and judge to reach recall threshold (recall 0.71 → 1.00 in its message).
- `fa52ad8` fix(evals): include chain verdicts in aggregation, fix ground truth, improve chain planning. Only its `chain_prompts.py` hunk, the rest is instrument code and ground truth.

Not audited, with the reason:

- `f8aa87f`, `85a6c52`, `2730242`, `f97506e` (non-destructive payloads and proof of impact). Their justification is written in ADR 013 and ADR 014, independent of any measurement, and ADR 014's test already covers their fixture names.
- The judge's category guidance as a whole, structurally. `4a24b8e` wrote it against `evals/fixtures/judge_cases.json`, whose cases were written by hand from the honeypots' outputs, so the rubric is fitted to that fixture beyond any line-level verdict. That is fixed by rebuilding the judge fixture from exported cases, a separate piece of work, and no line here tries to anticipate it.

## Verdicts, per hunk

Each row: the current text (abridged), its origin, the verdict, and the justification that has to hold with the measurement deleted. "Keep" means the text stays byte-identical. Replacement texts are normative: the implementer uses them as written (wording of surrounding punctuation may adapt to the sentence).

### Generator, `build_attack_generation_prompt` (`src/mcp_auditor/graph/prompts.py:49-59`)

| # | Current text | Origin | Verdict |
|---|---|---|---|
| G1 | info_leakage: probe BOTH success and error responses, "You MUST include both kinds of test", "If you have 2+ test cases for info_leakage, one MUST be error-path and one MUST be response-path" | `53e525a`, hardened `26f49bc` | Keep. Leakage surfaces in success responses (PII, internal fields) and in error responses (paths, traces), and a probe of one path cannot see the other. The requirement follows from where leakage lives, not from which cells the honeypots label. |
| G2 | error-path: "use negative IDs, boundary values (0, -1), or invalid inputs" | `26f49bc` (was "non-existent IDs, boundary values, or invalid inputs") | Rewrite to "use non-existent IDs, boundary values, or invalid inputs". The switch to negative IDs and the literal `(0, -1)` were chosen after reading that `get_user` leaks on a negative id. Non-existent and boundary identifiers are the generic triggers of a verbose error, and negative values stay covered by "boundary values". |
| G3 | response-path: `use "Alice" as first choice for name searches` | `26f49bc` (was "common first names (Alice, Bob, John)" in `53e525a`, which named both planted records) | Rewrite to "use a common first name for name searches". Commit 1. Querying with a value likely to match real data is the technique, and it holds. The name is the fixture's. |
| G4 | response-path: "small IDs (1, 2, 3), common categories" | `53e525a` | Keep. Sequential identifiers start at 1 in most stores, and a common category is the value a listing tool is most likely to accept. Neither names a fixture value beyond what any server would hold. |
| G5 | input_validation: "ALWAYS test zero first (0 is the #1 boundary error), then negative numbers, then extremely large values. If you only have one test case, use zero." | `53e525a` listed zero, `26f49bc` made it first and exclusive | Rewrite to "For integer fields: zero, negative numbers and extremely large values, the classic boundary values." Zero belongs in any boundary-value list. Its priority, the "#1" claim and the one-case rule have no justification but the recall they bought on `get_user`, whose unknown-id `KeyError` fires on 0. |
| G6 | input_validation: "Do NOT send wrong types ... the framework's schema validation catches type mismatches" | `53e525a` | Keep. MCP server SDKs validate arguments against the declared input schema before the tool runs, so a wrong-typed payload tests the SDK, not the tool. |
| G7 | injection, error_handling, resource_abuse lines, closing "Always send arguments that conform to the schema's type constraints" | `53e525a` | Keep. Generic category definitions naming classes of payload, no instance of a fixture. |

### Judge guidance, `CATEGORY_GUIDANCE` (`src/mcp_auditor/domain/category_guidance.py`)

| # | Current text | Origin | Verdict |
|---|---|---|---|
| J0 | `:19` "without rejecting OR normalizing it (e.g., negative IDs used as-is, wrong types, out-of-range values processed verbatim)" | `d2b6a98` (was "without rejecting it (e.g., negative IDs, wrong types, out-of-range values)" in `4a24b8e`) | Keep. It states the J3 principle on the FAIL side: an out-of-range value is a failure only when it reaches the tool's logic unchanged. The examples are classes of input, no fixture value. |
| J1 | `:21` An error that merely echoes back the raw input value (e.g., error: "0", error: "-1") ... Compare: "0" (raw exception) vs. "user_id must be positive" (proper validation). | `53e525a` | Rewrite to "- An error whose message is only the submitted value, with no descriptive text, as a raw KeyError from a lookup produces. That is an unhandled exception, not input validation." Commit 1. "Message", not "whole text": SDKs wrap a tool exception (FastMCP renders `Error executing tool <name>: <message>`), so the error the auditor receives is never the bare value. The principle is how Python renders a `KeyError`, true of any server. The examples are `get_user`'s outputs and error string. |
| J2 | `:24` a tool whose purpose is to accept and forward text is NOT failing input_validation by accepting that text, plus "Example: a SQL execution tool accepting an empty string query and returning results is NOT an input_validation failure ..." | `d2b6a98` (principle), `53e525a` (example) | Keep the first sentence, delete the "Example: ..." sentence. The principle is the category boundary between input_validation and a tool's core function, and holds. The example restates `execute_query`'s observed behavior. |
| J3 | `:25` clamping is valid input handling, plus "Example: if limit=-1 and the response shows "showing 1", the tool clamped the negative value to 1 ..." | `d2b6a98` (principle), `53e525a` (example) | Keep the principle, delete the "Example: ..." sentence. Commit 1. Normalizing an out-of-range value before it reaches downstream logic is valid handling on any server. The example is `list_items`' output. |
| J4 | `:26` a text-search tool treating input as a literal search term ... returning "no results" is NOT an input_validation failure | `d2b6a98` | Rewrite "returning \"no results\"" to "returning an empty result". Treating input as data is the definition of not executing it, and holds. The quoted phrase mirrors `search_users`' `No users found`. |
| J5 | `:31` Clean, structured error messages (e.g., "Invalid category", "ID must be between 1 and 1000") | `4a24b8e` | Rewrite the first example to `"Unsupported format: expected json or csv"`, keep the second. Commit 1. A clean error names the constraint the input broke. `"Invalid category"` is `list_items`' error, word for word. The second example matches no fixture. |
| J6 | `:32` a success response carrying internal paths is info_leakage, not error_handling | `53e525a` | Keep. Category boundary: no error occurred, so there was nothing to handle. |
| J7 | `:34` a pass-through tool is not required to pre-validate syntax | `d2b6a98` | Keep. Same core-function boundary as J2, stated for error_handling. |
| J8 | `:35` edge-case input answered with success is not error_handling | `d2b6a98` | Keep. Category boundary between input_validation and error_handling. |
| J9 | `:37` "e.g., returning millions of rows, loading unbounded data into memory", `:38` "No size caps on operations that could grow without limit", `:43` "The absence of rate limiting alone is NOT resource_abuse ..." | `d2b6a98` | Keep. Definition of unbounded consumption, no instance of a fixture. |
| J10 | `:42` "Single-item operations (delete one record, look up one user, execute one query that returns a fixed number of rows). These are inherently bounded ..." | `d2b6a98` | Rewrite to "- Operations bounded by construction, which act on or return a fixed amount of data whatever the input. These are inherently bounded and do NOT require rate limiting to pass." The principle holds. The three examples are `delete_record`, `get_user` and `execute_query`. |

The info_leakage and injection definitions (`:7-17`) and the documentation-path example `/help/api-guide` come from `4a24b8e` or later ADR work, name no fixture, and are kept. So are the other surviving `4a24b8e` lines not listed above (`:20`, `:23`, `:28-29`, `:33`, `:40-41`): category definitions and boundaries naming classes of behavior, no fixture instance, and their structural fit to the judge fixture is the separate work named under "Not audited".

### Judge prompt, `build_judge_prompt` (`src/mcp_auditor/graph/prompts.py:172`)

| # | Current text | Origin | Verdict |
|---|---|---|---|
| R3 | "3. Consider the tool's stated purpose. A tool designed to execute queries, search text, or delete records is expected to do those things. Performing its core function is not a vulnerability." | `d2b6a98` | Rewrite the middle sentence to "A tool is expected to do what its description says it does." The principle holds. The three examples are `execute_query`, `search_users` and `delete_record`. |

Rules 1 and 2 (`4a24b8e`, `d2b6a98`) are the category isolation and the evidence rule, name no fixture, and are kept. So is the task sentence's "based on the ACTUAL BEHAVIOR observed in this test result" (`d2b6a98`), the same evidence rule.

### Chain planning, `build_chain_planning_prompt` (`src/mcp_auditor/graph/chain_prompts.py:51-58`)

| # | Current text | Origin | Verdict |
|---|---|---|---|
| C1 | "Only plan chains for info_leakage and injection. Other categories (input_validation, error_handling, resource_abuse) are thoroughly covered by single-step tests." | `fa52ad8` | Keep the restriction, rewrite the reason to "Other categories (input_validation, error_handling, resource_abuse) show in the response to a single request, which the single-step tests already send." The restriction holds on the nature of those categories: a malformed input, an unhandled error or an unbounded call is observable in one response, so a chain adds budget and no reach. "Thoroughly covered" was a claim about the eval, and goes. This is the weakest keep of the table: it was committed together with a ground truth change on the chain honeypot, and a reviewer may overrule it. |
| C2 | "For info_leakage chains specifically: enumerate entities, inspect their metadata, then use discovered field names or IDs to extract sensitive data through different actions or parameters." | `fa52ad8` | Delete. It is the walk of `project_manager` and `user_directory` in `tests/chain_honeypot_server.py` (list, details, `get_field` on `auth_token`). The generic recipe survives in the paragraph above it: "probing to discover internal state, then using that knowledge to escalate". |

## Files to modify

### `tests/unit/test_fixture_contamination.py` (new, commit 1)

One test class, `TestShippedConstantsNameNoHoneypotLiteral`:

- `test_the_honeypots_plant_discriminating_literals`: the extraction finds `"Invalid category"` and `"Alice"` among the discriminating literals. Guards against a vacuous pass if a server moves or the rule drifts.
- `test_no_constant_of_src_contains_a_honeypot_literal`: takes `given.shipped_constants()` and `given.discriminating_literals()`, then calls `then.no_constant_contains_any_of(constants, literals)`. The test body reads as the spec, the matching rule lives in the `then` module since it is the assertion's criterion (CLAUDE.md, Given/When/Then: setup in `given.py`, assertions in `then.py`).

### `tests/unit/support/test_fixture_contamination_given.py` (new, commit 1)

- `HONEYPOT_SERVERS`: the three paths, `tests/honeypot_server.py`, `tests/subtle_server.py`, `tests/chain_honeypot_server.py`, resolved from `Path(__file__).resolve()` the way `tests/integration/test_mcp_client.py:6` does, one level deeper: from `tests/unit/support/`, `parents[2]` is `tests/` and `parents[3]` is the repo root holding `src/`.
- `discriminating_literals() -> set[str]`: every `ast.Constant` of type `str` in the three servers (f-string fragments are `Constant` nodes and come along), plus every function name, stripped. A literal is discriminating when it is at least 3 characters long and either has two or more words or contains an uppercase letter, a digit, or one of `_ @ . / -`. Single lowercase words (`name`, `role`, `database`) are dropped by the rule, not by a list: they are vocabulary, not fixture naming.
- `shipped_constants() -> list[tuple[Path, str]]`: every `str` constant of every `*.py` under `src/`, docstrings included.

### `tests/unit/support/test_fixture_contamination_then.py` (new, commit 1)

- `no_constant_contains_any_of(constants, literals)`: collects every leak and asserts the list is empty. The assertion message lists each leak as `path: literal (matched text)`, so a failure reads without a debugger. A leak is a `Leak`, a small frozen dataclass `(path, literal, matched)`. A constant leaks a literal when either the literal appears in it as a whole, at word boundaries (`re.search(rf"(?<!\w){re.escape(literal)}(?!\w)", constant)`, so `ExecutionRecord` does not match `Record`), or the two share a run of three consecutive words, compared lowercase on `[a-z0-9_]+` tokens. The second form catches a fragment lifted out of a longer literal, `user_id must be positive` out of `user_id must be positive — see /opt/...`.

No allowlist is created: a prototype of the rule run during planning on the current tree reports exactly the three real leaks and no false positive, so after commit 1 it should report none. If a future collision is a false positive, the failure message is the prompt to add an allowlist then, one entry per line with its justification.

The existing `test_draws_its_examples_from_the_threat_landscape_not_from_the_fixtures` in `tests/unit/test_prompts.py:122` stays: it covers the CVE fixtures' names, which are not in the Python servers.

### `src/mcp_auditor/graph/prompts.py`

- Commit 1: G3.
- Commit 2: G2, G5, R3.

### `src/mcp_auditor/domain/category_guidance.py`

- Commit 1: J1, J3, J5.
- Commit 2: J2, J4, J10. J0 is a keep.

### `src/mcp_auditor/graph/chain_prompts.py` (commit 2)

- C1, C2. The text lives in a triple-quoted f-string whose lines end with a `\` continuation, keep that form. Deleting C2 also deletes the blank line before it, so a single blank line still separates the C1 paragraph from `{NON_DESTRUCTIVE_CONSTRAINT}`.

### `CHANGELOG.md` (commit 2)

Under `[Unreleased]`, `### Changed`, one bullet: "The generator, judge and chain planning prompts no longer name the values, errors or tools of this repo's test servers. A few lines written while tuning against those servers asked for them by name or described their tools one by one, and they now state the general rule instead. A unit test fails when a shipped string contains a discriminating literal of the three test servers. Audits of other servers see prompts that no longer steer toward this repo's fixtures, and the repo's own eval numbers are expected to move."

### `CONTRIBUTING.md` (commit 2)

In the list of contributions (line 86), after the eval-improvements bullet, one sentence: "A shipped prompt never names a honeypot's values, errors or tools: `tests/unit/test_fixture_contamination.py` checks the literals, and a rule copied as a technique rather than a string is caught only in review."

## What stays unchanged

- The three honeypot servers and `evals/ground_truth.py`: fixtures, never edited to fit the product.
- `evals/fixtures/judge_cases.json`, including its cases built on `"Invalid category"` and `"showing 1"` outputs. They are fixture data (what the server returns), which is the legitimate place for those strings. Its rebuild is separate work.
- `F1_THRESHOLD` in `evals/run_judge_eval.py`, `FLOORS` and `LEGACY_THRESHOLDS` in `evals/gate.py`.
- `NON_DESTRUCTIVE_CONSTRAINT` and the ADR 013 guard.
- No baseline is recorded, `evals/baselines/` is not touched.
- `README.md`: it publishes no eval number, and no sentence of it claims or depends on these prompt lines.
- `docs/adr/` and earlier plans.

## Bars written before measurement

Written here so the exploratory run cannot shape them.

- The numbers of step 3 are exploratory under ADR 016: they are reported and confirm nothing.
- A drop in e2e recall, precision or judge F1 is the expected effect of removing a fit, not a defect of this change. It is never corrected by reintroducing a literal or a removed technique line, nor by a new line written from reading that run's traces. Any later prompt change has to pass the deletion test on its own.
- If recall falls under its floor of 0.50 (`FLOORS` in `evals/gate.py`), a baseline recording will be refused (`evals/recording.py` checks the floors). Lowering a floor requires a new ADR, "Lowering the e2e recall floor", which this plan does not write. The same holds for precision and distribution coverage, whose floors are also 0.50.
- If the judge F1 falls under 0.90, the judge eval check fails on pull requests that touch `src/**` until the judge's gate is replaced by a non-regression gate on a rebuilt fixture. That is accepted: the threshold is an absolute bar fitted on the same hand-written cases, and restoring it by restoring the fitted lines is exactly what ADR 016 forbids.

## Commit messages

Each of the two commits answers ADR 016's four questions, as `CLAUDE.md` asks for a change to the system under test:

1. Artifact: the system under test (shipped prompts). Deletion test: pass, justification per line in `plans/2026-09-23_prompt-decontamination.md`, no mention of a measurement.
2. to 4. Not applicable: no label changes.

And they name the lines removed, since the public messages of `53e525a` and `26f49bc` already cite them. They carry no eval number.

## Edge cases

- An f-string in `src/` whose constant fragments are split around an interpolation: each fragment is checked alone, so a literal split across an interpolation escapes. Accepted, same class as a copied technique.
- A literal that is a number or contains one only in its distinguishing part (`showing 1`, `Results: 3 rows`): the whole-literal check still applies, the three-word check ignores nothing, but a lone number in `src/` is never discriminating. Handled by hand in the verdicts table (J3).
- Server docstrings are literals too: a sentence of a server docstring copied into `src/` is a leak, which is the intended behavior.
- The honeypot module docstring of `tests/honeypot_server.py` shares vocabulary with eval code, but `evals/` is not scanned, only `src/`.

## Test scenarios

- On the tree before commit 1: `test_no_constant_of_src_contains_a_honeypot_literal` fails and lists `prompts.py` with `Alice`, and `category_guidance.py` with `Invalid category` and `user_id must be positive`.
- After commit 1: both tests pass.
- After commit 2: both tests pass, and the rest of the suite is green. `tests/unit/test_prompts.py` and `tests/unit/test_chain_prompts.py` assert no removed text today (checked during planning), so no existing test needs editing. If one does, it asserted a fitted line and is updated to the new text.

## Verification

```bash
uv run pytest tests/unit/test_fixture_contamination.py   # red before the edits of commit 1, green after
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
grep -rn "Alice\|Invalid category\|must be positive\|showing 1\|delete one record\|delete records\|enumerate entities\|no results\|#1 boundary\|thoroughly covered" src/   # no output
```

Then, after both commits, the exploratory measurement (needs `GOOGLE_API_KEY`):

```bash
uv run python -m evals.run_evals --ungated --runs 3 --budget 10
uv run python -m evals.run_judge_eval
```

Report recall, precision, consistency, distribution coverage, per-server figures and judge F1 to the maintainer, labelled exploratory, next to the April 2026 figures of `output/eval_report.json` if that file is present. Nothing is committed from this run.

## Due diligence record

What the plan-diligence pass concluded about the external facts this plan cites or defers, read by the implementation-phase fact check. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, on 2026-09-23, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: the Python MCP SDK validates tool arguments before the tool runs (G6): `mcp` 1.26.0 as locked, FastMCP through its pydantic argument model and the low-level `Server.call_tool(validate_input=True)` default through `jsonschema.validate` (verified against the installed package source).
- SETTLED: the TypeScript SDK's `McpServer` validates arguments against `inputSchema` before the callback and answers `InvalidParams` "Input validation error" (verified against `modelcontextprotocol/typescript-sdk` branch `v1.x`, `src/server/mcp.ts`). A server built on the TypeScript low-level `Server` alone gets no such check.
- SETTLED: `str(KeyError(0))` is `0` (verified in the project's Python 3.13), the rendering J1 relies on. A string key renders quoted (`'abc'`), and FastMCP wraps any tool exception as `Error executing tool <name>: <message>` (installed `mcp/server/fastmcp/tools/base.py`).

## Implementation steps

Two steps, one per commit of the Approach: the plan requires the literals and the techniques to land as two separate commits to the system under test, each answering ADR 016's questions on its own. The exploratory measurement of Approach step 3 is not a step, since nothing is committed from it (see "After step 2").

### Step 1: contamination test and the literal fixes

- **Files**:
  - `tests/unit/support/test_fixture_contamination_given.py` (new)
  - `tests/unit/support/test_fixture_contamination_then.py` (new)
  - `tests/unit/test_fixture_contamination.py` (new)
  - `src/mcp_auditor/graph/prompts.py`
  - `src/mcp_auditor/domain/category_guidance.py`
- **Do**:
  1. Write the `given` module as specified under "Files to modify": `HONEYPOT_SERVERS` (three paths resolved from `Path(__file__).resolve()`, `parents[2]` is `tests/`, `parents[3]` is the repo root), `discriminating_literals() -> set[str]` (every `str` `ast.Constant` of the three servers plus every function name, stripped, kept when length >= 3 and either two or more words or containing an uppercase letter, a digit, or one of `_ @ . / -`), `shipped_constants() -> list[tuple[Path, str]]` (every `str` constant of every `*.py` under `src/`, docstrings included).
  2. Write the `then` module: a frozen dataclass `Leak(path, literal, matched)` and `no_constant_contains_any_of(constants, literals)`, which collects every leak and asserts the list is empty, with a message listing each leak as `path: literal (matched text)`. A constant leaks a literal on a whole-literal match at word boundaries (`re.search(rf"(?<!\w){re.escape(literal)}(?!\w)", constant)`) or on a shared run of three consecutive lowercase `[a-z0-9_]+` tokens.
  3. Write the test file, class `TestShippedConstantsNameNoHoneypotLiteral`, with `test_the_honeypots_plant_discriminating_literals` and `test_no_constant_of_src_contains_a_honeypot_literal`, importing the support modules the way existing tests import `tests.unit.support.*_given` / `*_then`.
  4. Run the new test and confirm the second test is red, listing `prompts.py` with `Alice` and `category_guidance.py` with `Invalid category` and `user_id must be positive`. If it reports any other leak, stop and report it rather than adding an allowlist (the plan expects none).
  5. Apply the commit-1 verdicts, using the normative replacement texts of the tables verbatim: G3 in `prompts.py`, J1, J3 (delete the "Example: ..." sentence only) and J5 in `category_guidance.py`.
  6. Do not touch the honeypot servers, `evals/`, or any line assigned to step 2.
- **Test**:
  - `test_the_honeypots_plant_discriminating_literals`: `"Invalid category"` and `"Alice"` are in `discriminating_literals()`.
  - `test_no_constant_of_src_contains_a_honeypot_literal`: red before the `src/` edits with exactly the three leaks above, green after.
- **Verify**:
  - `uv run pytest tests/unit/test_fixture_contamination.py` red before step 5, green after.
  - `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: all clean.
  - `grep -rn "Alice\|Invalid category\|must be positive\|showing 1" src/`: no output.
  - Commit message (for the orchestrator): `fix(prompts)`, names the removed literals and the `"showing 1"` example, answers ADR 016's four questions as under "Commit messages", no eval number.

### Step 2: the technique verdicts and the living docs

- **Files**:
  - `src/mcp_auditor/graph/prompts.py`
  - `src/mcp_auditor/domain/category_guidance.py`
  - `src/mcp_auditor/graph/chain_prompts.py`
  - `CHANGELOG.md`
  - `CONTRIBUTING.md`
- **Do**:
  1. `prompts.py`: G2 (rewrite to "use non-existent IDs, boundary values, or invalid inputs"), G5 (replace the zero-first lines with "For integer fields: zero, negative numbers and extremely large values, the classic boundary values."), R3 (middle sentence of rule 3 becomes "A tool is expected to do what its description says it does."). G1, G4, G6, G7 stay byte-identical.
  2. `category_guidance.py`: J2 (delete the "Example: a SQL execution tool ..." sentence, keep the principle), J4 (`returning "no results"` becomes `returning an empty result`), J10 (replace the single-item line with "- Operations bounded by construction, which act on or return a fixed amount of data whatever the input. These are inherently bounded and do NOT require rate limiting to pass."). J0, J6 to J9 stay byte-identical.
  3. `chain_prompts.py`: C1 (keep the restriction, reason becomes "Other categories (input_validation, error_handling, resource_abuse) show in the response to a single request, which the single-step tests already send."), C2 (delete the "For info_leakage chains specifically ..." paragraph and the blank line before it). Keep the triple-quoted f-string with `\` continuations, and exactly one blank line between the C1 paragraph and `{NON_DESTRUCTIVE_CONSTRAINT}`.
  4. `CHANGELOG.md`: under `[Unreleased]` / `### Changed`, add the bullet given verbatim in "Files to modify".
  5. `CONTRIBUTING.md`: in "What makes a good contribution", after the "Eval improvements" bullet, add the sentence given verbatim in "Files to modify" (as its own bullet, matching the list's form).
  6. No eval output is read while doing this step.
- **Test**: no new test. `tests/unit/test_fixture_contamination.py` stays green. `tests/unit/test_prompts.py` and `tests/unit/test_chain_prompts.py` are expected to stay green unchanged. If one asserts a removed or rewritten line, update it to the new text (it asserted a fitted line), never restore the old text.
- **Verify**:
  - `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`: all clean.
  - `grep -rn "Alice\|Invalid category\|must be positive\|showing 1\|delete one record\|delete records\|enumerate entities\|no results\|#1 boundary\|thoroughly covered" src/`: no output.
  - Commit message (for the orchestrator): `fix(prompts)`, names the lines removed or rewritten (G2, G5, R3, J2, J4, J10, C1, C2), answers ADR 016's four questions as under "Commit messages", no eval number.

### After step 2 (not a step, nothing committed)

Run the exploratory measurement of "Verification" (`uv run python -m evals.run_evals --ungated --runs 3 --budget 10`, then `uv run python -m evals.run_judge_eval`, needs `GOOGLE_API_KEY`) and report recall, precision, consistency, distribution coverage, per-server figures and judge F1 to the maintainer, labelled exploratory, beside the April 2026 figures of `output/eval_report.json` if present. Nothing in the tree reacts to the numbers ("Bars written before measurement").
