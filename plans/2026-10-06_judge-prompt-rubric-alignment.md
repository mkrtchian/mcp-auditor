# Judge prompts aligned on the judge-case rubric

## Context

The clauses J0 to J11 of `docs/labeling-log.md` label the cases of the judge isolation fixture: a case label says whether the tool's response or error shows a failure in the category tested. They were written without reference to the judge prompt, and since [ADR 027](../docs/adr/027-honeypot-fixtures-follow-judge-rubric.md) the honeypot ground truth follows them too. The judge itself still decides on the older criteria of `build_judge_prompt` (`src/mcp_auditor/graph/prompts.py`) and `CATEGORY_GUIDANCE` (`src/mcp_auditor/domain/category_guidance.py`), and the chain judge (`build_chain_judge_prompt`, `src/mcp_auditor/graph/chain_prompts.py`) decides on no written criteria at all.

This plan rewrites both judge prompts so that they apply the clauses. It is a change to the system under test: the prompts serve every audit, the honeypot evals, the CVE benchmark and the judge isolation eval. It is not a baseline reset (no fixture, model or scoring code moves), so it goes through the three paired gates. Two instrument changes precede it, each in a commit of its own: a clause added to J3, then the repair of the one honeypot branch that the clause makes depart from its label (see "The rubric revision").

The justification of every prompt line is a clause of the rubric, an OWASP or CWE definition the clause cites, or a product choice stated below. None rests on a case of the fixture flipping. The fixture is a development set and no judge figure is published, so the prompt may be written after reading the cases, and the commit says which were read.

## The divergences, clause by clause

The current prompt and guidance, read against each clause. Each row names what the rewrite does.

| Clause | Current prompt or guidance | Rewrite |
|---|---|---|
| J0 | Asks whether the tool "has a vulnerability". Injection counts input "reflected unsanitized in a way that **could** alter execution". Resource abuse counts a tool that "allows" unbounded consumption. | The question becomes whether the response or the error **shows** a failure. A failure only possible gives PASS. |
| J1 | Rule 1 scopes to the category, good. The guidance routes exclusively: "crashes on bad input (that's error_handling)", "processes input through its core function (that's injection, not input_validation)", "Sensitive data in a success response is info_leakage, NOT error_handling". | A failure that meets several definitions is a FAIL in each. The exclusive routings are rewritten as statements of what each category judges. |
| J1 | Rule 2 says the test description is context, not evidence. Good. | Kept, extended to the chain's step descriptions and observations. |
| J2 | Says a tool forwarding text is not failing input_validation "even if it's empty". Nothing on coercion, nothing on a valid parameter the tool ignores. A crash on bad input sent away to error_handling without saying it is a PASS here. | An empty text in a parameter meant to carry one is invalid. Coercion counts. Acting against a parameter's meaning counts. A refusal in any form, a crash included, is a PASS. The nearest valid value is a PASS (kept, it was the clamping line). The grammar of a carried language is not an input property. |
| J3 | Says a tool forwarding input to a backend may silently process malformed input. No operational test of a formed error. | An operation that cannot succeed reported as a success is a FAIL. A formed error names the cause with no errno, no exception class, no exit code, no raw subprocess output. The new clause on made-up names. |
| J4 | Counts "executed as code" and reflection that "could alter execution". The echo exclusion is there, narrower than J8. | An effect beyond what the tool offers. A tool running what its description says is not injection. Literal data or refusal gives PASS. |
| J5 | Counts "PII (emails, roles, internal identifiers) returned when not required by the tool's purpose". Nothing on versions, internal hosts, the CWE-497 list, the declared scope, the caller's own payload. | The server's implementation and configuration, the system it runs on (CWE-497), data sensitive by nature, personal data from a tool whose objects are not people. The ordinary fields of the tool's own objects are not a leak. |
| J6 | Counts what a tool "allows". "No size caps on operations that could grow". | Hung, crashed, ran out, or did unbounded work, shown in the response. The oversized thresholds. |
| J7 | Nothing. | The framework and its validator are part of the server. A framework prefix does not clean a raw exception. |
| J8 | Partly, in the injection exclusion. | An echo shows no effect, for injection and resource_abuse. |
| J9 | Nothing on timeouts or dropped connections. | A timeout or a dropped connection is a resource_abuse FAIL with an oversized payload only, a PASS otherwise. An empty response shows nothing by itself. |
| J10 | Nothing. | Generalized without the sentinel, see "Product choices". |
| J11 | No third verdict. | Collapsed on PASS, see "Product choices". |
| ADR 014 | The examples of the rubric come partly from the fixtures (`ENOENT`, `Cmd('git') failed`, a bare `"999"`, `confirm=false`, `limit=-100`). | No example of the prompt is taken from a fixture, honeypot or CVE. Each is written for a tool of another domain. |

## Product choices

These are decisions of the maintainer, written in the commit message and in the CHANGELOG.

**A failure not shown gives PASS.** The judge stays binary. Where the rubric says unspecified (a timeout or a dropped connection on a payload that is not oversized, two readings left open on the judge inputs), the judge answers PASS: an auditor reports what the server shows, and a cause not shown is not reported. A third verdict is out of scope.

**J10 is generalized, never named.** The sentinel convention of `evals/cve_targets.py` belongs to the benchmark and never enters a shipped prompt: naming it would fit the product to the benchmark. What J10 adds to J4 and J5 is kept as a general rule: a payload that reaches something outside the tool's declared reach and brings it back (a file outside its declared directories, a credential, an internal host) shows a failure in injection and in info_leakage, whatever the tool's declared function, a fetch tool included. Residual divergence: the judge does not know that a string of the form of the sentinel is a secret by convention, and reads it like any other value.

**The chain judge reads the same criteria as the single-call judge.** A report that applies two definitions of a leak, one for a single call and one for a chain, cannot be defended. The chain planner explores `info_leakage` and `injection` only, so these are the two guidances it reads in practice, and the prompt passes the guidance of whatever category the chain targets.

**A failure shown by any step of a chain counts.** The current chain prompt requires that "the vulnerability must come from the multi-step escalation", so a chain whose first step returns a token is a PASS. Under one definition of a failure that requirement goes: the chain is a FAIL when any of its responses shows a failure of the category, and the progression explains how it was reached without being a condition.

## The rubric revision

One clause is added to J3 before the prompt is written, so that the prompt applies a written clause and not the reverse. It answers a question the clauses left open: whether a name the payload made up shows that a resource does not exist. The case `5a7557a560ec5eef` (`execute_query × error_handling`, a query on a table named `mcp_auditor_missing_table` answered with three rows, labeled FAIL under J3) rests on that reading, and so does the generator's usual probe of a not-found path.

The clause, appended to J3 in the rubric:

> A name the payload made up shows that the resource it names does not exist when it is specific to the call, so that no resource could bear it by chance: random, or describing itself as absent, such as `no-such-invoice-5f2c`. A short or ordinary name (`toto`, `test`, `admin`) could exist and shows nothing, and so does a number, even one at the boundary of a type. An operation on such a made-up resource reported as a success is an operation that cannot succeed reported as a success.

Applied to every case of the fixture, as the rubric's preamble requires for a clause revised once labeling has started. The cases it reaches are the `error_handling` cases whose arguments name a resource, read on their judge inputs only (no judge report, export or baseline is opened for this). A reading of the fixture before this plan found two: `5a7557a560ec5eef` (FAIL, made-up table reported with rows, stays FAIL) and `d259859c74a174b5` (PASS, made-up project refused with a formed error, stays PASS). Three more name something and stay PASS: `1b4cc3651cce4ffa` (a user id refused with a formed error), `b3df5f66dd99f2ef` (a traversal path as a service name, not a made-up name, refused), `dcd18209fdf3d874` (a search for `NoSuchUser-7f3a` answered `No users found`: a search that finds nothing reports no operation on the resource as a success). `3fd29d3533ce58dd` (PASS, a deletion of record -2147483648 reported done) is the case the number exclusion keeps out: a number is not a made-up name, and the clause does not reach it. The implementer reads every `error_handling` case again to confirm none other is reached. If a label moves, the fixture is edited in the same commit, and the judge baseline is re-scored by the eval, with no new recording unless a side is left with no stable and correct case (CONTRIBUTING, "Recording the judge baseline").

The labeling log entry, `### 2026-10-06, J3, a made-up name`, carries: the state of the gates (all green at `02af9f5`, run `37449377894`), the clause, how it was decided (by the maintainer, while planning the judge prompt change, on the question of `5a7557a560ec5eef`), what was known (the maintainer and the assistant had read the case's label and knew the judge of the baseline answered PASS on it in every run, which is declared bias), the cases it reaches with their labels, and the four questions of ADR 016. The criterion of (3) is that a name chosen to designate nothing is the caller's knowledge that nothing bears it, the same knowledge the caller has of a value it sent, and it holds without any verdict.

The same entry reads the three honeypot servers against the revised J3, as [ADR 027](../docs/adr/027-honeypot-fixtures-follow-judge-rubric.md) requires whenever a clause changes, and records the reading of every `error_handling` cell. One branch departs: `project_manager`'s `read_file` answers any path outside `/data/admin/` with `{"content": "Generic file content at <path>"}`, so a call on a made-up path such as `/projects/no-such-file-5f2c.txt` reports a file that does not exist as read. The planted branch departs the same way: it tests `path.startswith("/data/admin/")`, so a made-up path under that directory returns the credentials, a file that does not exist reported as read. `project_manager × error_handling` is labeled PASS and stable PASS in the honeypot baseline, and the generator's usual not-found probe sends exactly that call, so under the new prompt the judge would be right to FAIL it and the honeypot gate would go red on an undeclared cell. The other `error_handling` branches stay as labeled: numbers (`get_user`, `delete_record`) are outside the clause, `list_items`, `get_service_status`, `details`, `profile` and `get_field` refuse unknown names with a formed error, and `search_products` and `search_users` search, they name no resource.

Commit: `docs(labeling-log): ...`, alone, before the prompt commit.

**The repair (ADR 027, ADR 020).** In a second commit, alone: `read_file` in `tests/chain_honeypot_server.py` reads one file, the one that exists, `/data/admin/config.yaml`, matched exactly, and answers every other path, inside or outside `/data/admin/`, with the formed error `No file at <path>` (decided by the maintainer: the server knows which files exist and refuses the others, and no other readable file is added, since no cell needs one and each new content would be one more branch to read against the clauses). The planted info_leakage is untouched: `details` still discloses the configuration path in a single call (J5), and the planted chain (`list`, `details`, then `read_file` on the path `details` gave) still reads the credentials. The old echo of any other path, listed under R6 by earlier entries, ends with it. `evals/baselines/honeypot_e2e.json` is deleted in the same commit (a change to a honeypot's code is a reset, CONTRIBUTING, "Recording an e2e baseline"), with the comments of the changed branches rewritten (they still describe the echo of any other path) and a labeling log entry stating the intent of each changed branch (the exact read, planted info_leakage, the formed error, deliberate PASS control for error_handling), as the entry of 2026-10-06 does for its repairs, and the directions the repair can move cells, written before any run: `project_manager × info_leakage` loses the credentials on a guessed path under `/data/admin/`, and keeps the path in `details` and the credentials on the exact path, `project_manager × error_handling` and `resource_abuse` meet a formed error where they met a read, and the other tools of the chain server can move through the attack context. The gate is green at the parent. Then `--record-baseline` twice at that commit, the baseline committed by hand in a `chore(evals): ...` commit. A recording refused at that commit reverts the repair (ADR 020: a reset whose recording is refused is reverted) and the J3 commit with it, so that `main` never carries a clause a honeypot contradicts (ADR 027), and the plan stops there. The prompt commit gates against that baseline. The judge fixture keeps its cases and inputs (as for the repairs of ADR 027), and the fault injection fixture is not touched (its generator sends `{}`, no repaired branch reaches it).

## The prompts

### Shared rules

A new constant `JUDGING_RULES: str` in `src/mcp_auditor/graph/prompts.py`, beside `NON_DESTRUCTIVE_CONSTRAINT`, read by both judges. A function `format_judging_criteria(category: AuditCategory) -> str` returns the rules followed by the category's guidance, so that both judges render the same block in the same order. It lives in `prompts.py`, right below `build_judge_prompt`, its caller in the module, and `chain_prompts.py` imports it as it already imports `NON_DESTRUCTIVE_CONSTRAINT`.

Draft of `JUDGING_RULES`:

```text
RULES:
1. Judge what the response or the error shows. A failure that is only possible, that nothing in the response or the error shows, gives PASS. When the response leaves two readings open, or does not show whether the server or something around it caused what you see, give PASS: a cause that is not shown is not reported.
2. Judge only the category tested. A failure that meets the definition of the category tested is a FAIL even if it also meets the definition of another category. A failure that meets only the definition of another category gives PASS.
3. The auditor's own text, the test description and any observation written during the test, says what the auditor meant to test or believed. It is not evidence. Only the tool's response and error are.
4. The framework that serves the tool is part of the server. Judge a message from the framework or from its argument validator like any other part of the response. A prefix the framework adds in front of an exception's text does not make that text a formed error.
5. A timeout or a dropped connection gives PASS in every category except resource_abuse, which says when it counts. An empty response shows nothing by itself.
```

### Category guidance

`CATEGORY_GUIDANCE` keeps its shape, one text per category, a "counts" list then a "does NOT count" list. The module comment says both judges read it. Drafts:

```text
input_validation
What counts as an input_validation failure:
- The tool treats an invalid input as valid: it succeeds, or computes a result, from it. An input is invalid when it breaks what a schema could express (type, presence, length, bounds, format, allowed values) or a constraint the tool description states. Read it from the tool's name and description, the parameter's name and the value sent: a negative id, count or quantity, an empty text in a parameter meant to carry one.
- A value of the wrong type converted and used: "10" taken as a number, "yes" as a boolean.
- The tool acts against the meaning its name or description gives to a valid parameter: a dry_run=true call that still writes, a recursive=false call that still descends.
What does NOT count:
- An invalid input refused, whatever the form of the refusal, a crash included. A crash can be an error_handling failure.
- An out-of-range value answered with the nearest valid value: a page size of -5 answered with one item.
- Arbitrary text in a free-text parameter, such as a search term or a command argument. Such text is a valid input, and what the tool does with it is judged under injection.
- A statement in a language the parameter carries (SQL, a glob, a regular expression) that does not parse. Its grammar is not a property of the input: an operation that cannot succeed is judged under error_handling. An empty text is not such a statement: it is judged by the first line above.
```

```text
error_handling
What counts as an error_handling failure:
- An unhandled exception reaches the caller: a stack trace, or the text of an exception passed through as is, whether it comes from the server's code, a system library or a subprocess.
- An operation that cannot succeed is reported as a success: a malformed statement reported as executed, a resource that does not exist reported as found, read or changed. A success message counts as such a report, even with no output of the operation.
A resource name the payload made up shows that the resource does not exist when it is specific to the call, so that nothing could bear it by chance: random or describing itself as absent, such as no-such-invoice-5f2c. A short or ordinary name, such as test or admin, could exist and shows nothing, and so does a number, even one at the boundary of a type.
What does NOT count:
- A formed error: it names the cause in terms of the parameter or the resource, with no errno, no exception class name, no exit code and no raw output of a subprocess. "No invoice numbered 7" and "start_date must be before end_date" are formed, and so is a validator's report that lists the failing fields. "[Errno 13] Permission denied: ...", "Traceback (most recent call last)", "exit status 2: tar: ..." and a bare "'7'" (the text of a lookup exception) are not.
- An invalid input accepted with a success response. That is judged under input_validation, and is an error_handling failure only when the operation asked for could not have succeeded.
- What an error discloses. That is judged under info_leakage: here, only whether the error is formed.
```

```text
injection
What counts as injection:
- The response shows an effect of the payload beyond what the tool offers: the output of a command, the content of a file outside the scope the tool declares, a query result changed by syntax the payload injected into a statement the tool builds (rows the search should not return, a value the payload chose).
- The payload reached something outside the tool's declared reach and brought it back: a file outside its declared directories, a credential, an internal host. This counts whatever the tool's declared function, a tool that fetches URLs included.
What does NOT count:
- A tool running what its description says it runs: a tool described as running shell commands, running one.
- A payload handled as literal data: searched for as text, stored, or returned unchanged.
- A payload refused.
- An echo: the payload returned as it was sent, or a statement that it was executed with no output of its execution. A marker shows execution only when it comes back as the output of a command or a query, not as a copy of the input.
```

```text
info_leakage
What counts as info_leakage, in responses and errors alike:
- The server's own implementation or configuration: paths of its code or configuration files, library or engine versions, stack traces, the name of an internal class or model, database structure, secrets, environment variables, internal hosts.
- The system it runs on: paths of data files, other operating system users, installed packages, details of the runtime environment, command-line arguments, database connection strings.
- Data sensitive by nature, whatever the tool: credentials, passwords or their hashes, tokens and keys, identity numbers, bank or health data.
- Personal data about people from a tool whose objects are not people: a customer's phone number in a weather tool's answer.
- Anything the payload reached outside the tool's declared reach and brought back: a file outside its declared directories, a credential, an internal host. This counts whatever the tool's declared function, a tool that fetches URLs included.
What does NOT count:
- Fields that are ordinary for the objects the tool is about, as its name and description give them: a customer lookup returning the customer's name and address.
- The resources the tool is described as exposing, and the scope it declares: a listing from a tool that lists files, the root a file tool declares, named in a refusal.
- A path or URL given to the caller as a resource to consult, such as documentation.
- The caller's own payload coming back. What the server adds around it is still judged.
- A formed error that reveals no internal detail.
```

```text
resource_abuse
What counts as resource_abuse:
- The response shows the server hung, crashed or ran out of a resource: the process died or stopped answering, an out-of-memory error. A timeout or a dropped connection shows it only as the third line says.
- The server did an unbounded amount of work on request: every one of a million items returned.
- A timeout or a dropped connection, when the payload is oversized: a string of 100,000 characters or more, an integer of absolute value 2^31 or more, nesting 100 levels deep or more, or a count or size parameter of 10^6 or more. With any other payload, a timeout or a dropped connection does not show its cause, and gives PASS.
What does NOT count:
- A large value accepted and processed with a bounded effect.
- An oversized payload returned whole, with no hang and no crash.
- A statement that the payload was executed, with no output of its execution.
- An exception returned in the error. It is judged under error_handling.
- A cap or a rate limit missing, when the response does not show it exceeded.
```

The examples (`no-such-invoice-5f2c`, `dry_run=true`, a weather tool, `No invoice numbered 7`, `[Errno 13]`, `exit status 2: tar`) are written for this prompt: none comes from a honeypot or a CVE target. `tests/unit/test_fixture_contamination.py` checks the honeypot literals, among them the framework prefix the honeypots raise, which is why rule 4 describes the prefix without quoting it. Nothing checks the CVE targets' outputs mechanically: the review of the diff does, against the judge inputs of the fixture's CVE cases.

### `build_judge_prompt`

```text
You are a security evaluator for MCP tool servers.

Your task: decide whether the response or the error of the tool "{tool.name}" shows a **{category}** failure.

{format_judging_criteria(category)}

Tool description: {description}

Test category: {category}

Test case description: {test_case.payload.description}

Attack payload arguments: {arguments}

{outcome_section}

Decide:
- FAIL: the response or the error shows a **{category}** failure
- PASS: it shows none, even if a failure of another category is shown or a failure of this one remains possible

Provide a justification and severity (low, medium, high, critical).
```

### `build_chain_judge_prompt`

```text
You are a security evaluator for MCP tool servers.

Your task: decide whether the responses of the multi-step attack chain against "{tool.name}" show a **{category}** failure.

{format_judging_criteria(category)}

Tool description: {description}

Chain goal: {chain.goal.description}
Target category: {category}

Full chain of interactions:
{steps_section}

Apply the rules to every response of the chain. A failure shown by any step counts, whether or not the earlier steps led to it. The progression explains how a failure was reached, it is not required.

Decide:
- FAIL: a response of the chain shows a **{category}** failure
- PASS: no response of the chain shows one, even if a failure of another category is shown or a failure of this one remains possible

Provide a justification and severity (low, medium, high, critical).
```

The paragraph "Consider the tool's stated purpose ... The vulnerability must come from the multi-step escalation" goes: the injection and info_leakage guidance carry the first half, within the scope J4 and J5 give it, and the second is the requirement the product choice removes. The chain goal stays, as context: rule 3 covers it like the step descriptions and observations.

## Files

- `docs/labeling-log.md`: the J3 clause and its entry (instrument commit).
- `evals/fixtures/judge_cases.json`: only if a label moves under the J3 clause (instrument commit).
- `tests/chain_honeypot_server.py`, `evals/baselines/honeypot_e2e.json` (deleted, then recorded twice), `docs/labeling-log.md`: the repair of `read_file` (second instrument commit and its recording).
- `tests/fakes/fixture_judge.py`: `_SINGLE_STEP_CELL` matches the old task line (`the tool "…" has a **…**`). The new line reads `the tool "{tool.name}" shows a **{category}** failure`, so the regex becomes `r'the tool "(?P<tool>[^"]+)" shows a \*\*(?P<category>\w+)\*\*'`, and its comment stays. Without it every single-step prompt falls through to `_chain_cell` and raises, which breaks `tests/unit/test_eval_fault_fakes.py` and the integration test `tests/integration/test_gate_fault_injection.py`. `_CHAIN_TOOL` (`against "`) and `_CHAIN_CATEGORY` (`Target category: `) still match the new chain prompt, which keeps both texts.
- `src/mcp_auditor/graph/prompts.py`: `JUDGING_RULES`, `format_judging_criteria`, `build_judge_prompt`.
- `src/mcp_auditor/graph/chain_prompts.py`: `build_chain_judge_prompt`.
- `src/mcp_auditor/domain/category_guidance.py`: the five texts and the module comment.
- `tests/unit/test_prompts.py`, `tests/unit/test_chain_prompts.py`: see "Tests".
- `CHANGELOG.md`, `[Unreleased]`, `### Changed`: the judges follow the clauses that label the judge's cases, the chain judge reads the same criteria and counts a failure shown by any step, a failure not shown (a timeout or a dropped connection on a payload that is not oversized included) is a PASS.
- `README.md` line 120 ("LLM-as-a-judge"): add that the criteria follow the clauses that label the judge isolation cases, in `docs/labeling-log.md`, and that the chain judge reads the same criteria. The sentence that places the written rules in `domain/category_guidance.py` also names the shared rules, `JUDGING_RULES` in `graph/prompts.py`. Nothing else in the README describes the criteria.
- `evals/declared_flips.json`: see "Gates".

## What stays unchanged

The judge's output (`Judgment`: verdict, justification, severity) and its two values. The severity scale. `format_tool_header` and the judge's inputs: the judge still does not see the input schema, which J2 assumes. `REDACTION_NOTICE` and `with_redaction_notice`. The generator prompt, the chain planner and the step prompts. The ground truth, the honeypots (save the `read_file` repair), the judge fixture's cases and every label (save a label the J3 clause moves). The baselines, until the recordings below. `evals/judge_fixture_method.md` (its inputs fingerprint covers the cases, not the prompt). No ADR: the plan applies the clauses that ADR 025 and ADR 027 already make the reference, and the product choices above are prompt content, recorded in the commit and the CHANGELOG.

## Tests

Test-first, behavior only. No test asserts the wording of a rule or of a guidance line, which would break on every rewrite without catching a bug, and no test with a fake judges the quality of a verdict (evals do).

- For the `read_file` repair, in `tests/integration/test_chain_honeypot.py`, red before the repair: `read_file` on a made-up path outside `/data/admin/` and on a made-up path under it each return the formed error `No file at <path>` and no file content. The existing `test_read_file_at_admin_path_returns_sensitive_config` stays and must stay green.
- `TestChainJudgePrompt.test_includes_the_guidance_of_the_target_category`: a chain whose goal targets `info_leakage` renders `CATEGORY_GUIDANCE[AuditCategory.INFO_LEAKAGE]` in the prompt. Red before the change.
- `TestChainJudgePrompt.test_states_the_same_rules_as_the_single_call_judge`: `JUDGING_RULES` appears in both prompts. Red before the change.
- `TestJudgePrompt.test_includes_category_guidance` is rewritten to assert that `CATEGORY_GUIDANCE[category]` of the test case's category is in the prompt, instead of the literal "User input is executed as code", which this change removes.
- The other existing prompt tests stay.
- `tests/unit/test_fixture_contamination.py` runs on the new constants unchanged and must stay green. It also fails on any run of three words shared with a honeypot string, docstrings included: the drafts above were checked against it, and two lines were reworded for it (`it is a` and `the ordinary fields` appear in the honeypot docstrings). Any rewording during implementation is checked the same way.
- `tests/unit/test_eval_fault_fakes.py` covers the `FixtureJudge` regex on the new single-step prompt: it goes red with the prompt change and green with the regex change.

## Gates and governance

**Commit of the change.** One commit, `feat(judge): ...` (a deliberate change of behavior, listed under `### Changed`), holding the prompts, the guidance, the tests, the CHANGELOG, the README and the declared flips. Its message answers the four questions of ADR 016: (1) the change lands in the system under test, the two judge prompts and the category guidance, (2) the cases of the judge fixture and their labels were read, and the per-case outcomes of the judge baseline were known, (3) each line follows a clause J0 to J11, an OWASP or CWE definition that a clause cites, or one of the product choices, written out, (4) the change reaches every category, every case and cell, the CVE targets and the chains. The message also states the limits below.

**Declared flips, decided before any eval run.** A flip is declared only for a gated cell or case that the change is expected to move from right to wrong, with its mechanism. The rewrite moves the judge toward the labels that the fixture and the ground truth follow, so no deliberate regression is expected and the expected content of `evals/declared_flips.json` is `{"entries": []}`. The implementer still reads, before running anything, the gated PASS cells of the honeypot baseline and the gated PASS cases of the judge fixture against the new criteria, and declares any that a criterion now reads as a failure. Nothing is declared after a run has shown it flip: an undeclared flip that reproduces reverts the commit.

**Runs at the commit, clean tree.** `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, then the three gates in their CI configuration: `uv run python -m evals.run_judge_eval --concurrency 15`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark` (Docker and the built images). The judge and the e2e runs go one after the other, never in parallel, for the provider's token limit. Exit `1` on any gate: revert the change commit, never declare after the fact. Exit `3`: rerun the gate once, a second `3` stops the plan.

**Recording, only from green.** A suite whose gate is green with no flipped case, a declared flip excepted, and at least one case or cell `improved` or `partial`, has its baseline recorded again at the change commit: `--record-baseline` twice (exploratory, then confirmed), the file committed by hand in a `chore(evals): ...` commit of its own. The judge baseline first, then the honeypot baseline. A recording refused (a non-reproduced flip refuses it too) is retried at most once: two refused attempts leave the old baseline in place and the plan ends there. The CVE baseline is recorded again only if a target is detected in every run of the gated run, under the same rule.

## Edge cases and known limits

- **The chain judge is measured by the honeypot evals only.** The judge fixture holds single-call cases, and the cells a chain can reach (`project_manager` and `user_directory` × `info_leakage`) are unstable in the honeypot baseline, so they are not gated. A rubric for chains and chain cases in the fixture are separate work, after a new draw.
- **Cells far from the judge can move.** Single-call verdicts feed the chain planner and the attack context that the generator reads for the next tool, so any cell of a server can move. The paired gate replays a flip before calling it, which is what separates this from noise.
- **`ca03d12903e6e812`** (`git_log × input_validation`, PASS, error `/` on a negative count) sits on the judge's decision boundary and flipped in one run in three on several runs. The new input_validation guidance says a refusal in any form, a crash included, is a PASS, which is J2's reading of that case. A stricter reading of J2 is the risk.
- **`d6e753db6ac1a9a2`** (`kubectl_generic × injection`, FAIL) returns the probe as command output, without the separator the payload carried. The echo rule must keep reading that as output and not as an echo.
- **Library validator messages.** Under rule 4 and J7, a validator message that gives a library version is an info_leakage FAIL on any server that emits one. The generator sends arguments that conform to the schema, so this is rare in an audit.
- **The fixture's cases from the tools repaired by ADR 027** (`execute_query`, the old `search_users`) keep their labels and their old inputs. They stay valid tests of the judge on those inputs.
- **The J10 divergence** stated under "Product choices".

## Verification

- Unit tests red then green on the three test changes, then the full suite.
- `git grep -nE "MCPAUDIT|Error executing tool|missing_table|confirm=false|ENOENT|Cmd\('git'\)" src/` returns nothing.
- The three gates and the recordings as above, with their exit codes reported in the session summary.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, read by the implementation-phase fact check. A line here records what was concluded once, on 2026-10-06, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: CWE-497, "Exposure of Sensitive System Information to an Unauthorized Control Sphere", lists path names for data files, other OS users, installed packages, the application environment, command-line arguments and database connection strings, as the info_leakage guidance draft restates them (verified against cwe.mitre.org/data/definitions/497.html)
- SETTLED: run `37449377894` is the Evals workflow, conclusion success, at `02af9f54ad9eaca4c33600c9141c8cf9a4b73381` (verified with `gh run view`)
- SETTLED: `uv run python -m evals.run_judge_eval --concurrency 15` is the CI configuration of the judge gate (verified against `.github/workflows/evals.yml`)

## Implementation steps

Verification commands (from `CLAUDE.md`): `uv run pytest -n auto`, `uv run pytest tests/unit`, `uv run pytest tests/integration -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, and the three gates `uv run python -m evals.run_judge_eval --concurrency 15`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark`. Each step ends in one commit, made by hand after the step's checks pass. The order is fixed by the governance: the J3 clause, then the `read_file` repair and its recording, then the prompt change and its gates. A step that ends in a revert ends the plan.

### Step 1: the J3 clause on made-up names

- **Files**: `docs/labeling-log.md`, `evals/fixtures/judge_cases.json` (only if a label moves).
- **Do**:
  - Append the clause quoted under "The rubric revision" to J3 in the `### Judge cases` rubric section.
  - Read every `error_handling` case of `evals/fixtures/judge_cases.json` on its judge inputs only (no judge report, export or baseline opened). Confirm the reading of the plan: `5a7557a560ec5eef` FAIL stays FAIL, `d259859c74a174b5`, `1b4cc3651cce4ffa`, `b3df5f66dd99f2ef`, `dcd18209fdf3d874` and `3fd29d3533ce58dd` stay PASS, and no other case is reached. If a label moves, edit it in the fixture in this commit.
  - Write the entry `### 2026-10-06, J3, a made-up name` at the end of `## Entries`, with the content the plan lists: gate state (green at `02af9f5`, run `37449377894`), the clause, how it was decided, what was known (the declared bias), the cases reached with their labels, the four questions of ADR 016 (criterion of (3) as the plan states it), and the reading of the three honeypot servers' `error_handling` branches against the revised J3: `project_manager`'s `read_file` departs (both the echo branch and the `startswith("/data/admin/")` branch report a made-up file as read), every other branch stays as labeled, with the reasons the plan gives.
- **Test**: no code change. The judge eval re-scores the stored runs if a label moved, nothing to write here.
- **Verify**: `uv run pytest -n auto` green (fixture loaders still parse the fixture if it was edited). Commit `docs(labeling-log): ...`, alone.

### Step 2: the `read_file` repair of the chain honeypot

- **Files**: `tests/integration/test_chain_honeypot.py`, `tests/chain_honeypot_server.py`, `evals/baselines/honeypot_e2e.json` (deleted), `docs/labeling-log.md`.
- **Do**:
  - Tests first, in `TestProjectManagerChain` of `tests/integration/test_chain_honeypot.py`: `read_file` on a made-up path outside `/data/admin/` (such as `/projects/no-such-file-5f2c.txt`) and on a made-up path under it (such as `/data/admin/no-such-file-5f2c.yaml`) each return an error whose content contains `No file at <path>` and none of the `SENSITIVE_CONFIG` keys (`api_keys`, `database`). Run them red. Read how a raised `ValueError` surfaces in `response.content` from the existing error tests (the framework prefix) and assert on the containment of `No file at <path>`.
  - In `tests/chain_honeypot_server.py`, `read_file`: return `SENSITIVE_CONFIG` only for the exact path `/data/admin/config.yaml` (reuse the `internal_path` constant of the project if it reads naturally), raise `ValueError(f"No file at {path}")` for every other path. Rewrite the branch comments: the exact read is the planted info_leakage chain step 3, the formed error is a deliberate PASS control for error_handling, and the echo comment goes. Keep the R4 history sentence that explains why input_validation and injection left the ground truth if it still applies.
  - Delete `evals/baselines/honeypot_e2e.json`.
  - Labeling log entry (title in the style of the existing ones, such as `### 2026-10-06, read_file of the chain honeypot`): the gate state (green at the parent), the reason (the J3 clause of the previous entry, ADR 027), the decision by the maintainer, the intent of each changed branch, the end of the R6 echo, and the directions the repair can move cells, written before any run, as the plan lists them (`project_manager × info_leakage`, `× error_handling`, `× resource_abuse`, and the other tools through the attack context). State that the judge fixture and the fault injection fixture are not touched.
- **Test**: the two new integration tests red then green. `test_read_file_at_admin_path_returns_sensitive_config` and the rest of `tests/integration/test_chain_honeypot.py` stay green. `tests/integration/test_gate_fault_injection.py` stays green (its generator sends `{}`).
- **Verify**: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green. `uv run pytest tests/unit/test_fixture_contamination.py` green. Commit `test(evals): ...` or `fix(evals): ...` in the style of the earlier repair commits (`git log --oneline` for the entry of 2026-10-06), alone.

### Step 3: record the honeypot baseline after the repair

- **Files**: `evals/baselines/honeypot_e2e.json` (recorded).
- **Do**: at the commit of step 2, clean tree, run `uv run python -m evals.run_evals --record-baseline` twice (exploratory, then confirmed). Commit the file by hand, `chore(evals): ...`, alone. A refused recording reverts step 2 and step 1 (`git revert` of both, newest first) and the plan stops there: report it.
- **Test**: none.
- **Verify**: both recordings exit 0, the second one writes the baseline, `git status` shows only `evals/baselines/honeypot_e2e.json` before the commit.

### Step 4: the judge prompts follow the clauses

- **Files**: `tests/unit/test_prompts.py`, `tests/unit/test_chain_prompts.py`, `tests/fakes/fixture_judge.py`, `src/mcp_auditor/graph/prompts.py`, `src/mcp_auditor/graph/chain_prompts.py`, `src/mcp_auditor/domain/category_guidance.py`, `CHANGELOG.md`, `README.md`, `evals/declared_flips.json`.
- **Do**:
  - Before writing anything, read the gated PASS cells of the (new) honeypot baseline and the gated PASS cases of the judge fixture against the new criteria, and declare in `evals/declared_flips.json` any that a criterion now reads as a failure (format in `CONTRIBUTING.md`, "Declaring a deliberate regression", `base` from `git rev-parse HEAD`). Expected content: `{"entries": []}`, unchanged.
  - Tests first:
    - `TestJudgePrompt.test_includes_category_guidance` asserts `CATEGORY_GUIDANCE[test_case.payload.category]` (read the attribute path from the model) is in the prompt, instead of the literal `"User input is executed as code"`.
    - `TestChainJudgePrompt.test_includes_the_guidance_of_the_target_category`: a chain whose goal targets `info_leakage` renders `CATEGORY_GUIDANCE[AuditCategory.INFO_LEAKAGE]`.
    - `TestChainJudgePrompt.test_states_the_same_rules_as_the_single_call_judge`: `JUDGING_RULES` is in both prompts.
    - Run them: the two chain tests are red, and `test_includes_category_guidance` turns red once the guidance text changes.
  - `src/mcp_auditor/graph/prompts.py`: add `JUDGING_RULES` beside `NON_DESTRUCTIVE_CONSTRAINT` (draft under "Shared rules"), rewrite `build_judge_prompt` on the draft under "`build_judge_prompt`", and add `format_judging_criteria(category: AuditCategory) -> str` right below it (rules, a blank line, the category's guidance).
  - `src/mcp_auditor/graph/chain_prompts.py`: rewrite `build_chain_judge_prompt` on its draft, importing `format_judging_criteria`. Keep `against "{tool.name}"` and `Target category: {category}`. The "Consider the tool's stated purpose ... multi-step escalation" paragraph goes.
  - `src/mcp_auditor/domain/category_guidance.py`: the five texts of the drafts, the module comment saying both judges read it.
  - `tests/fakes/fixture_judge.py`: `_SINGLE_STEP_CELL` becomes `r'the tool "(?P<tool>[^"]+)" shows a \*\*(?P<category>\w+)\*\*'`, comment unchanged.
  - `CHANGELOG.md` `[Unreleased]`, `### Changed`, and `README.md` line 120, as the "Files" section says.
  - Any rewording of the drafts is checked against `tests/unit/test_fixture_contamination.py` (no three-word run shared with a honeypot string). No example taken from a fixture, honeypot or CVE target: read the diff against the judge inputs of the fixture's CVE cases.
- **Test**: the three prompt tests above, red then green. `tests/unit/test_eval_fault_fakes.py` red with the prompt change and green with the regex change. `tests/unit/test_fixture_contamination.py` and every other existing prompt test stay green.
- **Verify**: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green. `git grep -nE "MCPAUDIT|Error executing tool|missing_table|confirm=false|ENOENT|Cmd\('git'\)" src/` returns nothing. Commit `feat(judge): ...`, one commit holding all the files above, its message answering the four questions of ADR 016 and stating the product choices and the known limits, as "Gates and governance" requires.

### Step 5: the three gates and the recordings

- **Files**: `evals/baselines/judge_isolation.json`, `evals/baselines/honeypot_e2e.json`, `evals/baselines/cve/` (each only if recorded).
- **Do**: at the commit of step 4, clean tree, run in sequence, never two LLM gates in parallel: `uv run python -m evals.run_judge_eval --concurrency 15`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark` (Docker, built images). Exit `1` on any gate: `git revert` the step 4 commit, never declare after the fact, the plan ends. Exit `3`: rerun that gate once, a second `3` stops the plan. Then record under "Recording, only from green": the judge baseline first (`run_judge_eval --record-baseline` twice), committed alone in `chore(evals): ...`, then the honeypot baseline the same way, then the CVE baseline only if a target is detected in every run of the gated run. A refused recording is retried at most once, two refusals leave the old baseline in place and end the plan.
- **Test**: none.
- **Verify**: the exit code of every gate and recording, reported in the session summary.
