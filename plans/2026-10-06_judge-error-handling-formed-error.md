# The error_handling guidance judges an error that is not formed

## Context

The judge prompts were rewritten on the judge-case clauses in `f263c62` (`feat(judge): judge on the clauses that label the judge cases`, plan `plans/2026-10-06_judge-prompt-rubric-alignment.md`). The judge isolation gate ran at that commit and exited `1`: `aef906ac6a361f21` and `015b054f8f42d65e` (`get_user × error_handling`, label FAIL under J3, error `Error executing tool get_user: <the id sent>`) flipped to PASS and the flips reproduced. `51b444e` (`fix(judge): read an error that gives only a value as not formed`) added a bare value to the examples of an error that is not formed. The gate ran again at `51b444e` and exited `1` on `015b054f8f42d65e`, `aef906ac6a361f21` unstable. The honeypot e2e gate (`uv run python -m evals.run_evals`) then ran once at `51b444e`, before this plan was implemented, and exited `1` on the same cell, `get_user/error_handling` (baseline `FFFFFF`, run `PPP`, replays 4/4). No other gated cell regressed: `delete_record/error_handling` flipped once (`PPF`) and did not reproduce (0/2), and the two cells outside the gate moved as unstable cells do (`list_items/input_validation` `FFF`, `project_manager/info_leakage` `PPP`). Nothing is pushed: `main` on the remote is at `02af9f5`, six commits behind the local `main` (`6d6c725` to `51b444e`).

The maintainer kept both commits and plans the next change from here, on the condition that ADR 016 holds: every line the change adds is justified by a reason of the product, and the prompt is not fitted to the fixture. ADR 020 reverts a change after a run red on an undeclared cell. The reading applied here is that the change to the judge prompts is `f263c62`, `51b444e` and the commit of this plan, judged as a whole: nothing of it is pushed before its gates are green, nothing is declared after a run, and a red gate on this commit reverts all three.

## What the judge read

Eight exploratory judgments of the two cases at `51b444e` (four each, verdicts and justifications read, 1 FAIL and 7 PASS) show how the judge reads the guidance. These are diagnostics, not a measurement: nothing below is chosen by a count of verdicts.

- The judge sees that the error is not formed and does not take it for a failure: "Although the value-only error is not a formed error, that alone is not an error_handling failure under the stated criteria." The guidance lists two failures, an unhandled exception and an operation that cannot succeed reported as a success, and puts the formed error under "does NOT count". An error that is not formed is a failure nowhere in it.
- The judge applies the number exclusion to an error: six of the seven PASS say the id "could refer to an existing user". The exclusion was written for a success report (an operation on a resource that does not exist reported as a success), and the guidance does not say so.

## The change and its product reasons

Only the `error_handling` text of `CATEGORY_GUIDANCE` (`src/mcp_auditor/domain/category_guidance.py`) changes. Two edits, the first bounded by three precisions, each with the reason that justifies it. No reason mentions a case, a verdict or a gate, and both hold with every mention of the measurement deleted (ADR 016, the deletion test).

**1. An error the caller receives that is not formed is a failure.** What the error_handling category reports to the user of mcp-auditor is whether a server, when an operation fails, gives its caller an error the caller can act on. The caller of an MCP tool is usually an agent: an error that names the cause (`No invoice numbered 7`) tells it what to change, an error that does not (a raw exception, an errno, a value with nothing around it) tells it nothing and shows the server did not handle the condition. That is CWE-755 (Improper Handling of Exceptional Conditions), and it is J3's own structure: an error the caller receives is either formed, a PASS, or the text of an exception passed through as is, a FAIL. The guidance kept the two ends and lost the dichotomy between them. The edit moves the definition of a formed error into "What counts", as the condition an error has to meet, and leaves "A formed error" under "does NOT count". The line it replaces, "An unhandled exception reaches the caller", held for a response as well as an error, and so does the new one: a server can return its error as ordinary content, which the judge reads under "Tool response" (the audit records an error only when the MCP result is flagged `isError` or the call itself fails, on a JSON-RPC error, a timeout or a client exception, `make_execute_tool` in `graph/nodes.py` and `call_tool` in `adapters/mcp_client.py`), and its caller receives it all the same.

Three precisions bound that first line, each for a reason of its own:

- **A cause stated in general terms is formed.** The security guidance error_handling serves recommends that an error tell its caller as little as it needs: OWASP's Error Handling guidance and the mitigations of CWE-209 (Generation of Error Message Containing Sensitive Information) advise a generic message to the caller and the detail in the server's logs. A refusal that says the input was rejected, or that the resource was not found, without naming which, follows that advice and still tells the caller what kind of thing to change. The category must not count as a failure what the security guidance recommends. A value alone states no cause at all, generic or specific, and stays on the failing side.
- **A validator's report that names the failing fields is formed, whatever else it carries.** The report of a framework's argument validator names the field and the rule it breaks, which is what the caller needs. The internal model name and the versioned link beside them are a disclosure, and what an error discloses is judged under info_leakage (the guidance's last line, and J7 for a library version). Without the precision, the report reads both ways: it lists the fields, and it is also the text of a validation exception behind the framework's prefix, which rule 4 does not clean.
- **A response that carries the result asked for is not an error.** The first line covers the response as well as the error, and a tool whose result is a single value (a lookup returning a name, a field returning its value) answers with a value alone. That value is the operation's success, not an error that names no cause.

**2. The made-up name and the number exclusion apply to a success report only.** The paragraph on a name the payload made up answers one question: does the payload show that the resource does not exist, so that a success reported on it is an operation that cannot succeed reported as a success. When the server answers with an error, nothing was reported as a success and the question does not arise: whether the error is formed does not depend on whether the resource exists. J3 ties the clause to the success report in its last sentence. The edit attaches the paragraph to the success-report line, for that line only.

Draft of the new text (the "does NOT count" lines on input_validation and info_leakage are unchanged):

```text
What counts as an error_handling failure:
- An error the caller receives, in the response or the error, that is not formed. A response that carries the result asked for is not an error. An error is formed when it names the cause in terms of the parameter or the resource, with no errno, no exception class name, no exit code and no raw output of a subprocess. The cause may be stated in general terms: a refusal that says the input was rejected, or that the resource was not found, without saying which field or which resource, is formed. "No invoice numbered 7" and "start_date must be before end_date" are formed, and so is a validator's report that names the failing fields, whatever model name or link it carries beside them: those are judged under info_leakage. A stack trace, "Traceback (most recent call last)", "[Errno 13] Permission denied: ...", "exit status 2: tar: ..." and an error that gives only a value, the one sent or a key, quoted or not, such as a bare "7" or "'7'", are not: such an error is the text of an exception passed through as is, whether it comes from the server's code, a system library or a subprocess, or it names no cause.
- An operation that cannot succeed is reported as a success: a malformed statement reported as executed, a resource that does not exist reported as found, read or changed. A success message counts as such a report, even with no output of the operation. For this line only: a resource name the payload made up shows that the resource does not exist when it is specific to the call, so that nothing could bear it by chance: random or describing itself as absent, such as no-such-invoice-5f2c. A short or ordinary name, such as test or admin, could exist and shows nothing, and so does a number, even one at the boundary of a type.
What does NOT count:
- A formed error.
- An invalid input accepted with a success response. That is judged under input_validation, and is an error_handling failure only when the operation asked for could not have succeeded.
- What an error discloses. That is judged under info_leakage: here, only whether the error is formed.
```

The examples are those the guidance already carries (the invoice domain, `start_date`, `[Errno 13]`, `exit status 2: tar`, `"7"`). None comes from a fixture, honeypot or CVE target (ADR 014): no `999`, no `987654321`, no `get_user`, no `user_id`. The generic refusal is described, not quoted: the honeypots' own generic message is a discriminating literal of `tests/unit/test_fixture_contamination.py`, and the draft names no such string.

## No fitting to the fixture

- **No variant loop.** The text above is the change. It is written and committed before any judgment of it, and no exploratory call is made on it: the next measurement is the gate. A gate that comes back red is not followed by another edit, it reverts the whole change (see "Gates").
- **No selection by score.** No threshold on the fixture's cases decides whether the text ships. The reasons above decide it.
- **The rules stay.** `JUDGING_RULES` is not touched: the diagnosis does not involve rule 1 (two readings left open), and no product reason found here calls for changing a shared rule.
- **The scope is error_handling.** The guidance of a category is read only for the cases and cells of that category (`format_judging_criteria` in `graph/prompts.py`, called by both judges), so the change reaches the error_handling judgments of every audit and nothing else. These are single-call in practice: the chain planner's prompt asks for `info_leakage` and `injection` chains only, but `ChainGoal.category` accepts any category, so an error_handling chain the planner returns anyway is judged on the new text too.

## Files

- `src/mcp_auditor/domain/category_guidance.py`: the `error_handling` text, as drafted. Nothing else in the file.
- Nothing else. No CHANGELOG edit: the `[Unreleased]` entry of `f263c62` already says the judges follow the clauses, and this change is part of the same unreleased change. No README edit. `evals/declared_flips.json` stays `{"entries": []}`, unless the reading under "Edge cases" finds a gated cell or case the new text reads as a failure, which it then declares in the same commit.

## What stays unchanged

`JUDGING_RULES`, the four other guidance texts, `build_judge_prompt`, `build_chain_judge_prompt`, the fixtures, the labels, the ground truth, the honeypots, the baselines (until the recordings below), the rubric in `docs/labeling-log.md`.

## Tests

No test asserts the wording of a guidance line (plan of `f263c62`, "Tests"), and no test with a fake judges the quality of a verdict. The change adds no test. `tests/unit/test_prompts.py::TestJudgePrompt::test_includes_category_guidance` keeps passing (it reads `CATEGORY_GUIDANCE` itself). `tests/unit/test_fixture_contamination.py` must stay green: no discriminating honeypot literal (a string or function name of the three honeypot servers) whole in a string constant of `src/`, and no run of three words shared with one, docstrings included. The draft above, the line on the response included, passes that check as written. A rewording it forces is checked against the product reasons above and stays within them.

## Commit

`fix(judge): judge an error that is not formed as an error_handling failure` (or close), alone. Its message answers the four questions of ADR 016:

1. Where it lands: the system under test, the error_handling guidance both judges read.
2. What was known: the judge gate runs at `f263c62` (red on `aef906ac6a361f21` and `015b054f8f42d65e`) and at `51b444e` (red on `015b054f8f42d65e`), the honeypot e2e gate run at `51b444e` (red on `get_user/error_handling`, `delete_record/error_handling` flipped once and not reproduced, `list_items/input_validation` `FFF` and `project_manager/info_leakage` `PPP` outside the gate), and eight exploratory judgments of those two cases at `51b444e`, verdicts and justifications read, with the labels of both cases. The change was found by reading that output, so any number it produces on those cases is exploratory and confirms nothing.
3. The criterion: the product reasons above, the two edits and the three precisions, written out, each holding without the measurement.
4. What it reaches: every error_handling judgment of every audit, on every server and CVE target, and nothing outside error_handling.

It names the runs seen, so that review can check none was declared after the fact.

## Gates

At the commit, clean tree, in sequence, never two LLM gates in parallel: `uv run python -m evals.run_judge_eval --concurrency 15`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark` (Docker, the built images). The rules are those of the plan of `f263c62`, "Gates and governance":

- Exit `1` on any gate: revert the whole judge change, newest first, `git revert --no-edit <this commit> 51b444e f263c62`, and stop. No further edit, no declaration. The J3 clause (`a9793d9`), the `read_file` repair (`8e48e1d`) and the honeypot baseline (`df41eaa`) stay: they are instrument changes that do not depend on the prompts, and the honeypot baseline was recorded on the old prompts, which the revert restores.
- Exit `3`: rerun that gate once, a second `3` stops.
- Exit `4` (a crash, the CVE preflight included): stop and report, no revert and no recording. A crash measures nothing.
- Recording, only from green: a suite whose gate is green with no flipped case, a declared flip excepted, and at least one case or cell `improved` or `partial`, is recorded again at the commit, `--record-baseline` twice, committed alone in `chore(evals): ...`. The judge baseline first, then the honeypot baseline, then the CVE baseline only if a target is detected in every run of the gated run. A recording refused twice leaves the old baseline in place and stops.

## Edge cases and known limits

- **The generic refusal of invalid arguments.** The three honeypot servers answer a wrong type, a missing argument or a value outside an allowed set with one generic message behind the framework's prefix (the fixture repair of 2026-09-24 in `docs/labeling-log.md`, `dd04f33`), and the seven gated error_handling PASS cells of the honeypot baseline (`delete_record`, `get_service_status`, `list_items`, `search_products`, `search_users`, `project_manager`, `user_directory`) receive it whenever the generator sends an invalid format. Under J3 they are correct PASS controls. The precision "a cause stated in general terms is formed" reads that message as formed, for the product reason given with it, and the cells are not declared. Without the precision the new first line would have exposed them.
- **The SDK's validator report.** The pydantic report of the SDK's validator (`1 validation error for <tool>Arguments`, the failing field, a `[type=..., input_value=...]` tag and an `errors.pydantic.dev/<version>` link) is what an unmodified FastMCP server returns on invalid arguments. No honeypot and no case of the judge fixture returns it since `dd04f33`. The precision on a validator's report reads it as formed.
- **An empty error written by mcp-auditor's client.** `call_tool` in `adapters/mcp_client.py` writes `str(exc)` as the error of any exception its client raises, and a closed anyio stream has an empty text, which reaches the judge as an empty `Tool error:` block. The judge cannot see who wrote an error, and rule 1 gives PASS when nothing shows whether the server or something around it caused what is seen. The guidance adds nothing for it: a line asking the judge to discount errors the auditor wrote would give every server a way toward PASS. The fix belongs in the adapter, as separate work: write a transport failure as the connection closed, the case rule 5 already names, never as an empty string.
- **A causeless message that is not exception text.** "Or it names no cause" makes the draft stricter than J3 on a message such as a bare "internal error", which J3 does not classify. No honeypot and no case of the judge fixture produces one. The divergence is recorded, not acted on.
- **Short errors at the boundary.** Rule 4 judges the framework's messages like the server's. The implementer reads the gated error_handling PASS cells of the honeypot baseline and the error_handling PASS cases of the judge fixture against the new text before any run, and declares in `evals/declared_flips.json`, in the commit of the change, any the text reads as a failure, with its mechanism (CONTRIBUTING, "Declaring a deliberate regression"). The baseline holds verdicts only, so a cell is read from the errors its tool's code and the framework can return. The fixture's eight error_handling PASS cases were read at review: the six errors (`Unknown service`, `Invalid category`, `Unknown project: ...`, `Unknown user: ...`, `user_id must be positive — see ...` twice) all name the cause, and the two others answer with no error, so none reads as a failure under the new text. The expected content is `{"entries": []}`.
- **`aef906ac6a361f21` was unstable at `51b444e`.** A flip that does not reproduce leaves the gate green, and the recording rule above decides whether the baseline moves.
- **The judge does not know a bare value is the text of an exception.** The labelers knew it from the server code (J3 cites a bare `"999"` as the text of a `KeyError`). The new line does not need it: an error that names no cause fails whatever produced it.
- **Every limit of the plan of `f263c62`** still holds (the chain judge measured by the honeypot evals only, cells far from the judge can move, the J10 divergence).

## Verification

- `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, green.
- `git grep -nE "MCPAUDIT|Error executing tool|missing_table|confirm=false|ENOENT|Cmd\('git'\)|999|get_user|user_id" src/mcp_auditor/domain/category_guidance.py` returns nothing.
- The three gates and the recordings, their exit codes reported.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, as of 2026-10-06. Later passes, the implementation-phase fact check included, read it. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `CWE-755 (Improper Handling of Exceptional Conditions)` (verified against cwe.mitre.org/data/definitions/755.html, a Class entry MITRE discourages for mapping a specific vulnerability)
- SETTLED: a tool execution error is a result with `isError: true`, an unknown tool or invalid arguments may come back as a JSON-RPC protocol error instead (verified against the MCP specification 2025-06-18, server/tools, "Error Handling")
- SETTLED: `1 validation error for <tool>Arguments`, then the failing field, a `[type=..., input_value=..., input_type=...]` tag and `https://errors.pydantic.dev/2.12/v/<type>` (verified against the installed pydantic 2.12.5 and mcp 1.30.0, `func_metadata.py`)
- OPEN (unverified): the remote `main` at `02af9f5`, six commits behind the local `main`, matches the local tracking ref, but a live `git ls-remote` was refused for lack of credentials in the diligence sandbox

## Implementation steps

Verification commands (from `CLAUDE.md`): `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, and the three gates `uv run python -m evals.run_judge_eval --concurrency 15`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark`. Each step ends in its commits, made by hand after the step's checks pass. A step that ends in a revert or a stop ends the plan.

### Step 1: the error_handling guidance judges an error that is not formed

- **Files**: `src/mcp_auditor/domain/category_guidance.py`, `evals/declared_flips.json` (only if a cell or case is declared).
- **Do**:
  - Before editing, read against the drafted text (under "The change and its product reasons"):
    - the gated `error_handling` PASS cells of `evals/baselines/honeypot_e2e.json` (keys `<tool>/error_handling` in each run, a cell stable and correct in every run is gated, its label in `evals/ground_truth.py`), each read from the errors its tool's code in the three honeypot servers (`tests/honeypot_server.py`, `tests/subtle_server.py`, `tests/chain_honeypot_server.py`) and the framework can return, the generic refusal of invalid arguments each server's `call_tool` override returns included (see "Edge cases and known limits");
    - the `error_handling` PASS cases of `evals/fixtures/judge_cases.json`, on their judge inputs only.
    Declare in `evals/declared_flips.json` any cell or case the new text reads as a failure, with its mechanism (format in `CONTRIBUTING.md`, "Declaring a deliberate regression", `base` from `git rev-parse HEAD`, `runs_seen` naming the runs listed under "Commit"). Expected content: `{"entries": []}`, unchanged.
  - Replace the `AuditCategory.ERROR_HANDLING` text of `CATEGORY_GUIDANCE` with the draft, verbatim. Nothing else in the file changes (module comment and the four other texts included).
  - If `tests/unit/test_fixture_contamination.py` forces a rewording, keep it within the product reasons above, and keep the examples out of every fixture, honeypot and CVE target (ADR 014).
  - No CHANGELOG, README or other doc edit.
- **Test**: no new test (plan, "Tests"). `tests/unit/test_prompts.py::TestJudgePrompt::test_includes_category_guidance` and `tests/unit/test_fixture_contamination.py` stay green.
- **Verify**: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green. `git grep -nE "MCPAUDIT|Error executing tool|missing_table|confirm=false|ENOENT|Cmd\('git'\)|999|get_user|user_id" src/mcp_auditor/domain/category_guidance.py` returns nothing. Commit `fix(judge): judge an error that is not formed as an error_handling failure` (or close), alone, holding the guidance and any declaration, its message answering the four questions of ADR 016 as "Commit" lists them and naming the runs seen.

### Step 2: the three gates and the recordings

- **Files**: `evals/baselines/judge_isolation.json`, `evals/baselines/honeypot_e2e.json`, `evals/baselines/cve/` (each only if recorded).
- **Do**: at the commit of step 1, clean tree, run in sequence, never two LLM gates in parallel: `uv run python -m evals.run_judge_eval --concurrency 15`, `uv run python -m evals.run_evals`, `uv run python -m evals.run_cve_benchmark` (Docker, the built images). Apply "Gates":
  - Exit `1` on any gate: `git revert --no-edit <step 1 commit> 51b444e f263c62`, newest first, and stop. No further edit, no declaration.
  - Exit `3`: rerun that gate once, a second `3` stops.
  - Exit `4`: stop and report, no revert, no recording.
  - From green only (no flipped case, a declared flip excepted, at least one case or cell `improved` or `partial`): record with `--record-baseline` twice at that commit, each suite committed alone in `chore(evals): ...`. The judge baseline first, then the honeypot baseline, then the CVE baseline only if a target is detected in every run of the gated run. A recording refused twice leaves the old baseline in place and stops.
- **Test**: none.
- **Verify**: the exit code of every gate and recording, reported, and `git status` clean after each commit.
