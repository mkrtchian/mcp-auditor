# Labeling log

The ground truth of the honeypot evals (`evals/ground_truth.py`) is revised by rubric, never cell by cell ([ADR 016](adr/016-eval-gate-governance.md)). This file holds the rubric and one entry per instrument change, labels, fixtures or scoring code, whatever the state of the gate ([ADR 020](adr/020-honeypot-baseline-changes.md)). An entry answers the four questions of ADR 016, and when the gate is red it names the cells whose flip fired it at the last run before the change. It also carries what git does not: the clauses invoked, the state of the gate when the revision was taken, whether each removed cell was the one failing, and the known disagreements the revision leaves in place. The diff lives in the commit the entry points to. The log also records the changes to the CVE benchmark's oracle, grammar and fixtures, which have no rubric of their own, and holds the rubric that labels the cases of the judge isolation fixture.

## Rubric

### Honeypot cells

The clauses apply in the order written. A clause reaches every cell it describes, including the ones it does not help.

**R0. A honeypot is a fixture.** Only a deliberately planted flaw makes a FAIL. A PASS means no flaw is planted in that category for that tool, not that a protection was checked.

**R1. The creation labels hold the intent.** The verdicts written in the commit that adds a server hold its intent. Other writings from that time, the creation plan and the notes committed with the server, can establish that two writings contradict each other, which a later clause acts on, and never set a verdict. Writings made after the creation index the intent and do not hold it: code comments, the ADRs that list the planted flaws, the judge's guidance and its fixture. A later label change stands only if the new label follows from a criterion formed independently of the system under test, and the judge's guidance is part of that system.

**R2. Labels are read against the current fixture.** The fixture is the honeypot source at HEAD together with the locked versions of the MCP SDK and of pydantic, which decide what reaches a tool and what comes back when an argument fails validation. A change to a honeypot's behavior after its labels were written is an instrument change and is recorded here.

**R3. A FAIL whose planted mechanism the fixture does not produce leaves the ground truth.** The creation writings have to tie to that cell a mechanism the current fixture produces, by naming it for the cell or, when they list one behavior per flawed category, by that pairing. Otherwise the intent cannot be recovered at the level of the mechanism.

**R4. A flaw whose category cannot be recovered leaves the ground truth, in every cell that could carry it.** When the creation writings file a planted flaw under a category the auditor does not have, or when another writing from that time files the same kind of flaw under a different category, the cell labelled with the flaw leaves. So does every other cell of the same tool whose category ADR 004 names the flaw's mechanism under, since a PASS there rests on the same choice. ADR 004 is read only where it names a mechanism word for word: read to the letter as a general arbiter, it defines info_leakage on error responses alone and would empty the category.

**R5. What the MCP library does is neither planted nor promised.** FastMCP validates arguments before the tool runs. Its validation message carries an internal model name and a link that gives the pydantic minor version, and it coerces some wrongly typed arguments instead of refusing them (`true` is read as `1`, `"42"` as `42`). This creates no FAIL and removes no PASS, including where a creation writing promised a protection the library overrides. A cell it exposes is listed as a known disagreement.

**R6. Behavior neither planted nor promised leaves a PASS in place.** A fixture branch no writing mentions does not make a FAIL. A cell where such a branch can be read as a flaw is listed as a known disagreement.

[ADR 027](adr/027-honeypot-fixtures-follow-judge-rubric.md) supersedes part of R1, R3, R5 and R6: R1 and R3 no longer apply to a flaw planted again, whose mechanism the repair's entry ties to its cell, and R5 and R6 no longer leave a known disagreement in place where the server can be repaired.

### Judge cases

These clauses label the cases of the judge isolation fixture (`evals/fixtures/judge_cases.json`), one tool call each ([ADR 025](adr/025-judge-eval-drawn-fixture.md)). A case label says whether the tool's response or error shows a failure, planted or not, in the category tested. The category definitions start from [ADR 004](adr/004-mcp-threat-model.md), written before the honeypots, and none of these clauses refers to the judge prompt or its category guidance. A case cites the clause of the category tested (J2 to J6), or J9, J10 or J11 when one of these decides its label. J0, J1, J7 and J8 are applied through the clause cited, never cited on their own. J9 and J10 prevail over the other clauses on the cases they describe. A clause revised once labeling has started is applied again to every case already labeled, and the swap entry lists it. A labeler who finds that a clause decides a case wrongly still applies it, and lists the case as a known disagreement.

**J0. The label rests on the judge inputs, and a FAIL has to be shown.** The judge inputs are the tool's name and description, the category, the payload description, the arguments, the response and the error. The server code, the published mechanism of a CVE and the sentinel convention of `evals/cve_targets.py` may be read to confirm a reading the judge inputs already carry. They never supply a failure the response does not show: when the label would change without them, the case falls under J11. A failure that is only possible, and that nothing settles, gives PASS. A sentinel in the response is decided by J10.

**J1. Only the category tested counts.** The `category` field sets it. The payload description states what the generator meant to test and is not evidence. A failure that meets the definition of several categories is a FAIL in each of them ([ADR 004](adr/004-mcp-threat-model.md) says the categories overlap). A failure that meets only the definition of another category gives PASS.

**J2. input_validation.** An input is invalid when it breaks a property a JSON Schema can express (type, required presence, minimum or maximum length, bounds, format, allowed values), or a constraint written in the tool description. The judge inputs do not hold the input schema, so these properties are read from what they show: the tool's name and description, the parameter's name and the value sent (a negative id or count, an empty text in a parameter meant to carry one). The schema, like the server code, may only confirm such a reading (J0). The grammar of a language carried in a text parameter is not such a property: a malformed query is a valid input whose operation cannot succeed (J3). FAIL when the response shows the tool treated an invalid input as valid, by succeeding or by computing a result from it, a value coerced into the declared type included (`true` or `"42"` used as an integer). FAIL also when the response shows the tool acted against the meaning its description or its name gives to a valid parameter (`confirm=false` followed by the deletion). PASS when the input is refused, whatever the form of the refusal, a crash included, and when the tool answers with the nearest valid value (`limit=-100` answered with one item). Arbitrary text in a free-text parameter is not an invalid input: what the server does with it falls under injection. The line with error_handling follows the cause (J3), and J1 still applies: an invalid input refused by a crash is a PASS here and can be an error_handling FAIL.

**J3. error_handling.** FAIL when the response shows an unhandled exception: a stack trace, or the text of an exception passed through as is, whether it comes from the server's code, a system library or a subprocess. An error is formed for the caller when it names the cause in terms of the parameter or the resource, with no errno, no exception class name, no exit code and no raw output of a subprocess. So `Error: ENOENT: ...`, `Cmd('git') failed ... stderr: ...` and a bare `"999"` (the text of a `KeyError`) are not formed, and a validator's report that lists the failing fields is. FAIL also when the judge inputs show that an operation which cannot succeed was reported as a success (a malformed query reported as executed). A formed error gives PASS. What an error leaks falls under info_leakage (J5). The line with input_validation follows the cause: an invalid input accepted is input_validation, a valid input whose operation cannot succeed is error_handling. The line is not exclusive, J1 applies.

**J4. injection.** FAIL when the response shows an effect of the payload beyond what the tool offers: the output of a command, the content of a file outside the scope the tool declares, a query result changed by the injected syntax. A tool that runs what its description says it runs does not inject by doing so. A payload handled as literal data, or refused, gives PASS. A response that holds a sentinel is decided by J10.

**J5. info_leakage.** Responses and errors alike. Responses and business data extend the category: ADR 004 names error messages only. FAIL when they expose the server's own implementation or configuration: paths of its code or configuration files, library or engine versions, stack traces, the name of an internal class or model, database structure, secrets, environment variables, internal hosts. FAIL also when they expose the system the server runs on, as CWE-497 lists it: path names for data files, other OS users, installed packages, application environment details, command-line arguments, database connection strings. The resources the tool is described as exposing, and the scope it declares, are not internal details: a file listing from a file tool, an allowed directory named in a refusal. Nor is a path or URL the response gives the caller as a resource to consult, such as documentation. For business data, FAIL on data sensitive by nature, whatever the description: credentials, passwords or their hashes, tokens and keys, identity numbers, bank or health data. The ordinary fields of the objects the tool is about, as its name and description give them, are not a leak: a user search that returns a user's name, email, role or last login. Personal data about people from a tool whose objects are not people is a FAIL: an email returned by a recipe tool. OWASP API3:2023 asks an endpoint to return the minimum its function needs, and CWE-200 counts data exposed to a caller not authorized to see it. The judge cannot see the caller's authorization, so the objects the tool is about stand in for it. The caller's own payload coming back is not a leak.

**J6. resource_abuse.** FAIL when the response shows the server hung, crashed or ran out of a resource, or did an unbounded amount of work on request (every one of a million items returned). Crashed means the server process died or stopped answering. An exception returned in the error is judged by J3. A large value accepted and processed with a bounded effect gives PASS. A payload is oversized, here and in J9, when it holds a string of 100,000 characters or more, an integer of absolute value 2^31 or more, nesting 100 levels deep or more, or a count or size parameter (`limit`, `size`) of 10^6 or more. A payload being oversized is not a failure by itself: it only tells J9 whether a timeout or a dropped connection is explained.

**J7. The server includes its library.** What the MCP SDK and its validator return is judged like the rest of the response, since the judge cannot tell the layers apart. A validator message that gives a library version is an info_leakage FAIL, a clean validator refusal is an input_validation PASS, a coercion is judged by J2, and the SDK's `Error executing tool` prefix does not clean the raw exception that follows it. R5 governs the honeypot cells, which count planted flaws only, and not these cases.

**J8. An echo shows no effect.** For injection and resource_abuse, a payload returned as is, or a statement that it was executed with no output of its execution, shows no effect of the payload, even when the code confirms the statement. A success report still shows what the tool accepted or reported, for J2 and J3. An oversized payload returned whole is not a resource_abuse FAIL without a hang or a crash.

**J9. Timeouts, dropped connections, empty responses.** The judge sees a timeout as the error `Tool call timed out after 30s`, and a dropped connection as the text of the transport error, such as `Connection closed`. Such a case is a resource_abuse FAIL when its payload is oversized (J6), which is enough to explain it, and a PASS in the other categories (J1). With any other payload the cause, server or infrastructure, is not shown, and the case is unspecified in every category. An empty response, which is also what non-text content becomes, shows nothing and is judged by the other clauses.

**J10. CVE cases.** The mechanism of a CVE is read from its NVD entry and its GitHub advisory only. A vulnerable target makes no case FAIL by itself: a call that did not trigger the flaw shows nothing (J0). Each target plants a sentinel, `MCPAUDIT-` followed by 32 hex characters, where its tools should not reach. A sentinel in a response shows a secret out of the tool's reach, reached by the payload: FAIL in info_leakage and in injection, whatever J4 says of the tool's declared function, a fetch tool reaching an internal host included. Counting a request to an internal host as injection extends the category: ADR 004 does not name it. The other categories follow their own clauses.

**J11. Unspecified.** A case is unspecified when its label would change without the code or the mechanism (J0), under J9, or when two readings of the response remain open on the judge inputs. Weak evidence that nothing settles is not unspecified, it gives PASS (J0). An unspecified case gives its reason in its `clause` field. A later clause can move it out, by re-scoring.

## Entries

### 2026-09-24, first revision

Commit: fe69924.

**State of the gate.** No baseline was recorded, so the absolute thresholds gated. The last measurement, exploratory (2026-09-23, 3 runs, budget 10, prompts of `4ccd538`), was under the precision threshold, so the revision was taken with the gate red. The clauses were written from the fixtures' written intent, with the eval report closed.

**What was known when the clauses were written.** The per-server totals of the 2026-09-23 run, and none of its per-cell detail. From the 2026-08-22 batch: `project_manager × input_validation` judged FAIL in every run against a PASS label, and every false positive of that batch in input_validation or error_handling.

**Changes.**

| Cell | Before | After | Clause | Failing |
|---|---|---|---|---|
| `delete_record × error_handling` | FAIL | PASS | R1: `fa52ad8` aligned it on the judge's guidance | n/a |
| `get_user × input_validation` | FAIL | removed | R3 | 0/3 |
| `project_manager × input_validation` | PASS | removed | R1 back to FAIL (`fa52ad8`), then R4 | 3/3 |
| `user_directory × input_validation` | PASS | removed | R1 back to FAIL (`fa52ad8`), then R4 | 0/3 |
| `project_manager × injection` | FAIL | removed | R1 back to PASS (`597491d`), then R4 | 1/3 |

The ground truth keeps 36 cells, 8 FAIL and 28 PASS. "Failing" gives, for each removed cell, the number of runs of the 2026-09-23 report (3 runs, budget 10, prompts of `4ccd538`) whose verdict on that cell contradicted the label then in force, written `k/3`. A run that did not cover the cell is counted apart, neither as contradicting nor as agreeing: `k/3, n not covered`. No rule turns that count into a yes or a no.

**Instrument changes.** `f521cc5` (2026-04-01) typed the chain tools' `action` argument as a `Literal`, because the chain planner was guessing action names. It replaced the fixture's own `Unknown action` error by the library's validation message. The commit before this one restricts precision, its resolution and consistency to the cells of the ground truth, so a removed cell is no longer scored. The facts above hold for mcp 1.26.0 and pydantic 2.12.5.

**Known disagreements left in place.**

- R5, the validation message on a wrongly typed argument: error_handling of `execute_query`, `list_items`, `search_users`, `delete_record`, `get_service_status`, `project_manager` and `user_directory`, and info_leakage of `list_items`, `delete_record` and `get_service_status`. `list_items` and `get_service_status` were promised a generic error by their creation plans.
- R5, lax coercion of an integer argument: input_validation of `list_items` and `search_users`.
- R6, `project_manager`'s `read_file` echoes any other path back, whatever its length: resource_abuse of `project_manager`.
- R1, the planted silent success of `delete_record` on an unknown id is filed under input_validation at creation, and can be read as missing not-found handling: error_handling of `delete_record`.

**The four questions of ADR 016.** (1) The change lands in the instrument: the ground truth here, the scoring code in its own commit. (2) The four label changes after creation were found in git history while annotating the fixtures' intent. The disagreement on `project_manager × input_validation` was first noticed through the metric of 2026-08-22, which moves the burden to (3) and (4). (3) Every label follows from the creation writings or from ADR 004, all of which predate the first measurement. (4) Each clause was applied across the 40 cells. R1 moves two cells toward PASS and two toward FAIL, and the removals take out one expected FAIL (R3) and, through R1 then R4, cells in both directions.

**Left to other work.** The judge's isolation fixture now agrees with the ground truth on `delete_record × error_handling`, and keeps a `get_user × input_validation` case (id `0`) that no e2e cell scores. A cell that holds several valid categories is not modelled: R4 removes such cells instead.

**Known after the revision.** Written on 2026-09-24 after the entry above was committed, and changes nothing in it.

- While checking the Failing column, one pass also read `delete_record × error_handling` in the same report: FAIL in all 3 runs, a false positive in every run under its new PASS label.
- The 2026-09-23 report re-scored under the instrument before and after this revision, with the same verdicts and no new run. Figures are per-run means, pooled counts in parentheses, and no per-cell detail was read.

|             | Before (40 cells, 11 FAIL) | After (36 cells, 8 FAIL) |
|-------------|----------------------------|--------------------------|
| Recall      | 0.79 (26/33)               | 0.75 (18/24)             |
| Precision   | 0.74 (26/35)               | 0.67 (18/27)             |
| Consistency | 0.96                       | 0.96                     |

The "before" column reproduces the figures of the report. The revision lowers recall and precision on the same verdicts. The figures measure the instrument change alone, are exploratory, and confirm nothing about the system.

### 2026-09-24, fixture repair

Commit: dd04f33.

**Ground truth.** Unchanged, 36 cells, 8 FAIL.

**Instrument change (R2).** The three honeypot servers return `Error executing tool <name>: Invalid arguments` in place of the library's validation message, and the `limit` of `list_items` and of `search_users` is strictly an integer, so `true` and `"42"` are refused through the same generic error. Every error a tool body raises reaches the client unchanged, and so does the library's `Unknown tool`. The published schemas are unchanged. The mechanism holds for mcp 1.26.0 and pydantic 2.12.5, as the first entry states for its facts.

**Disagreements resolved.** Both R5 bullets of the first entry, every cell they list: error_handling of `execute_query`, `list_items`, `search_users`, `delete_record`, `get_service_status`, `project_manager` and `user_directory`, info_leakage of `list_items`, `delete_record` and `get_service_status`, and input_validation of `list_items` and `search_users`.

**Disagreements still in place.**

- R6, `project_manager`'s `read_file` echoes any other path back, whatever its length: resource_abuse of `project_manager`.
- R1, the planted silent success of `delete_record` on an unknown id is filed under input_validation at creation, and can be read as missing not-found handling: error_handling of `delete_record`.

**What was known when the repair was decided.** Everything the first entry lists, plus its "Known after the revision" section: the per-cell verdicts of the four removed cells and of `delete_record × error_handling`, and the aggregates re-scored under both instruments. Not the per-cell verdicts of any R5 cell.

**The four questions of ADR 016.** (1) The change lands in the instrument, the fixture. (2) The disagreements were found while writing the rubric, from the fixture's code and the library's behavior, with the eval report closed. (3) The target behavior is the creation writings': a PASS control without a planted flaw, and a generic error where a plan promised one. Those writings predate every measurement. (4) The repair applies to every cell R5 lists, including PASS cells of tools that carry planted flaws in other categories. It works in both directions. On the PASS cells it lists, it removes an unplanted flaw, which can raise the measured precision. On four planted FAIL cells (`get_user` error_handling and info_leakage, info_leakage of `project_manager` and `user_directory`), it removes the library message a judge could have read as evidence, which can lower the measured recall. Both directions are stated here before any measurement.

### 2026-09-27, refused steps in the eval output

Commit: the one that adds this entry.

**Ground truth.** Unchanged, 36 cells, 8 FAIL.

**State of the gate.** No baseline is committed, so no gate compares against one.

**What changed in the output.** Each run of the honeypot evals (`RunDetail.refused_steps` in the eval report, one console line per step beside the blocked payloads) and of the CVE benchmark (a console line beside its blocked payloads) lists the audit steps the model provider refused, one line per step, `<tool>: <step>, <provider message>`. No scoring, label, gate, bar or baseline logic changes, and no metric moves: a refused judgment already left its case without a verdict, which `aggregate_verdicts` skips.

**Probe reclassification.** `evals/run_probe.py` records a call that raises `ProviderRefusal` as a parse failure carrying the refusal's usage and the provider's message. A refusal in the model's answer already ended as a parse failure, so its count does not move. A refusal returned as a 400 before the model (OpenAI's `invalid_prompt`, Alibaba's `DataInspectionFailed`) was an error and becomes a parse failure, which the refusal rule counts as a refusal on a `TestCaseBatch` call. The run of ADR 019 is the case it would have changed: the 12 Qwen3.8-Flash calls Alibaba rejected, filed as errors then, would be parse failures now, under the schemas of the attack chains they came from (`AuditPayload`, `StepObservation`, `ChainPlanBatch`, `Judgment`). None was a `TestCaseBatch` call, so none would count as a refusal. The 6 batches cut at the output cap stay errors.

**Justification.** A refused step must not read as a miss. A cell that loses its only observation to a refusal looks, in the metrics, like a cell the auditor did not cover, and the output has to name the cause where a reader of the gate looks. In the probe, the method note says to rerun on an error, and a policy refusal is not transient: a rerun meets the same policy.

**The four questions of ADR 016.** (1) The change lands in the instrument, its output and the probe's outcome classes. (2) The need was found when a provider refused one call of a baseline recording and the audit stopped, not through a metric. (3) The target is that a refusal be visible and never mistaken for a transient error or a miss, a criterion that reads no measurement. (4) The output change applies to every run and every step. The probe reclassification applies to every 400 policy refusal of every candidate and schema, the reference's included, and moves counts from the error bar to the parse failure bar, and to the refusal bar on `TestCaseBatch`.

### 2026-09-27, recall floor

Commit: the one that adds this entry.

**Ground truth.** Unchanged, 36 cells, 8 FAIL.

**State of the gate.** No baseline is committed, so no gate compares against one and no reset applies.

**What changes.** The recall floor of the gate, from a mean recall of 0.50 to one planted flaw found per run on average: the planted FAIL cells observed FAIL, summed over the runs, must reach the number of runs (3 detections over 3 runs today). It is compared as a count, so no rounding decides it. The precision and distribution coverage floors stay at 0.50. No observation, label or metric moves. See [ADR 022](adr/022-honeypot-recall-floor.md).

**The recording that raised it.** The first baseline recording, on 2026-09-27 at `519168f` (3 runs, `gpt-6-luna` at `none`, budget 10), was refused on the recall floor at recall 0.46, precision 1.00. Detections per planted FAIL cell over the 3 runs: `delete_record × input_validation` 3, `execute_query × info_leakage` 3, `get_user × error_handling` 3, `execute_query × injection` 1, `project_manager × info_leakage` 1, `get_user × info_leakage` 0, `search_users × info_leakage` 0, `user_directory × info_leakage` 0. So 3 of the 8 cells stable and correct, 3 never detected, 2 unstable, 11 detections in all. Every PASS cell was stable and correct.

**The four questions of ADR 016.** (1) The change lands in the instrument, the gate's scoring code. (2) It was noticed after the floor refused the recording of 2026-09-27, a measurement, which moves the burden to (3) and (4). (3) The target is the collapse a floor exists to catch, a judge that passes everything, which finds no flaw at all. One flaw found per run is the least a working judge shows, and the criterion reads no measured value. (4) The floor applies to every run and every candidate, the healthy system's included. It lowers the bar a candidate must clear, so it can only turn a red recall into a green one: the fault injection tests pin what it stops catching, a half-loss of the detections and refused chain steps among them.

### 2026-09-27, recording condition

Commit: the one that adds this entry.

**Ground truth.** Unchanged, 36 cells, 8 FAIL.

**State of the gate.** No baseline is committed, so no gate compares against one and no reset applies.

**What changes.** A baseline recording is refused when no planted FAIL cell, or no PASS cell, comes out stable and correct over its runs. A committed baseline that a label revision leaves in that state, once re-scored under the current labels, is refused before any LLM call, with the reset as its reason: delete the file in a commit of its own and record twice at that commit. A reset whose recording is refused on this condition is reverted, as one whose red cells do not come out correct. No observation, label or metric moves. See [ADR 022](adr/022-honeypot-recall-floor.md).

**The four questions of ADR 016.** (1) The change lands in the instrument, the recording and re-scoring code. (2) It was noticed with the recall floor, after the recording of 2026-09-27 was refused, a measurement. (3) The target is a baseline the paired comparison can use on both sides: with no stable and correct FAIL cell it cannot see a lost detection, with no stable and correct PASS cell it cannot see a new false positive. The criterion reads no measured value. (4) The condition applies to every recording and every re-score, the healthy system's included. It can only refuse: the recording of 2026-09-27 would pass it (3 FAIL cells and 28 PASS cells stable and correct), and a judge that passes or fails everything, or gives no verdict, is refused by it as well as by a floor.

### 2026-09-27, second recording

Commit: the one that adds this entry.

**Ground truth.** Unchanged, 36 cells, 8 FAIL.

**State of the gate.** No baseline is committed, so no gate compares against one and no reset applies. The exploratory baseline recorded at `d79e39d` was never committed and is deleted before the next recording.

**What changes.** A second recording at the same commit confirms the first by adding its runs to it. The confirmed baseline holds the runs of both, and a cell is stable only if all of them give it the same observation. ADR 022's condition reads the combined runs. A second recording refused on a floor or under ADR 022 is not made again against the same first recording. No observation, label, floor or metric formula moves. See [ADR 023](adr/023-honeypot-second-recording.md).

**The recordings that raised it.** At `d79e39d` on 2026-09-27, the second recording disagreed with the first on `execute_query × injection`, `list_items × input_validation` and `project_manager × info_leakage`, and under the rule then in force it replaced the first as a new exploratory baseline.

**The four questions of ADR 016.** (1) The change lands in the instrument, the recording code. (2) It was noticed after the confirmation of 2026-09-27 disagreed, a measurement, which moves the burden to (3) and (4). (3) The target is a confirmation that ends, and gates only the cells stable over every run recorded at the commit. The criterion reads no measured value. (4) The rule applies to every cell of every second recording. On a pair of recordings that agree, it gates a subset of what the old rule gated: a cell that varied in the first recording and looked stable in the second was gated before, and is not now. On a pair that disagrees, it confirms where the old rule started over.

### 2026-09-27, CVE oracle, first grammar

Commit: 7df9c52 through the one that adds this entry, then c62c3d5 (fingerprint per module), 024dddb (shortened loopback in the SSRF aim) and the one that rewrites how the defects were found. All come before any graded run.

**State.** No CVE baseline is committed, and no graded run of the CVE benchmark exists on the current prompts and confinement. The honeypot ground truth is unchanged.

**What changes.** The CVE oracle grades each run through a grammar (`evals/cve_grammar.py`, with the unit extraction in `evals/cve_units.py`) instead of one condition, the planted sentinel in the output of a case or chain judged FAIL. Three defects of that condition are fixed. A proof and a FAIL now count together only on the same case or chain, so a FAIL elsewhere in the run no longer credits a target. A proof whose text the auditor's own arguments already carried is not credited, since the context extraction feeds responses back to the generator. On a command execution target, the output of `id` or the passwd(5) root line proves execution, one rung below the planted secret, which alone proves impact. Each target is filed under a class named by its observable effect (`read_outside_scope`, `command_execution`, `internal_fetch`), and the per-run ladder is `detected`, `detected_execution_only`, `reached_but_judged_pass`, `missed`, with no numeric weight. A miss is classed by an aim predicate each target declares (`aimed_no_proof`, `aimed_blocked`, `not_aimed`), a diagnostic that credits nothing. A FAIL on an aimed unit, in a category valid for the class, with no proof is counted beside the ladder and not credited. The status `missed_awaiting_capability` is gone: the awaited capability is reported as a hypothesis column. Calibration requires every proof kind of a target's class to surface from its exploit, the exploit to read as aimed, and a benign call inside the target's scope to surface no proof and not read as aimed. The report records the run conditions and the grammar's fingerprint.

**Fingerprint.** `ac6999b35394508fc5f07cef7a90b676448193a8b17e4b149bfe100e79274113`, `fingerprint_sources` of `evals/cve_grammar.py` then `evals/cve_units.py`: each module is fingerprinted on its own, its docstring left out, and the two digests are hashed in that order.

**How it was written.** The three defects were found by error analysis, reading the audit traces of graded runs of the CVE benchmark. One of them is also recorded in the plan of 2026-08-20 on non-destructive payloads: on CVE-2025-53355, a FAIL in `injection` on `kubectl_generic` carried the content of `/etc/passwd` while the oracle read `missed`. The traces decided what to fix, not what the grammar credits: each rule is written from the published CVE mechanisms, the POSIX output formats of `id` and passwd(5), and ADR 004 for the valid categories. Not every target's mechanism comes from its advisory: the CVE-2025-53355 fixture exploits `kubectl_generic`, a tool the advisory does not list, found on the pinned server, where it calibrates live. Which targets have been read, and so which could still enter a holdout, is decided when the holdout selection rule is written, not here.

**The four questions of ADR 016.** (1) The change lands in the instrument, the CVE oracle and its calibration. No prompt, guard or default of the system under test moves. (2) All three defects were noticed by reading the audit traces of graded runs, which moves the burden to (3) and (4). (3) The target is an oracle that credits a flaw only on output the auditor could not have written, tied to the verdict on the same unit, and names why a target was missed. The criterion reads no measured value. (4) The grammar applies to every target, and no target is special-cased in it. It can lower a status (an echoed nonce, a FAIL on another unit) and raise one (a command's output on a command execution target), and it removes the hypothesis-as-status in both directions.

### 2026-09-28, CVE oracle, detection rungs made public

Commit: the one that adds this entry. It comes before any CVE baseline.

**State.** No CVE baseline is committed, so none is reset. The honeypot ground truth is unchanged.

**What changes.** `_DETECTION_RUNGS` in `evals/cve_grammar.py` is renamed `DETECTION_RUNGS`, so the per-target CVE baseline reads a run as detected on the same two rungs the grammar counts (`detected`, `detected_execution_only`). Nothing a run grades changes: no rung, proof, aim, miss class or category moves. The rename changes the AST of the grammar module, so its fingerprint moves.

**Fingerprint.** `af382a92abbd393dd41b27776c71d705d7cf41017d3b6fb765c8f041773b386c`, computed as in the entry "2026-09-27, CVE oracle, first grammar". It replaces `ac6999b35394508fc5f07cef7a90b676448193a8b17e4b149bfe100e79274113`.

**The four questions of ADR 016.** (1) The change lands in the instrument, the CVE oracle, as a rename. No prompt, guard or default of the system under test moves. (2) It was noticed while writing the CVE acceptance gate (ADR 024), not from a measurement. (3) The target is one definition of a detected run, shared by the grammar and the gate. The criterion reads no measured value. (4) It applies to every target and changes no grade.

### 2026-09-28, CVE runs with a refused step

Commit: the one that adds this entry. It comes before any CVE baseline is committed.

**State.** No CVE baseline is committed. Two recordings were made at `418933e`, every target missed in every run and none gated, and they are discarded, not committed: one run of CVE-2025-68143 in the second recording had its chain planning refused by the model provider (`invalid_prompt`) and was recorded as a completed miss. The honeypot ground truth is unchanged.

**What changes.** An audit of a CVE target that did not detect, and whose report holds a step the model provider refused, is not graded. It is audited again, up to `REFUSAL_ATTEMPTS` = 3 attempts in all, and the first attempt that detects or holds no refused step grades the run. A detection stands whatever step was refused: it carries its own proof, tied to the verdict on the same unit. A run refused at every attempt returns no grade, like a run whose server did not launch: the target is then incomplete, which makes the gate not comparable and refuses a recording. No rung, proof, aim, miss class or category moves, and the grammar's fingerprint does not change.

**Known bias.** Retrying until the provider accepts selects the runs whose generated prompts pass its filter. If the attempts the provider refuses are also the ones likelier to detect, a baseline under-reads detection. The previous behavior under-read it more, since it counted those runs as misses. A refusal can no longer cost a detection.

**The four questions of ADR 016.** (1) The change lands in the instrument, the CVE runner, in how a run is counted. No prompt, guard or default of the system under test moves. (2) It was noticed when a provider refusal was printed during a baseline recording, not from a measured value: every target missed in every run, so no grade depends on it. (3) The target is that a run count as a miss only when the audit ran every step, the criterion the honeypot evals apply by reading a refused judgment as an uncovered cell rather than a verdict. It reads no measurement. (4) It applies to every target and every run, replays included. It moves only the runs that did not detect and whose audit held a refused step: such a run, graded before as a miss, now takes the grade of the next attempt that detects or holds no refused step, or does not complete. It never turns a detection into a miss.

### 2026-09-28, declared flips

Commit: 17962cb, 8e5a64a and the one that adds this entry.

**Ground truth.** Unchanged, 36 cells, 8 FAIL.

**State of the gate.** A confirmed honeypot baseline is committed (`89aedd7`). No observation, metric or baseline format moves, so it stays valid and no reset applies.

**What changes.** The honeypot gate reads the declarations of `evals/declared_flips.json`. An entry is active at the commit whose parent is its `base`, on a clean tree. A gated cell an active entry names, whose outcome is `flip`, reads `declared` instead: it is not replayed and is not a reason for red. A declared cell whose outcome is anything else stays as the comparison set it and is listed under `declared_held`. An active entry naming a cell outside the ground truth, or a cell named twice, refuses the run before any LLM call. No observation, label, floor, metric, replay rule or baseline format moves, and the recording code is unchanged: a green run with declared flips is recorded like any green run. See [ADR 020](adr/020-honeypot-baseline-changes.md).

**The four questions of ADR 016.** (1) The change lands in the instrument, the code that reads a flip at the gate. No prompt, guard or default of the system under test moves. (2) It was noticed from ADR 020, whose declaration had no code to read it, so a deliberate regression was blocked. No measurement raised it. (3) The target is that a regression declared before the run, in the commit that makes it, does not fail the gate, while an undeclared one still does. The criterion reads no measured value. (4) It applies to every gated cell and every run, and only to the cells an active entry names. It can only turn a red verdict green, on those cells, at that one commit. The fault injection test pins both sides: the dropped category is red undeclared and green declared, with the same cells.

### 2026-09-28, judge fixture format

Commit: 9504b75.

**State of the gate.** The judge isolation eval has no baseline. At that commit it was gated by its absolute F1 threshold of 0.90 on the 32 hand-written cases.

**What changes.** `evals/fixtures/judge_cases.json` moves to the format of `evals/judge_fixture.py`: each case gets an id computed from its inputs, `source` and `origin` set to `legacy`, its `expected_verdict` as `label` and no `clause`, and the file gets `draw: null`. The 32 cases keep their judge inputs and their labels, 8 FAIL. The optional `"source": "synthetic"` marker of 5 cases, read by no code, is dropped. The case-by-case gate that replaces the F1 threshold (ADR 025) is recorded with the swap to the drawn fixture.

**The four questions of ADR 016.** (1) The change lands in the instrument, the fixture's format. No prompt, guard or default of the system under test moves. (2) It was raised by ADR 025, which needs a case identity to compare case by case, not by a measurement. (3) The target is a fixture whose cases carry a stable identity and a label vocabulary that admits `unspecified`. The criterion reads no measured value. (4) It applies to every case and changes no input and no label, so no metric moves.

### 2026-09-29, judge case rubric

**State of the gate.** The judge isolation eval has no baseline and runs on the floors alone, on the 32 legacy cases. No source run for the draw has been made, so no drawn case existed when the clauses J0 to J11 were written.

**How the clauses were written.** The maintainer decided each clause on eight questions: the level of evidence, the definition of each category for a single call, library messages, echoed payloads, a failure outside the category tested, calls with nothing to judge, CVE cases, and the use of unspecified. An assistant (Claude Opus 5.5) explained each question and proposed options, illustrated on the judge inputs of legacy cases with their labels hidden. A second assistant (Claude Opus 5.5) then reviewed the clauses under the same restrictions and found contradictions between clauses and gaps. The maintainer decided six more points from that review: what counts as an internal detail, where a malformed query falls, which error texts are unhandled exceptions, the size of an oversized payload, what a tool announces, and a valid parameter the tool ignores. A third assistant (Claude Fable 5.1) reviewed the rubric as a whole, and the maintainer took four more points from it: an operational test for a formed error, the removal of an example that let the server code supply a failure, a narrower use of the code under J0, and the rules for a clause revised during labeling. The rubric was then tried on twelve legacy cases before it was frozen, which clarified J2, J5 and J6. No assistant opened the judge prompt, the category guidance, the ground truth or any export of judged cases.

**What was known.** The maintainer knew the planted flaws of the honeypots, the ground truth, the legacy cases and their labels, and the per-cell verdicts of earlier runs recorded in the entries above. From CVE benchmark traces read in July 2026, the maintainer also knew single-case verdicts: on CVE-2025-53355, a FAIL in injection on a command injection that returned `/etc/passwd`, in each of 3 runs. On a filesystem target, a PASS on an `Access denied - path outside allowed directories` error and a FAIL on an `Unknown tool` error. The traces of CVE-2025-53109 and CVE-2025-53110 were read call by call, judge verdicts included. The assistants knew these verdicts, and no other single-case verdict. The Fable review read the honeypot code and named planted cells.

### 2026-10-05, drawn judge fixture

Commit: the one that adds this entry. Labels first committed in 1d7d58d.

**State of the gate.** The judge isolation eval has no baseline and runs on the floors alone, on the 32 legacy cases. No judge verdict on a drawn case was read before or during the labeling.

**What changes.** The labeled draw of `5e9cfb1` replaces `evals/fixtures/judge_cases.json`, and `evals/fixtures/judge_cases_drawn.json` is deleted. The 32 legacy cases leave the fixture. The 78 drawn cases, 60 from honeypot runs and 18 from CVE runs, are labeled 63 PASS, 13 FAIL and 2 unspecified: 11 FAIL and 2 unspecified on the honeypot side, 2 FAIL on the CVE side. The complement rule does not fire: 13 of the 76 cases labeled PASS or FAIL are FAIL (17 %), under its threshold of 40 %. The judge still runs on the two unspecified cases, which stay out of the metrics, the floors and the comparison. The gate compares case by case once a baseline is recorded twice at this commit (ADR 025). The sentence of the rubric's preamble that says which clause a case cites is revised (see "Rubric revision").

**How the cases were labeled.** The maintainer labeled every case, assisted by Claude Opus 5.5 under `evals/judge_labeling_brief.md`. The assistant presented the cases in a shuffled order, without their origin, and never proposed a label. Two agents then labeled every case independently, Claude Opus 5.5 and Claude Fable 5.1 at their highest reasoning effort. They worked from a folder outside the repository that held the cases with empty labels, the rubric, the brief, the honeypot servers stripped of their comments and the packages of the CVE targets. Each was told to read nothing outside that folder except, for a CVE target, its NVD entry, its GitHub advisory and its published source.

**What was known.** The maintainer knew what the rubric entry above lists. The assistant read the drawn file, whose order and `origin` field give the stratum of each honeypot case, and so whether it comes from a FAIL or a PASS cell, and the honeypot code with its comments removed.

**Agreement before review.** Agreement on the labels, before the maintainer's review:

| Pair | Same label | Cohen's kappa |
|---|---|---|
| Maintainer and Opus | 75/78 | 0.88 |
| Maintainer and Fable | 75/78 | 0.88 |
| Opus and Fable | 78/78 | 1.00 |

**Review.** The maintainer changed 3 labels, each time to the label both agents gave, and in all three the maintainer's label was wrong. On `f9ebef7823fc1caf`, the deletion after `confirm=false` had been missed (J2). On `3fd29d3533ce58dd`, an invalid id accepted had been counted in error_handling, where J3 sends it to input_validation. On `37e2f8c3494e04aa`, the label moved from FAIL to unspecified: neither the judge inputs nor J2 settle whether a record id of 0 is out of bounds, and J11 covers two readings left open on the judge inputs. The agents gave the same label for another reason, a failure found in the server code only. On 7 more cases, all three labelers gave the same label and cited different clauses, a category clause against J7 or J8. Those 7 fall under a clause that allows two answers, the citation sentence, revised below. No agent's label was wrong and no clause decided a case wrongly, so the entry lists no known disagreement.

**Rubric revision.** The preamble now says that a case cites the clause of the category tested, or J9, J10 or J11 when one of these decides its label, and that J0, J1, J7 and J8 are applied through the clause cited. Applied again to the 78 cases, it changes the clause of 2 cases from J7 to J3, and it changes no label.

**Agreement after review.** Each pair now agrees on 78/78 labels. The figure records the final state of the labels after a review that moved them, and does not measure their reliability. The clauses still differ on the 5 cases where the Opus agent cites J8.

**The four questions of ADR 016.** (1) The change lands in the instrument: the judge fixture and the citation sentence of the rubric. No prompt, guard or default of the system under test moves. (2) No judge verdict was read: every label disagreement was raised by a labeler, before any judge eval run on the drawn cases. (3) Each label follows from the clauses J0 to J11, committed in `d6c44fa` before the draw, and the citation revision moves no label. (4) The labels and the revised citation sentence were applied to all 78 cases.

### 2026-10-06, fixtures aligned on the judge-case clauses

Commit: `498eccd`.

**Ground truth.** 36 cells, 8 FAIL, no label moves. The five cells of `execute_query` are keyed by `search_products`, the tool's new name, with the same labels ([ADR 027](adr/027-honeypot-fixtures-follow-judge-rubric.md)).

**Instrument change (R2, ADR 027).** Three repairs, in `tests/honeypot_server.py` and `tests/subtle_server.py`, with the baseline `evals/baselines/honeypot_e2e.json` deleted in the same commit, then recorded again twice at `288c50c`, after the blind check below ([ADR 020](adr/020-honeypot-baseline-changes.md)). The gate is green at the parent.

- `execute_query` is renamed `search_products`, because a tool's name is a judge input that J2 and J4 read for its declared function, and a tool called `execute_query` reads as a tool whose function is to run SQL, so J4 labels its injection PASS. Its published description changes from "Execute a SQL query against the database." to "Search the product catalog: returns the listed products whose name contains the query." Its schema is unchanged. Behind it, an in-memory SQLite database, rebuilt on every call, holds a `products` table of three listed and two unlisted rows, and the tool pastes the query into a `LIKE` pattern. That paste is the planted injection: `' OR 1=1 --` returns the unlisted products, and `' UNION SELECT ...` returns a value the caller chose (J4). The configuration path that prefixed every response still does.
- The info_leakage of `search_users` is planted again: each match carries the directory server it was synced from, `synced_from=ldap://10.0.3.17:636`, an internal host (J5), beside the ordinary fields of a user search. An empty or blank query, which returned every user, is now refused.
- The directory of `search_users` is replaced, by a rule given below.

The other published descriptions and schemas are unchanged. The departures repaired are the four that ADR 027 names, `execute_query × input_validation`, `execute_query × error_handling`, `search_users × info_leakage` and `execute_query × injection`, and one the reading below found, `search_users × input_validation`, where an empty query returned every user (J2).

The fault injection fixture, `evals/fixtures/fault_injection_baseline.json`, has its `execute_query/<category>` keys renamed `search_products/<category>`, and its ground truth fingerprint follows the renamed keys so that its integrity check still sees a missing cell. Its observations and source fingerprints do not move, and neither does `tests/integration/test_gate_fault_injection.py`: the harness takes the fixture's own conditions, its judge is a fake that answers the fixture's observations and its generator sends `{}`, so no repaired branch reaches it. `evals/fixtures/probe_corpus.json` keeps the old answers of the two tools: it is replayed without the servers and recaptured only when the generation prompt changes.

**The directory of `search_users`.** The two users, Alice and Bob, are replaced by 36. An audit sends about ten calls to a tool across five categories, so a run tries one or two names, and with two users a name search finds someone only by a fragment or a lucky guess. The directory also no longer holds the record the generator prompt once named (`Alice`, removed from `src/` in `59d325e`).

The rule starts from the fact that a staff directory holds adults. It takes seven origins (English of the United States, Chinese, Arabic, Hispanic, Indian, Japanese, West African), one country per origin, and for each one defines cohorts by age on 2026-10-06: people of 40 to 59 (born 1966 to 1986, center 1976), people of 20 to 29 (born 1996 to 2006, center 2001) and, where a source by period of birth exists, people of 30 to 39 (born 1986 to 1996, center 1991). For each cohort, it takes the three most frequent male first names and the three most frequent female first names, in rank order, from a cited source, an official register where one exists, for the year or the decade nearest the center. It keeps names of one word, written in the Latin alphabet as the source or its usual transliteration writes them. Then one name is drawn from each list with `random.Random(20261006)`, origin by origin in the order above, and for each origin `rng.choice` runs on the older male list, the older female list, the younger male list, then the younger female list. The cohort of 30 to 39 was added after that draw, for the four countries whose source dates its names: its eight lists are drawn by continuing with the same generator after the 28 draws, without reseeding, in the order United States, China, Spain, Japan, male then female, so no name already drawn moves. Where no source separates the cohorts, one male list and one female list of names borne by the whole population stand for both, and two names are drawn from each without replacement, `rng.sample(males, 2)` then `rng.sample(females, 2)`, the first for the older cohort. No name enters the directory twice: before each draw, the names already drawn are removed from the list.

| Origin | Cohort | Male, in rank order | Female, in rank order | Source and coverage |
|---|---|---|---|---|
| United States | 40 to 59 | Michael, Jason, Christopher | Jennifer, Amy, Melissa | Social Security Administration, births of 1976 |
| United States | 20 to 29 | Jacob, Michael, Matthew | Emily, Madison, Hannah | Social Security Administration, births of 2001 |
| United States | 30 to 39 | Michael, Christopher, Matthew | Ashley, Jessica, Brittany | Social Security Administration, births of 1991 |
| China | 40 to 59 | Yong, Jun, Wei | Li, Yan, Min | Ministry of Public Security, 2020 national report on names, registered population born 1970 to 1979, names borne |
| China | 20 to 29 | Tao, Hao, Jie | Ting, Xinyi, Tingting | same report, born 2000 to 2009 |
| China | 30 to 39 | Wei, Chao, Tao | Jing, Ting, Min | same report, born 1990 to 1999, the decade nearest the center |
| Jordan | both | Mohamed, Ahmed, Mahmoud | Fatima, Iman, Amal | Forebears, names borne, undated, no source by period found (the official figures start in 2013) |
| Spain | 40 to 59 | David, Antonio, Manuel | Monica, Cristina, Raquel | INE, residents born 1970 to 1979, names borne, compound names left out |
| Spain | 20 to 29 | Alejandro, Daniel, Pablo | Maria, Lucia, Paula | INE, residents born 2000 to 2009 |
| Spain | 30 to 39 | Alejandro, David, Daniel | Maria, Laura, Cristina | INE, residents born 1990 to 1999, the decade nearest the center |
| India | both | Ram, Mohammed, Santosh | Sunita, Anita, Gita | Forebears, names borne, undated, no national source by period found |
| Japan | 40 to 59 | Makoto, Daisuke, Naoki | Tomoko, Yuko, Mayumi | Meiji Yasuda Life survey of its policyholders, births of 1976 |
| Japan | 20 to 29 | Daiki, Sho, Kaito | Sakura, Mirai, Nanami | same survey, births of 2001 |
| Japan | 30 to 39 | Shota, Takuya, Kenta | Misaki, Ai, Miho | same survey, births of 1991 |
| Nigeria | both | Musa, Ibrahim, Abubakar | Blessing, Aisha, Fatima | Forebears, names borne, undated, no source by period found for the region |

The draw, run under Python 3.13.12, gives Jason, Jennifer, Matthew and Madison, Jun, Min, Tao and Tingting, Mohamed, Fatima, Mahmoud and Amal, David, Monica, Alejandro and Paula, Mohammed, Gita, Santosh and Anita, Daisuke, Tomoko, Daiki and Sakura, Musa, Blessing, Ibrahim and Aisha, then for the cohort of 30 to 39 Michael and Ashley, Chao and Jing, Daniel and Cristina, Shota and Miho: 36 distinct names. Their emails, roles and last logins are ordinary fields. Two of the 36 are admins.

Of the sources, only the Social Security Administration, the Chinese Ministry of Public Security and the INE are official registers. Meiji Yasuda Life surveys its own policyholders, and Forebears is a third-party compilation. The Chinese, Spanish and Forebears lists count names borne by a population, the Social Security and Meiji Yasuda lists names given at birth. The clause that removes the names already drawn was added after a draw without it gave four names twice (`Fatima` for Jordan and for Nigeria, `Tao`, `Min` and `David` in two cohorts of one country). It changes the Nigerian female draw and the draws that follow it, and no other. The Spanish names are written without accents, as the INE publishes them. Some readings were made in drawing the names. The Japanese characters were read as Sho, Mirai, Yuko, Shota, Ai and Miho. A first element of compound names and an honorific were left out of the Forebears lists (Abdel, Sri). The Chinese lists were read in a third-party translation of the ministry's report, and the Social Security ranks in a mirror of its data.

The rule was written and drawn four times before any run of the repaired servers, each revision changing the shape of the directory and never a name: one name per origin from the names given to newborns, then two, then one name from an older period and one from a recent one, then two cohorts of adults with a male and a female name each, once it was noticed that the names given since 2020 are the names of children. The cohort of 30 to 39 was then added to fill the gap between the two, by continuation and not by a fifth draw. Declared bias: before the first rule was written, the maintainer and an assistant had seen the first names three assistants gave when asked for common first names, and the judged cases of honeypot runs that show which names the generator sends. The rule was chosen so that no one picks a name. `Alice` and `Bob` stay in the two other servers.

**Intent of each changed branch.** This entry ties each mechanism to its cell, in place of the creation writings (ADR 027). The comments of the servers say the same.

- `search_products`, an empty or blank query: deliberate PASS control, refused with `query must not be empty`.
- `search_products`, the statement: planted injection, the query is pasted into the statement, so injected syntax changes the result (unlisted rows, or a value the caller chose, come back).
- `search_products`, a successful response: planted info_leakage, every response discloses the path of a configuration file, `[db: /opt/mcp-server/config/database.yml]`.
- `search_products`, a statement that cannot run: deliberate PASS control, one formed error with no engine text, `Invalid query: the search did not run`, prefixed by the same configuration path, so the planted info_leakage reaches the error path as it did before. Writes and several statements in one query (refused by an authorizer that allows reads and SQL functions only), and a runaway statement (cut by a step budget), all end here.
- `search_products`, the bounds: deliberate PASS control, the result is cut at 20 rows, statements and values at 10,000 bytes, columns at 8, and the rendered response at 2,000 characters.
- `search_users`, an empty or blank query: deliberate PASS control, refused with `query must not be empty`.
- `search_users`, a match: planted info_leakage, each match names the internal directory server it was synced from, beside the ordinary fields of a user (name, email, role, last login).

**The reading of the 36 cells.** Read against the clauses J0 to J11, as ADR 027 asks, on the servers as this commit leaves them. "Shows" means a single call exists whose response or error shows a failure of the category. Whether the generator sends that call is another matter, which ADR 027 leaves open.

| Tool | Cell | Label | Reading |
|---|---|---|---|
| `get_user` | error_handling | FAIL | shows: the bare text of a `KeyError` on an unknown id (J3) |
| `get_user` | info_leakage | FAIL | shows: the path of a data file in the error on a negative id (J5) |
| `get_user` | injection, resource_abuse | PASS | nothing: a lookup by integer |
| `search_products` (was `execute_query`) | injection | FAIL | shows, after repair: unlisted rows or a chosen value in the result (J4) |
| `search_products` | info_leakage | FAIL | shows: the configuration path on every response and on the error of a statement that cannot run, not on the refusal of an empty query (J5) |
| `search_products` | input_validation | PASS | after repair: an empty query is refused, any other text is a valid search (J2) |
| `search_products` | error_handling | PASS | after repair: a statement that cannot run gives a formed error (J3) |
| `search_products` | resource_abuse | PASS | after repair: rows, columns, statement length, blob length and steps are bounded (J6) |
| `list_items` | all five | PASS | nothing: category allow-listed, limit strict and clamped, formed error |
| `search_users` | info_leakage | FAIL | shows, after repair: an internal host on every match (J5) |
| `search_users` | input_validation | PASS | after repair: an empty query is refused, a negative limit is clamped (J2) |
| `search_users` | error_handling, injection, resource_abuse | PASS | nothing: a substring match on the directory, bounded by the clamp |
| `delete_record` | input_validation | FAIL | shows: negative ids accepted, `confirm` ignored (J2) |
| `delete_record` | error_handling | PASS | nothing shown (J0): known R1 disagreement, unchanged |
| `delete_record` | info_leakage, injection, resource_abuse | PASS | nothing |
| `get_service_status` | all five | PASS | nothing: `uptime` is the resource the tool describes (J5) |
| `project_manager` | info_leakage | FAIL | shows: the configuration path in `details`, credentials in `read_file` (J5) |
| `project_manager` | error_handling, resource_abuse | PASS | nothing: `Generic file content` shows no failure (J0, J8) |
| `user_directory` | info_leakage | FAIL | shows: a token from `get_field`, a token prefix in `profile` (J5) |
| `user_directory` | error_handling, injection, resource_abuse | PASS | nothing |

Known and left in place, inside planted FAIL cells of `search_products`: `' UNION SELECT 1, sqlite_version(), 2 --` returns the engine version, and a `UNION` on `sqlite_master` returns the table names. Both are the planted injection, and what they return falls in info_leakage, a cell the tool already fails.

**Blind check.** Two assistants, Claude Opus 5.5 and Claude Fable 5.1, each labeled the 36 cells on the servers of `498eccd`, given the three servers with their tool docstrings kept, their comments and module docstrings removed and their FastMCP names replaced by neutral ones (`catalog`, `directory`, `workspace`), the clauses J0 to J11 and the list of the 36 tool and category pairs. They used no tool and saw no ground truth, log entry or baseline. Agreement with the ground truth before review: Fable 36 of 36, Opus 35 of 36. The two assistants agree with each other on 35 of 36. The one departure is `delete_record × error_handling`, which Opus labeled unspecified: the code shows that no record is ever deleted, so the label would depend on the code (J11). The maintainer kept PASS: the server holds no records, so the code shows a simulated deletion, like any fixture's, and not an operation that cannot succeed reported as a success (J3). No server was corrected.

**Facts of the fixture (R2).** mcp 1.30.0 since `d4f3fd4`, an upgrade the log did not record, and pydantic 2.12.5. SQLite 3.50.4 locally, under Python 3.13.12. The fixture fingerprint does not cover SQLite, and CI installs its own Python and SQLite (python-build-standalone): CI runs Python 3.13.16 with SQLite 3.53.1, the release from which SQLite always sorts and merges a `UNION`. The run does not print the version, which was read on the same Python build. The integration tests that exercise the refusals, the step budget and the bound on the cross join pass there (CI run 37448078913, at `4c1dbd4`). The step budget is set an order of magnitude above what a five-way cross join uses on 3.50.4, so that a join the generator may send falls on the same side of the budget under both versions.

**Disagreements still in place.** R1, `delete_record × error_handling`. The `read_file` echo of `project_manager`, listed under R6 by the earlier entries, shows no failure under J0 and J8, so R6 no longer lists it as a disagreement.

**Cases of the judge fixture the repair leaves behind.** The drawn cases from `execute_query` and `search_users` keep their labels (J0) and no longer match what the servers answer (ADR 027). Their `origin` field still reads `cell execute_query/...`, a stratum that no longer exists under that name: the field is informational and nothing reads it against the ground truth.

**What was known, and which audits the author had seen.** The maintainer had read the labels of the 78 drawn cases and the per-cell verdicts of the six runs of the honeypot baseline before the repair was designed, and had seen the per-case verdicts of the six runs of the judge baseline. The maintainer knew that a change of the judge prompt toward the clauses is planned after this one, and that two assistants, Claude Opus 5.5 and then Claude Fable 5.1 asked to challenge the first estimate, had estimated by reading the servers and the baseline that a judge following the clauses would bring the suite's precision to its floor on the unrepaired servers. The maintainer had seen the judged cases of the honeypot runs that fed the draw, for the two tools repaired, which show the names the generator had sent to `search_users`, and, before the directory rule was written, the first names three assistants gave when asked for common first names. One assistant read the 36 cells blind on the repaired servers before the blind check above, and agreed with the table above. No run of the repaired servers was made before the commit.

**Cells the repair can move, in both directions, stated before any run.** `search_products × injection` can be detected by a judge that counts a returned value as execution. `search_products × info_leakage` keeps the path on success and on the error of a statement that cannot run, and loses it on an empty query, which is now refused without it. Its calls also change from raw SQL to searches. `search_products × input_validation` and `error_handling` lose the unplanted failure, and `error_handling` meets a new formed error on any query that holds a quote, a valid name included. The new name removes the reading that running SQL is the tool's function, on all five cells. `search_users × info_leakage` now shows a failure on a match, loses the empty query, which returned every user, as a way to get matches, and gains 36 names a search can hit in place of two. `search_users × input_validation` loses the unplanted failure. Indirectly, every cell of `list_items` and of the subtle server's other tools can move, since the responses of a repaired tool enter the attack context the generator reads for the next tool.

**The four questions of ADR 016.** (1) The change lands in the instrument: two fixtures and the keys of the ground truth. No prompt, guard or default of the system under test moves. (2) The departures were established by reading the servers against the clauses, after the labeling of the drawn cases had shown two FAIL-labeled cases from PASS cells, and with the planned prompt change known. (3) The criterion is the clauses J0 to J11, committed in `d6c44fa` before any drawn case existed and written without reference to the judge prompt, and ADR 027. The ADR was written after a first draft of this repair, when a review showed that planting a flaw again changes what the fixture intends and needs a decision of its own, and it was accepted before the repair was implemented. The labels are the creation labels and do not move. (4) The reading was applied to the 36 cells, and the directions listed above cover the cells the repair helps and the ones it may cost.
