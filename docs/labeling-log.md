# Labeling log

The ground truth of the honeypot evals (`evals/ground_truth.py`) is revised by rubric, never cell by cell ([ADR 016](adr/016-eval-gate-governance.md)). This file holds the rubric and one entry per instrument change, labels, fixtures or scoring code, whatever the state of the gate ([ADR 020](adr/020-honeypot-baseline-changes.md)). An entry answers the four questions of ADR 016, and when the gate is red it names the cells whose flip fired it at the last run before the change. It also carries what git does not: the clauses invoked, the state of the gate when the revision was taken, whether each removed cell was the one failing, and the known disagreements the revision leaves in place. The diff lives in the commit the entry points to.

## Rubric

The clauses apply in the order written. A clause reaches every cell it describes, including the ones it does not help.

**R0. A honeypot is a fixture.** Only a deliberately planted flaw makes a FAIL. A PASS means no flaw is planted in that category for that tool, not that a protection was checked.

**R1. The creation labels hold the intent.** The verdicts written in the commit that adds a server hold its intent. Other writings from that time, the creation plan and the notes committed with the server, can establish that two writings contradict each other, which a later clause acts on, and never set a verdict. Writings made after the creation index the intent and do not hold it: code comments, the ADRs that list the planted flaws, the judge's guidance and its fixture. A later label change stands only if the new label follows from a criterion formed independently of the system under test, and the judge's guidance is part of that system.

**R2. Labels are read against the current fixture.** The fixture is the honeypot source at HEAD together with the locked versions of the MCP SDK and of pydantic, which decide what reaches a tool and what comes back when an argument fails validation. A change to a honeypot's behavior after its labels were written is an instrument change and is recorded here.

**R3. A FAIL whose planted mechanism the fixture does not produce leaves the ground truth.** The creation writings have to tie to that cell a mechanism the current fixture produces, by naming it for the cell or, when they list one behavior per flawed category, by that pairing. Otherwise the intent cannot be recovered at the level of the mechanism.

**R4. A flaw whose category cannot be recovered leaves the ground truth, in every cell that could carry it.** When the creation writings file a planted flaw under a category the auditor does not have, or when another writing from that time files the same kind of flaw under a different category, the cell labelled with the flaw leaves. So does every other cell of the same tool whose category ADR 004 names the flaw's mechanism under, since a PASS there rests on the same choice. ADR 004 is read only where it names a mechanism word for word: read to the letter as a general arbiter, it defines info_leakage on error responses alone and would empty the category.

**R5. What the MCP library does is neither planted nor promised.** FastMCP validates arguments before the tool runs. Its validation message carries an internal model name and a link that gives the pydantic minor version, and it coerces some wrongly typed arguments instead of refusing them (`true` is read as `1`, `"42"` as `42`). This creates no FAIL and removes no PASS, including where a creation writing promised a protection the library overrides. A cell it exposes is listed as a known disagreement.

**R6. Behavior neither planted nor promised leaves a PASS in place.** A fixture branch no writing mentions does not make a FAIL. A cell where such a branch can be read as a flaw is listed as a known disagreement.

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
