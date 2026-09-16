# ADR 015: Eval Gate Governance and Tuning Discipline

**Date:** 2026-08-24
**Status:** Draft
**Supersedes:** the acceptance criteria of ADR 003 (recall >= 0.80, precision 1.00), and the clause of ADR 006 that keeps the end-to-end eval as the acceptance gate for the system as a whole

## Context

The e2e gate compares four point estimates to absolute thresholds. With 11 expected positives per run, a single false positive moves a run's precision by about 0.08, so near its threshold the metric has three or four reachable values. Averaged over the three runs of the batch of 2026-08-22, that same false positive moves the gated figure by about 0.03, and that is the resolution of the instrument at that setting. The gap that decided the gate on that batch was under a quarter of it, and a power calculation at that effect size, for one proportion against a fixed threshold at the batch's own pass rate, puts the sample size needed to resolve it two to three orders of magnitude above what the batch holds. The gate was reporting a draw.

Two estimators are in play and only one is gated. Precision is gated as the average of per-run precisions, while the natural interval for a proportion is computed over all runs pooled. They are different quantities, and quoting the one beside the other would give the gated point an interval that describes something else.

Across the suite's five months, every intervention on a red gate moved the instrument: the threshold in `012aac4`, the rubric in `53e525a` and `d2b6a98`, the generator tuning in `26f49bc`, the labels in `fa52ad8`. Four of those five also moved a prompt that ships to users. `graph/prompts.py` carries the generator prompt and the judge prompt, so the judge prompt is the rubric and the product at once and an edit to it is both changes in one. Each of those edits was legal under the criteria then in force: the rules were the defect. Error analyses have so far produced instrument revisions rather than new detection capability.

ADR 003 splits the code by the nature of its logic. This one splits the eval instruments by the claim each of them backs, and it governs what may move when the number comes back red. Evals remain the feedback loop ADR 003 describes, and judge precision remains the lever on end-to-end precision that ADR 006 describes. Work on either now runs under the justification rule below.

## Decision

### The instruments and what each licenses

**One instrument, one claim.** The honeypot e2e suite is a regression guard. It gates the build, and its aggregate metrics are not published as a measure of quality. The judge isolation eval calibrates one component and licenses nothing about the system. A capability claim belongs to instruments that run against servers this project did not write, with nothing of theirs read during tuning: the holdout layer of the CVE benchmark, and a nuisance suite over healthy patched servers that does not exist yet.

**The CVE benchmark holds two layers, and everything separates them except the substrate and the oracle.** The acceptance layer holds targets whose traces have been read. It carries the error analysis that feeds new detection work, and its report names which target was reached, which condition failed and which class the error falls in. It reports nothing that reads as a detection rate. The holdout layer holds targets chosen under the selection rule below and never read since, and never having been read does not, on its own, enroll a target in it. It is the one layer whose number can be quoted as capability. Both layers use the same pinned Docker fixtures and the same oracle, so they are one instrument carrying two licenses.

**A target is spent by being read.** Reading means opening a target's per-case traces, its judge inputs or its judge verdicts. A run summary, a calibration output and a harness log do not spend a target, and deterministic calibration does not either, since it replays a hand-written exploit against the fixture and observes nothing about the auditor. A target whose traces have been read, or that justified a change to a shipped prompt, moves to the acceptance layer and is replaced. The move runs one way. When the case is unclear the target counts as spent, because replacing a target costs one fixture and trusting a spent one costs every number it later backs.

**The selection rule for the holdout layer is written down before any target is chosen.** The rule and its inclusion criteria are fixed in advance, and the targets follow from them. It will live at `docs/holdout-rule.md`, written before the first fresh target is picked. Choosing targets first and describing the rule afterwards leaves nothing to falsify, and writing the rule early costs a paragraph.

**A capability number records where its targets sit relative to the model's training data.** The CVE targets are public. Whether an advisory predates the training data of the models that audit it has not been checked for any of them, and a target nobody here has read can still be one a model has seen, so the rule above tracks one of the two channels and not the other. Recording each target's disclosure date against the training cutoffs of the models that ran it, the same identifiers the baseline stamps, does not close the second channel, and no selection rule can. It makes the exposure visible, and a holdout carrying targets on both sides of that line measures it.

**The oracle is frozen before a holdout run.** The oracle is built by reading the acceptance layer, so a fresh target can be scored by a grader that was shaped on spent ones, and retiring a target does not undo that shaping. The conditions the oracle credits and the way it splits partial credit stabilize on the acceptance layer first. An oracle revised after a holdout run makes every earlier holdout number describe a different instrument, and a holdout run scored by an oracle that moved afterwards is exploratory.

**A capability rate is a statement about a population of targets, and only targets buy resolution on it.** Running one target more times estimates how reliably that target is detected, and it removes the noise of two models in series. It adds no draw from the population of CVEs, whose interval is governed by how many targets there are. The two levers answer different questions, so a claim about reliability per target and a claim about a detection rate are budgeted separately.

### The gate

**The gate is paired and compares cell by cell**, a cell being one pair of tool and category in the ground truth. It fires when a cell that was correct in the recorded baseline becomes incorrect, and it also fires below an absolute floor per gated metric. Baseline records live under `evals/baselines/`, one per gated instrument, and lowering a floor requires a new ADR. Paired comparison reduces the variance of the estimate whenever baseline and candidate verdicts positively correlate, at no extra measurement cost, and it gives no protection on the cells whose verdicts do not.

**A cell flip is one wrong verdict, which is the resolution itself, so pairing alone cannot separate a regression from run-to-run instability.** The baseline records several runs, so it records which cells held the same verdict across them. A flip gates when the baseline verdict for that cell was stable across those runs. A flip on a cell that was already unstable is recorded as inconclusive and does not gate, and the absolute floor catches a collapse spread across many such cells.

**A flip is re-tested under a rule written before it happens.** The stability test above reads the runs the baseline holds, and a cell that flips one time in ten looks stable across three runs about seven times in ten, so cells it calls stable will fire on their own. A flip is replayed a fixed number of times and gates only when it reproduces a fixed number of those, both recorded in the baseline file. Without that rule the only move left is re-running until the gate clears.

**The acceptance layer gates on the same paired comparison, and publishes nothing while doing so.** A target that was detected in the recorded baseline and stops being detected fires the gate. Against a baseline that records no detection the gate holds nothing and stays green, so it can be built early, before any published number depends on it.

**The baseline is re-recorded only from a green run.** Re-recording it while the gate is red is the one move forbidden outright, since it compares the candidate to itself. A red gate clears by a change to the system under test, or by a revision that survives the four questions below.

**The first baseline on a new model is exploratory.** The gate refuses to compare across models, so on the day a model is retired there is no gate and nothing to be green. While the old model still answers, both run and the delta is recorded. Once it stops answering, the first baseline on the new model is recorded as exploratory, and the absolute floor per metric is the only guard until a second recording agrees with it on the cells the first called stable.

**A delta below the instrument's resolution is inconclusive, a third outcome.** The resolution is per gated metric and reported next to the numbers in the eval report: for precision it is the move a single false positive makes on the batch, for recall a single false negative, each on its own denominator. A delta smaller than it is recorded as inconclusive at this set size, with the delta and the count, and it is never read as a win or as a regression.

**The baseline records its conditions.** It records runs, budget, the models used for generation and for judging, and the oracle version, and the gate refuses to compare across differing values. Those identifiers are stamped where the clients are built, rather than inferred when the report is assembled, so a model swapped underneath a run makes the comparison fail loudly. Under any-fail aggregation, `P(cell FAIL) = 1 - (1-q)^k` with `q` the per-case false-FAIL rate and `k` the number of cases drawn, so precision falls as the budget rises and two budgets do not measure the same thing.

### Discipline under a red gate

**A change to the system under test justifies itself without the instrument.** A prompt, a guard table or a default may be found by reading eval output, and it may ship. Its written justification has to hold once every mention of the measurement is deleted. A justification that needs the clause "and the oracle credits that" is fitting the product to the benchmark instead of to the threat it audits. ADR 014 carries the visible half of this and its guard test, which asserts that the prompt line ADR 014 added reuses no literal the CVE fixtures plant. That test covers one prompt line, and extending it to every shipped prompt is work this decision does not do. The other half, a change whose only reason was the grader's behavior, leaves no string behind, and no test catches it. Only this rule holds it.

**A number produced by a change that came out of the same data is exploratory.** It is recorded and it confirms nothing. A confirmatory number needs a bar written down before the measurement ran, or data the change was not derived from.

**An instrument change and a system change do not license each other.** An instrument change ships alongside a change to the system under test whose justification survives the deletion test above on its own, or the instrument change waits. A system change written to make the instrument revision look earned licenses nothing. The judge prompt answers to both rules at once, since it is rubric and product in one file. The CVE oracle carries a different double role: it grades both layers, so what binds it is the freeze rule above.

**The ground truth is an oracle, and it is revised by rubric.** It is never revised cell by cell. A revision is written down before its effect on the metrics is computed, and it is recorded in `docs/labeling-log.md`, created with the first revision. That file carries only what git does not: the rubric clause invoked, the state of the gate at the time of the decision, and a pointer to the commit that carries the diff. A revision taken while the gate is red is re-annotated from the fixture's written intent and the rubric clause alone, with the eval report closed. Removing a cell is a revision like any other, and its log entry records whether the removed cell was the failing one.

**Honeypots are fixtures.** Only deliberately planted flaws count, and every branch carries a written intent, as `tests/honeypot_server.py` already does. A branch whose intent cannot be recovered is annotated as unspecified, and its cell leaves the ground truth instead of carrying a guessed label.

### What gets published

**Published proportions carry intervals.** They get a Wilson or Beta-Bernoulli interval, never a bare point estimate. F1 gets no valid CLT interval: it is non-linear in the confusion matrix, and at a point estimate of 1.0 a normal approximation collapses to zero width and reads as certainty. It gets an interval from a Dirichlet posterior over the confusion matrix, or it is published only beside the count of positive cases it rests on and the recall interval that count implies, since that count governs how much the figure can mean.

**any-fail aggregation stays.** The alternatives were measured on the verdicts recorded on 2026-08-22, and the figures that follow describe that batch rather than the current system: strict majority takes recall from 0.94 to 0.52, a two-fail threshold to 0.61. 14 of the 31 true positives do not reach a strict majority of FAIL votes, including every finding carried by a single chain.

**A re-measured number does not enter this document.** A figure that reports the current state of the system goes to the README, beside the provenance of the run that produced it, because this ADR is immutable and that figure is not. Two kinds of figure stay here: a derivation from the fixed design, and a dated measurement that justified a decision, which does not go stale because the decision was taken on it.

## Alternatives considered

### Counting the two CVE layers as two instruments

**Rejected.** The two layers back different claims, and "one instrument, one claim" makes that look like a reason to count two. This project separates its instruments by substrate and by oracle, and the two layers share both. Read as a rule for counting, "one instrument, one claim" would also split the honeypot suite, which carries a measured precision and a regression job at once. It governs what an instrument licenses, and the number of instruments follows from the substrate and the oracle.

### A capability claim from the acceptance layer, bounded to its regime

**Rejected.** Published work defends searching and evaluating on one small, expensive benchmark, framed as a discovery problem, under manual inspection and audits for leaked strings, and states that the resulting artifact is specialized to that regime. A capability claim needs evidence that the result generalizes beyond the benchmark it was tuned on, and the holdout layer exists to produce that evidence. As of this decision, three of the six targets are spent and three are not, so a rate over the six would also put two states in one number.

## Consequences

As of this decision, this project publishes no quantitative capability claim of any kind. The honeypot metrics gate regressions, the judge eval calibrates a component, and the CVE benchmark reports mechanisms and error classes.

No instrument here measures the false-positive rate on a healthy server. The honeypot precision is computed inside fixtures written for this project, and this decision stops publishing it as a quality number. A capability rate from the holdout layer answers detection, and it says nothing about whether the auditor stays quiet on a server with nothing to find. That measurement waits on the nuisance suite.

No part of the gate described here is built. `evals/run_evals.py` still compares four averages to absolute thresholds and no baseline is recorded. This ADR is the decision, and the thresholds stand until the baseline record and the cell-by-cell comparison replace them.

The holdout layer does not exist. The targets that have not been read do not form it, since they were chosen before any selection rule was written, so a rate over them has nothing to falsify. Their numbers stay exploratory, and the selection rule decides whether each one enters the holdout layer or is replaced.

The condition-level report does not exist either. As of this decision, the oracle credits a single planted sentinel per target, as ADR 014 records, so the acceptance layer reports reached, judged pass, or missed, and nothing finer.

An oracle bug found while reading a holdout run spends that target, which moves to the acceptance layer and is replaced. The size of the holdout layer follows from how fast targets are spent.

Once the gate lands, a green gate means no regression against the baseline, and nothing else. It is no longer a success criterion for any piece of work.

The README stops publishing the honeypot metrics as quality numbers, in the change that carries this decision: the thresholds table and its "All thresholds met" line are removed, and the architecture section's "Quality is measured through evals" repoints here. The judge F1 goes with them or gains its interval and its count. Its fixture set was built to cover the judge's own observed failure modes, as ADR 006 records, so it is a development set and a figure measured on it is not confirmatory.

The gate rests on the claim that it detects regressions, and nothing in its construction tests that claim. The proof is fault injection: degrade the generator on one category, truncate the judge context, swap the judge model, disable chain aggregation, and count what the gate catches. None of these injections has been run yet.

Nothing tests the other direction either: whether a result survives a change to the fixture value it was measured against. Where a shipped prompt names a literal that a fixture plants, the check is to rename the literal in the fixture and re-run: a result that holds is a capability, and one that falls was reading the fixture. The CVE benchmark needs a different check, since its sentinels are random tokens minted per run that no prompt can name. What is memorizable there is the attack technique tuned from reading a target's traces, and the instrument for that is the holdout layer.

## Four questions for any revision taken while the gate is red

1. Which artifact does the change land in, the instrument or the system under test? If the system, does its justification survive deleting every mention of the instrument?
2. Was the disagreement noticed before, or after, reading the metric?
3. Does the new label follow from a criterion formed independently of the observed behavior, or does it describe what the system does?
4. Was the rubric applied to every affected cell, including the ones it does not help?

A revision fails on question 1 when the change lands in the system under test and its justification does not survive the deletion test, on question 3 when the label describes the observed behavior, and on question 4 when the rubric was applied selectively. Question 2 does not disqualify on its own: a disagreement noticed through the metric moves the burden onto the rubric clause invoked in questions 3 and 4.
