# ADR 016: Eval Gate Governance and Tuning Discipline

**Date:** 2026-09-21
**Status:** Accepted
**Supersedes:** the acceptance criteria of ADR 003 (recall >= 0.80, precision 1.00)

## Context

The honeypot e2e gate compares four point estimates to absolute thresholds. With 11 expected positives per run, a single false positive moves a run's precision by about 0.08. On the batch of 2026-08-22, which averaged three runs, it moves the gated figure by about 0.03, that is the resolution of the instrument at that setting. The gap that decided the gate was about a quarter of it, and a power calculation for one proportion against a fixed threshold at the batch's pass rate puts the sample size needed to resolve it two to three orders of magnitude above the 37 predictions the batch holds, so the gate was reporting a draw.

Every intervention on a red gate in the suite's five months touched the instrument: the threshold in `012aac4`, the judge prompt in `53e525a` and `d2b6a98`, the judge fixture and the generator prompt in `26f49bc`, the labels in `fa52ad8`. Four of the five also moved a prompt that ships to users, and the judge prompt in `graph/prompts.py` is instrument and product at once, so an edit to it is both changes in one. Each edit was legal under the criteria then in force, so consecutive numbers were rarely produced by the same instrument: the defect was in the rules.

[ADR 015](015-eval-instruments-and-claims.md) splits the instruments by the claim each of them backs. This ADR governs what may move when a number comes back red.

## Decision

### The gate

**The gate is paired and compares cell by cell**, where a cell is one pair of tool and category in the ground truth. It fires when a cell that was correct in the recorded baseline becomes incorrect, or when a gated metric falls below its absolute floor. `consistency` leaves the gated set and carries no floor, since the per-cell stability recorded in the baseline takes over its job. A baseline is recorded per gated instrument under `evals/baselines/`. A floor is a collapse detector and not a quality bar, and lowering one takes a new ADR. Pairing reduces the variance of the comparison wherever baseline and candidate verdicts positively correlate. The acceptance layer of the CVE benchmark gates the same way, on a target that stops being detected, and against a baseline with no detection it stays green, so it can be built before any published number depends on it.

**A flip gates only on a cell whose baseline verdict was stable across the recorded runs.** A flip is one wrong verdict, which is the smallest move the instrument can make, so pairing alone cannot separate a regression from run-to-run instability. A flip on a cell that was already unstable is recorded as inconclusive. A candidate cell counts as correct only if every run has it correct, so new instability is a flip.

**A flip is re-tested under a rule written before it happens.** A cell that rarely flips still looks stable across three runs most of the time, so cells the baseline calls stable will still flip with no regression behind them. A flip is replayed a fixed number of times and gates only when it reproduces a fixed number of those, both numbers recorded in the baseline file.

**The baseline is re-recorded only from a green run.** Re-recording it while the gate is red compares the candidate to itself, and it is the one move forbidden outright. A red gate clears by a change to the system under test, or by a revision that survives the four questions below.

**The baseline records its conditions**: runs, budget, the tools filter, the models used for generation and for judging, and the oracle version. The gate refuses to compare across differing values, and why two budgets do not compare is derived in the docstring of `aggregate_verdicts`. Across models there is no gated comparison: while the old model still answers, both models run and the delta is recorded, and once the old model stops answering the first baseline on the new model is exploratory, guarded by the floors alone, until a second recording agrees with it on the cells the first called stable.

### Discipline under a red gate

**A change to the system under test justifies itself without the instrument.** A prompt, a guard table or a default found by reading eval output may ship if its written justification holds once every mention of the measurement is deleted, which is the deletion test. ADR 014 covers the half a test can catch, a shipped prompt naming a literal that a fixture plants. The other half, a change whose only reason was the grader's behavior, leaves no string behind and rests on this rule alone. A number produced by a change found by reading eval output is exploratory: it is recorded and confirms nothing, and a confirmatory number needs a bar written before the measurement ran, or data the change was not derived from.

**An instrument change and a system change do not license each other.** An instrument change does not borrow its justification from a system change shipped with it, and a system change written to make the revision look earned licenses nothing.

**Honeypots are fixtures.** Only deliberately planted flaws count, and every branch carries a written intent, as `tests/honeypot_server.py` already does. A branch whose intent cannot be recovered is annotated as unspecified, and its cell leaves the ground truth.

**The ground truth is an oracle, revised by rubric and never cell by cell.** A revision is a written clause that applies to every cell it reaches. It is written down before its effect on the metrics is computed and recorded in `docs/labeling-log.md`, and the clauses recorded there form the rubric. The file carries only what git does not: the rubric clause invoked, the state of the gate at the time, and a pointer to the commit. A revision taken while the gate is red is re-annotated from the fixture's written intent and the rubric clause alone, with the eval report closed. Removing a cell is a revision like any other, and its log entry records whether the removed cell was the one failing.

**A delta below the instrument's resolution is inconclusive**, a third outcome never read as a win or as a regression. The resolution is the move one misclassified case makes on the metric as the gate compares it, after averaging over runs.

### Four questions for any change taken while the gate is red

1. Which artifact does the change land in, the instrument or the system under test? If the system, does its justification survive the deletion test?
2. Was the disagreement between label and verdict noticed before or after reading the metric?
3. Does the new label follow from a criterion formed independently of the observed behavior, or does it describe what the system does?
4. Was the rubric applied to every affected cell, including the ones it does not help?

Questions 1, 3 and 4 disqualify on their own. Question 2 does not: a disagreement noticed through the metric moves the burden onto questions 3 and 4.

## Alternatives considered

**An aggregate gate against the previous baseline, with a tolerance derived from the spread of runs.** Rejected. A tolerance computed as `sd / sqrt(runs)` widens as `--runs` is lowered, so the cheapest CI setting is the most tolerant one.

**Majority aggregation instead of the any-fail rule of `evals/metrics.py`.** Rejected. Measured on the verdicts of 2026-08-22, a batch and not the current system: strict majority takes recall from 0.94 to 0.52, a two-fail threshold to 0.61.

## Consequences

The discipline above needs no code and applies now. The gate itself is not built: no baseline is recorded, and the current thresholds stand until the baseline record and the cell-by-cell comparison replace them. Once the gate lands, a green gate means no regression against the baseline and nothing else. The judge isolation eval keeps its own absolute F1 threshold, outside this decision. Neither status this decision creates has a field yet: inconclusive and exploratory live in the text around a number until the report carries them.

`tests/chain_honeypot_server.py` carries no written intent yet, and `tests/subtle_server.py` names two of its flaws without declaring them deliberate. Annotating both comes before the rule on unspecified intent can be applied to their cells.

A configured model name that is a moving alias does not change when the version behind it does, so the recorded conditions catch a swapped name and not a swapped version.

`consistency` has a per-cell rate bounded below by `ceil(n/2)/n` over the `n` runs that covered the cell, so a run in which the cell disagreed dropping out of coverage raises its rate. It stays in the report as a diagnostic.

Nothing in the gate's construction tests that it detects regressions. The proof is fault injection, named here and still to run. Nothing tests the other direction either, that a detection survives when a literal named by a shipped prompt is renamed in the fixture. On the CVE benchmark, whose sentinels are minted per run, that check is the holdout layer of ADR 015. Extending the fixture-literal test of ADR 014 beyond the one prompt line it covers is work this decision does not do.
