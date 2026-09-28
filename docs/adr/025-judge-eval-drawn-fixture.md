# ADR 025: The Judge Isolation Eval Draws Its Cases and Gates Case by Case

**Date:** 2026-09-28
**Status:** Accepted
**Supersedes:** in ADR 006, the sources of the judge cases, the growth of the fixture as new failure modes surface, its update when the judge prompt changes, and the F1 threshold. In ADR 007, the promotion of misjudged cases into the judge fixture. In ADR 015, the description of the judge fixture as built from the judge's own observed failure modes. In ADR 016, the sentence that keeps the judge isolation eval under its own absolute F1 threshold.

## Context

The judge isolation eval ([ADR 006](006-judge-evaluation-strategy.md)) scores the judge prompt on a fixture of 32 cases, 8 of them expected to fail. ADR 006 ranks observed false positives first among the sources of cases, and [ADR 007](007-e2e-eval-case-export.md) adds a loop that promotes misjudged cases from the end-to-end export. Commits `d2b6a98` and `53e525a` each changed the fixture together with the judge prompt. The fixture measures the prompt on the failure modes the prompt was changed to handle.

The gate is an F1 of 0.90 over a single run of each case. With 8 cases expected to fail, it tolerates one error and rejects two, so a run already at one error goes red when one more verdict flips between runs.

## Decision

**The fixture is drawn by a rule written before the draw, and no case enters because of its verdict.** The rule names the runs it draws from before any of their cases is labeled. The first source is the judged cases exported by honeypot end-to-end runs, drawn at random within the cells the ground truth labels FAIL and within the cells it labels PASS, in quotas set before the draw. Cells outside the ground truth are left out, and so are attack chains, which another prompt judges. The second source is the judged cases of CVE benchmark runs, drawn at random per target in quotas set before the draw. The current 32 cases are removed from the fixture.

**Each case gets its own label, which says whether the tool's response or error shows a failure, planted or not, in the category tested.** The judge is asked the same question. The rule that only planted flaws count governs the cells of the honeypot suite ([ADR 016](016-eval-gate-governance.md)), not these cases. Under the any-fail rule of `evals/metrics.py`, one failing case fails a cell, so a case drawn from a FAIL cell can rightly be labeled PASS. The labeling rubric is written before any case is labeled and does not refer to the judge prompt. The cases are labeled from an export stripped of the judge's verdict, its justification and the `correct` field, and the labeling log records what the labeler already knew of the verdicts.

**The fixture changes only by a new draw on newer runs, under the same rule.** A new draw replaces the cases a red gate names, so a draw is made only while the gate is green. A case label changes only by a rubric clause applied to every case it covers. A case the rubric cannot decide is labeled unspecified: it stays in the fixture and leaves the metrics and the comparison.

**The gate compares case by case, under the rules of [ADR 016](016-eval-gate-governance.md) and [ADR 020](020-honeypot-baseline-changes.md), with the case in place of the cell.** The gated cases that a change to the judge prompt is expected to flip are declared before the eval runs on the changed prompt. A second recording adds its runs to the first ([ADR 023](023-honeypot-second-recording.md)). The floors, and the conditions that refuse a recording, are those of [ADR 022](022-honeypot-recall-floor.md), applied to cases: on average one case per run that is expected to fail and judged as failing, a precision of 0.50, and no recording without a stable and correct case among those expected to fail and among those expected to pass. The baseline records the provider, the judge model and its reasoning level, the number of runs, and a fingerprint of the judge inputs, labels excluded. Until a baseline is confirmed, the gate runs on the floors alone.

## Alternatives considered

**A held-out split of the fixture.** Rejected. Every source available is either a honeypot the judge prompt was tuned on or a CVE target that labeling spends. If the split were made by cell, so that near-identical cases stay on one side, the held-out part would hold two or three FAIL cells whose cases move together, and it could only detect a collapse the floors already catch.

**Keeping the promotion of misjudged cases.** Rejected. A promoted case enters the fixture together with the prompt change it justifies, so the fixture keeps measuring the judge on the failures the prompt was changed to handle.

## Consequences

The whole fixture is a development set. Every case is read to be labeled, and the judge prompt may change once a case has been read, under the deletion test of ADR 016. Changing the judge prompt until no gated case breaks stays allowed, since the eval keeps its role as a fast feedback loop. Accepting a regression that was not declared before the eval ran on the change is not ([ADR 020](020-honeypot-baseline-changes.md)). No judge figure is published. The eval licenses nothing about the system ([ADR 015](015-eval-instruments-and-claims.md)).

Labeling the CVE cases means reading the judge inputs of all six targets, which spends the three that had not been read. None of the six can enter the holdout layer, which ADR 015 had left open to those three.

Most cases expected to fail will likely come from the honeypots, which the judge prompt was tuned on.

The precision floor detects a judge that returns FAIL on every case only while the cases expected to fail are under half of those labeled PASS or FAIL.

The case-by-case disagreements of two models on this fixture can inform a choice between them, as development-set evidence that likely favors the model that generated the payloads of the drawn runs. There is no gated comparison across models (ADR 016).

A held-out set becomes possible once servers not written by this project supply enough judged cases, from the nuisance suite or from CVE targets as they are spent and leave the holdout layer.
