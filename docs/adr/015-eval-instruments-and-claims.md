# ADR 015: Eval Instruments and What Each Licenses

**Date:** 2026-09-21
**Status:** Accepted
**Supersedes:** the clause of ADR 006 that keeps the end-to-end eval as the acceptance gate for the system as a whole

## Context

One instrument carried three jobs: the honeypot e2e suite was the regression guard, the measure of what the auditor detects, and the source of the README's figures. Changing a label can correct the specification of a fixture, which the first job needs, or move the benchmark toward what the auditor already does, which invalidates the second, and the diff does not say which.

This ADR splits the eval instruments by the claim each of them backs. What may move when a number comes back red is governed by [ADR 016](016-eval-gate-governance.md).

## Decision

**One instrument, one claim.** The honeypot e2e suite is a regression guard: it gates the build, it is no longer the acceptance gate for the system as a whole, and its metrics are not published as a measure of quality. The judge isolation eval calibrates one component on a set built from its own observed failure modes, and licenses nothing about the system. A capability claim belongs to instruments that run against servers this project did not write, and whose traces it did not read during tuning: the holdout layer of the CVE benchmark, and a nuisance suite over healthy patched servers that does not exist yet.

**The CVE benchmark holds two layers that share the pinned Docker fixtures and the oracle that grades them**, `evals/cve_oracle.py`. The acceptance layer holds targets whose traces have been read and carries the error analysis that feeds detection work. Its report names, per target, the oracle condition that failed and how the miss is classed, and nothing that reads as a detection rate. The holdout layer holds targets chosen under the selection rule below and never read since, and it is the one layer whose number can be quoted as capability. A capability number comes from a run with no tools filter, since a target's filter is derived from its calibration exploit and hands the auditor the tool the oracle credits.

**A target is spent by being read, or by justifying a change to a shipped prompt.** Reading means opening its per-case traces, its judge inputs or its judge verdicts, by hand or through an agent that reports back what it read. A run summary, a calibration output and a harness log do not spend it. A spent target moves to the acceptance layer and is replaced. The move runs one way, and an unclear case counts as spent: replacing a target costs a fixture, trusting a spent one costs every number it later backs.

**The selection rule for the holdout layer is written before any target is chosen.** It will live at `docs/holdout-rule.md` with its inclusion criteria, and the targets follow from it. Choosing targets first and describing the rule afterwards leaves nothing to falsify.

**A capability number records where its targets sit relative to the models' training data.** Whether a CVE advisory predates the training data of the models that audit it has not been checked for any target, and the reading rule above tracks what this project has read, not what the model has seen. Recording each target's disclosure date against the cutoffs the vendors declare, and which kind of cutoff each one is, does not remove that exposure, and no selection rule can, but a holdout with targets on both sides of the cutoff is what would measure it.

**The CVE oracle is frozen before a holdout run.** Its conditions are written by reading the acceptance layer, so a fresh target would be scored by a grader shaped on spent ones, and retiring a target does not undo the shaping. The conditions it credits and its split of partial credit stabilize on the acceptance layer first: an oracle revised after a holdout run makes every earlier holdout number describe a different instrument, and a run scored by an oracle that moved afterwards is exploratory, recorded and confirming nothing.

**Only targets narrow the interval on a capability rate.** Running one target more times estimates how reliably that target is detected and adds no new sample from the population of CVEs, and the interval depends on how many targets there are. Reliability per target and detection rate are budgeted separately, and at the sizes the holdout layer will reach, its number shows whether detection exists and bounds it, but cannot resolve a precise rate or a delta of a few points. The number is the share of targets detected in one run at fixed conditions, not a per-target detectability, and it is published with the classes of flaw the layer covers.

**Published proportions carry a Wilson or Beta-Bernoulli interval**, never a bare point estimate, and a Bayesian interval names its prior. A conclusion that does not survive a change of interval method is inconclusive. F1 gets no valid CLT interval, because it is non-linear in the confusion matrix, and at a point estimate of 1.0 a normal approximation collapses to zero width. F1 gets its interval from a Dirichlet posterior over the confusion matrix.

## Alternatives considered

**Two CVE layers as two instruments.** Rejected. Instruments here are told apart by the servers they run and the oracle that grades them, and the two layers share both. "One instrument, one claim" says what a number licenses, not how instruments are counted: read as a count, it would also split the honeypot suite, which carries a measured precision and a regression job at once.

**A capability claim from the acceptance layer, scoped to that benchmark.** Rejected. A capability claim needs evidence of generalization beyond the benchmark it was tuned on, and three of the six targets are spent as of this decision, so a rate over the six would also put two states in one number.

**A fresh honeypot, held out.** Rejected as a capability instrument. It is held out from the tuning, but it comes from the author of the suite it would validate, and a capability claim needs servers this project did not write.

## Consequences

As of this decision, this project publishes no quantitative capability claim.

No instrument measures the false-positive rate on a healthy server: the nuisance suite named above is the one that would, and until it runs no claim about false alarms is published. An unfiltered holdout run costs several times a filtered one on the current fixtures.

The holdout layer does not exist. The three unread targets do not form it, since they were chosen before any selection rule was written: the rule decides whether each one enters it or is replaced, and their numbers stay exploratory until then. An oracle bug found while reading a holdout run spends that target, and the size of the layer follows from how fast targets are spent.

The condition-level report waits on the oracle. It credits a single planted sentinel per target, as ADR 014 records, so the acceptance layer reports detected, reached but judged pass, or missed, and nothing finer until that single sentinel becomes the set of conditions with partial credit that this decision assumes.

The gated precision gets no interval from the rule above. It is an average of per-run precisions, and a Wilson interval over the pooled runs estimates a different quantity, the long-run share of correct FAIL predictions on these forty cells at these conditions, since repeated runs re-score the same ground truth instead of sampling new items. Its coverage also assumes verdicts independent across cells within a run, which the context the auditor carries from tool to tool (ADR 009) does not provide.
