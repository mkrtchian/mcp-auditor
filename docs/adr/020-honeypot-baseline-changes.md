# ADR 020: How the Honeypot Baseline Changes

**Date:** 2026-09-25
**Status:** Draft
**Supersedes:** in ADR 016, for the honeypot suite: the oracle version as a condition that refuses a comparison, the two ways out of a red gate, the first baseline on a new model when the gate was red, and, for the cells a declared regression names, the rule that fires the gate.

## Context

[ADR 016](016-eval-gate-governance.md) records the conditions of a baseline and refuses to compare a run against it when one of them differs. The code records the oracle version, which ADR 016 names, as a fingerprint of the ground truth. It also records a fixture fingerprint per honeypot, which ADR 016 does not list. ADR 016 provides a way through for one condition only, the model.

Three situations have no legal way through. A label revision is one of the two ways out of a red gate that ADR 016 offers, but it changes the fingerprint of the ground truth, so the gate refuses the next comparison. A new honeypot makes the gate refuse the comparison too, since the baseline has no fixture fingerprint for it. And a change to the system under test that is justified without the instrument can be expected to cost cells: the gate turns red on them, and ADR 016 forbids re-recording while it is red.

The one move left is deleting the baseline file, which is a reset. With no file, the recording command does not check the verdict of the gate, so it can record a baseline from a run that the absolute thresholds call red. ADR 016 governs that reset for a new model only. Editing a module docstring, which never reaches the model, is enough to force it, since the fixture fingerprint hashes module docstrings.

This ADR governs the baseline of the honeypot suite. The CVE benchmark keeps the rules of ADR 016.

## Decision

**A label revision re-scores the baseline instead of resetting it.** The baseline keeps an observation per run and per cell, and an observation carries no label, so each cell is scored again under the current labels. The comparison then goes on without a new recording. The gate no longer refuses a comparison when the fingerprint of the ground truth differs.

**The fixture fingerprint covers what executes or is sent to the model.** Comments, formatting and the module docstring are left out.

**Every change to the instrument has an entry in the labeling log that answers the four questions of ADR 016, whatever the state of the gate.** This covers labels, fixtures and the scoring code, which turns verdicts into cell observations and metrics. A revision now moves cells in and out of the comparison, so a green gate no longer exempts it from the four questions.

**A reset is allowed while the gate is red, provided the cells that were red come out correct.** A change to a fixture, to the scoring code, to the model, to the number of runs or to the budget resets the baseline: its file is deleted in the commit that makes the change, and a new baseline is recorded, first exploratory then confirmed, as ADR 016 requires for a first baseline on a new model. While the gate is red, the labeling log entry, or the commit message when the change is a model, names the cells that were red, those whose flip fired the gate at the last run before the change. Each of them has to be stable and correct in the confirmed baseline. If one is not, the change is reverted and its recording discarded, which brings the old file back. A new model that does better on those cells can land this way.

**Runs and budget change only from a green gate.** Fewer runs let a cell that fails in one run of three come out correct in every run. A lower budget sends fewer probes, so a false positive has fewer chances to appear. Either can clear the red with nothing fixed.

**A deliberate regression is declared before the evals run on the change.** A change to the system under test that passes the deletion test of ADR 016 and is expected to cost cells names those cells in its commit. For each cell, the commit says by which mechanism the change reaches it. The declaration applies to that commit only. A flip on a declared cell does not fire the gate. The baseline is then re-recorded from a green run at that commit. After a run that is red on an undeclared cell, the change is reverted. A later declaration must not name a cell that already flipped in a run of the change. The commit also says which eval runs of the change its author had seen.

**One change at a time.** CI evaluates the head of what is pushed to main. Two changes pushed together are compared once, and the effect of one cannot be told apart from the effect of the other. A reset, a revision or a declared regression is alone in its commit, and measured at that commit before anything lands on it. A new honeypot is one change, its labels included. The baseline file changes only by a re-recording from a green run, a reset or a declared regression.

## Alternatives considered

**A reset with no check on the cells that were red.** Rejected. Taken while the gate is red, it clears the red with nothing fixed.

**Freezing the labels in the baseline and comparing under the old ones.** Rejected. The gate would keep protecting cells whose old label the rubric has declared wrong.

**Accepting a regression with a flag on the run.** Rejected. The decision would be taken after the run was seen.

**One baseline file per honeypot.** Rejected. It avoids a second recording of the fixtures that a change did not touch, at the cost of three files, metrics merged across files and a recording that writes only part of the baseline.

**Fingerprinting the token stream of the whole source, as the code does.** Rejected. An edit to a module docstring, or a formatting pass that changes quotes or trailing commas, would force a reset of the baseline.

## Consequences

These rules apply from the first recording. Before it, no baseline exists. A first recording is exploratory until a second one agrees with it, as ADR 016 requires for a new model and as the recording code already enforces for any first recording.

The code that reads a declaration does not exist yet. It is built the first time a deliberate regression is planned. Until then such a regression is blocked.

A reset records every cell again. A cell the change did not touch can come out unstable and leave the comparison, and a cell it did touch that comes out incorrect leaves the comparison too, with no flip recorded. Only the cells that were red are checked.

Once the old model stops answering, a change of model under which the cells that were red do not come out correct cannot be reverted, and has no legal way through.

The fixture fingerprint does not cover the locked versions of the MCP SDK and of pydantic, which the labeling log counts as part of the fixture. The scoring code has no fingerprint.

Nothing in the code enforces these rules: the ban on deleting the file outside the cases this ADR allows, the green gate before a change of runs or budget, the check of the cells that were red, the mechanism named for each declared cell, and the order between a declaration and the runs. Review and commit messages carry them.
