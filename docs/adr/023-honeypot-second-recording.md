# ADR 023: A Second Honeypot Recording Adds Its Runs to the First

**Date:** 2026-09-27
**Status:** Accepted
**Supersedes:** in ADR 016 and ADR 020, for the honeypot suite, the agreement a second recording must show with the first to confirm it.

## Context

A first honeypot baseline stays exploratory until a second recording at the same commit confirms it (ADR 016, ADR 020). The recording code confirms it only if every cell whose observation was the same in all runs of the first recording keeps that observation in every run of the second. The confirmed baseline then holds the runs of the second recording alone.

A cell whose observation changes from run to run still looks stable across three runs some of the time. A cell that gives the wrong verdict in one run out of four is enough to make a confirmation fail about one time in four. Confirmation needs every such cell to come out the same in both recordings, so if the cells vary independently, the chance of confirming falls geometrically with their number. Each failed attempt makes the second recording the new first one. The baseline that finally confirms holds three runs in which those cells happened to look stable, among them cells that the check never covered because they varied in the first recording. Those cells enter the gated set on three runs, as they would after a single recording.

On 2026-09-27, at `d79e39d`, the second recording disagreed with the first on three cells. Over nine runs made that day with the same code under test, a refused recording included, five cells varied. Treating them as independent, the rates they showed give a confirmation about one chance in four of agreeing, and less if a cell that did not vary in nine runs sometimes does. This ADR was written after those disagreements were seen.

## Decision

**The second recording adds its runs to the first instead of testing it.** Both recordings are made at the same commit and under the same conditions, so their runs sample the same system. The confirmed baseline holds the runs of both, and a cell is stable only if all of those runs give it the same observation.

The second recording is refused on the grounds that applied before this decision. The one change is that ADR 022 now reads the combined runs, and refuses them when they leave no planted FAIL cell, or no PASS cell, stable and correct. A second recording refused because one of its runs did not complete can be made again. Refused on a floor or under ADR 022, it is not made again against the same first recording: the change that reset the baseline is reverted and both recordings are discarded, as ADR 020 does when a red cell does not come out correct.

## Alternatives considered

**More runs per recording, keeping the agreement test.** Rejected. At any number of runs, a cell whose runs look stable in half the recordings makes a pair of recordings fail the confirmation on it one time in four, so more runs move the problem to cells that vary more rarely, without removing it.

**Keeping the current rule and recording until two recordings agree.** Rejected. The baseline that passes is kept because it agreed.

## Consequences

A baseline confirmed by a second recording holds twice the runs a candidate makes. As a condition of the baseline, the number of runs is still the number one recording makes, and a candidate is compared at that count.

A cell that varies in either recording is not gated, so a regression on it is recorded as inconclusive (ADR 016). Under ADR 020, a cell that was red must come out stable and correct over the runs of both recordings.

A second recording that differs from the first as a whole no longer blocks the confirmation, for example when the model behind an alias changed between the two. It shrinks the gated set to the cells both recordings agree on, and ADR 022 refuses it once one side has no stable and correct cell left.

A baseline re-recorded from a green run follows a change, so its runs are not added to the ones it replaces. It gates on the runs of one recording, and a cell that varied in the baseline it replaces can enter the gated set by looking stable in them.
