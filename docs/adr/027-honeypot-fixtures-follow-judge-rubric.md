# ADR 027: The Honeypot Fixtures Follow the Judge-Case Rubric

**Date:** 2026-10-06
**Status:** Accepted
**Supersedes:** nothing in an earlier ADR. In the rubric of `docs/labeling-log.md`: R1 and R3, which read the mechanism of a flaw in the writings of the commit that created the server, no longer apply to a flaw planted again. R5 and R6 no longer leave a known disagreement in place when the server can be repaired.

## Context

Two instruments rest on the same three honeypot servers: the honeypot suite audits them, and the judge isolation eval draws most of its cases from those audits. The suite scores a `tool × category` cell against its label, FAIL where a flaw is planted and PASS elsewhere, and only planted flaws count ([ADR 016](016-eval-gate-governance.md)). A case of the judge isolation eval is one tool call, labeled under the clauses J0 to J11 of `docs/labeling-log.md` by whether the response or error shows a failure, planted or not, in the category tested ([ADR 025](025-judge-eval-drawn-fixture.md)).

Since one failing case fails a cell (`evals/metrics.py`), the suite and the clauses agree on a cell only if the server shows a failure in the cell's category when the cell is labeled FAIL, and none when it is labeled PASS. Four cells depart from this condition. `execute_query × input_validation` and `execute_query × error_handling` are labeled PASS, but the labeling of 2026-10-05 gave each of them a case labeled FAIL: for `input_validation`, an empty query that the tool reported as executed. In the other direction, the flaws planted behind `search_users × info_leakage` and `execute_query × injection` show no failure on any call. J5 lists what `search_users` returns on a match as the ordinary fields of a user search. `execute_query` echoes the query it receives, which J8 reads as no effect of the payload. Under J4, a tool that runs what its description says it runs does not inject by doing so. On these 4 cells, a judge that follows the clauses is scored wrong by the suite: a false positive on the 2 PASS cells whenever the generator sends the call that shows the failure, and a miss on the 2 FAIL cells.

## Decision

**A honeypot shows a failure behind every cell labeled FAIL, and behind no cell labeled PASS.** Behind a cell labeled FAIL, the server answers some call with a response or error that shows a failure in that category under the judge-case clauses. Behind a cell labeled PASS, no response or error shows one. That call is a single tool call, the unit a judge case is labeled on (ADR 025). A chain of calls does not count.

**A departure is established by reading the server against the clauses.** A judge verdict can prompt the reading, never establish it. When a server is added or repaired, or when a clause changes, the server is read against the clauses and the labeling log entry of the change records the reading.

**A server that departs is repaired.** The cell labels keep their meaning, FAIL where a flaw is planted and PASS elsewhere. A failure that the MCP library produces without going through the server's code is repaired where the server can intercept it, and stays a known disagreement under R5 where it cannot. One exception: when the failure behind a PASS cell comes from the flaw planted for another cell of the same tool, the PASS cell leaves the ground truth instead of being repaired.

**A flaw whose mechanism shows no failure is planted again with another mechanism.** The new mechanism is written from the clause of the cell's category. The repair's labeling log entry states the intent of each server branch the repair changes, and which audits of the server the repair's author had seen, if any. From then on that entry ties the mechanism to the cell, in place of the creation writings that R3 reads. When no mechanism can show a failure under the clause without changing the tool's declared function, the cell leaves the ground truth instead, and the entry says why.

**A clause is never revised to fit a server.**

## Alternatives considered

**Leaving the servers as they are.** Rejected. On the responses of these 4 cells, no verdict is correct for both the suite and the clauses.

**Labeling a cell by what the server shows.** Rejected. The ground truth would then follow failures that nobody planted in the fixture.

**Removing the cells whose planted flaw shows no failure.** Rejected. ADR 016 removes a cell whose intent cannot be recovered. Here the intent is known. Removal would also cost the suite its only planted injection.

**Revising the clauses until the planted flaws show a failure.** Rejected. The fixtures this project wrote would then define what a failure is, for the judge cases too.

## Consequences

The fixtures now follow the rubric that labels the judge cases, so an error in a clause reaches both instruments and neither can detect it.

A clause revision can require a fixture repair, and with it a reset of the baseline ([ADR 020](020-honeypot-baseline-changes.md)). A repair whose recording is refused is reverted with its recordings ([ADR 023](023-honeypot-second-recording.md)), and the server departs from this rule until another repair is recorded.

A cell whose server conforms can still be missed in every run. The rule says nothing about whether the generator sends the call that shows the failure.

A cell planted again tests another mechanism, so its results before and after the repair are not comparable. The tool's name is a judge input, which J2 and J4 read for the tool's declared function, so a repair may rename the tool when the old name contradicts the new description. The cells of the tool are then keyed by the new name, with their labels unchanged, in the commit of the repair.

The judge cases drawn before a repair keep their labels, which are decided from the judge inputs of each case (J0). Those whose response the repair changes no longer match what the servers answer, until a new draw replaces them (ADR 025).

Nothing in the code checks that a server conforms.
