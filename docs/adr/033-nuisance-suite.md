# ADR 033: The Nuisance Suite Counts Alarms on Patched Versions

**Date:** 2026-10-22
**Status:** Accepted
**Supersedes:** in [ADR 015](015-eval-instruments-and-claims.md), that the nuisance suite runs over healthy patched servers and would measure the false-positive rate on a healthy server. It runs over patched versions, which can still hold flaws, and its claim is a bound on false alarms.

## Context

Under ADR 015, no claim about false alarms is published until a nuisance suite runs. The holdout layer of the CVE benchmark measures how often the auditor detects a flaw on its vulnerable version ([ADR 028](028-cve-holdout-selection.md)). It cannot say how often the auditor raises an alarm where there is nothing to find.

A healthy server, one with no known flaw, has no ground truth. The version that fixes a known flaw has one for that flaw, on the tools that carried it.

## Decision

**On the patched version, a case or a chain counts as a false alarm when it calls a tool that carried a fixed flaw and is judged FAIL in a category valid for the flaw's class.**

**The code that applies this definition, the counter, is separate from the grammar of the CVE oracle and has its own fingerprint.** It reads the categories valid for a flaw's class from the grammar, so a flaw counts only when its class is one the grammar grades. Keeping the counter out of the grammar lets each one change without the other: a change to the counter neither resets the baseline of the CVE acceptance gate nor makes a holdout number exploratory, whereas a change to the grammar does both.

**The unit is the server, built at the first pinnable release that fixes every one of its flaws in the holdout's census ([ADR 028](028-cve-holdout-selection.md)) that the suite counts.** A flaw counts when the grammar grades it, a tool call reaches it, its effect shows in a tool response and its vulnerable version is pinnable. No counted flaw is then still open on that release. Since a user runs one audit, the figure is the share of servers flagged in one run.

**The figure is read beside the holdout's detection rate at the same commit, under the holdout's run conditions apart from the number of runs, so the two numbers describe one auditor.** The number of runs changes how precise the figure is and leaves the auditor it describes unchanged, so this suite sets its own number of runs. An auditor that probes less raises fewer alarms, but only the holdout shows what that costs in detection.

**Each run also reports the figure on each side of the cutoff of its models, as the holdout does ([ADR 032](032-holdout-drawn-without-sides.md)).** A model that read an advisory knows the tool the advisory names and can aim at it on the patched version.

**Before each run, a benign call to each tool the suite counts must succeed without error on the patched version**, so a server whose tool cannot work does not pass as clean. A tool whose declared function is the effect of its flaw's class does by design what its class names. An alarm on it, or on a tool whose backend the container cannot provide, can be true or false and only reading its trace would tell which, so both leave the count, as a tool the fix removed does.

**Servers enter in the holdout's salted draw order, at least as far as the holdout walk has gone, each with the census flaws the suite counts.** No one chooses which servers enter. Past the flaws the holdout walk has reached, the suite takes more servers only through a logged addition, sized as a number of servers that enter the figure and never decided on an alarm number of this suite.

**Each server is admitted by two independent agents blind to the auditor**, so that what enters the suite and how it is built is not fitted to the auditor. Reading the advisory does not show whether the chosen version really fixes the flaw, so each counted flaw is checked by reproduction: an exploit surfaces a planted witness on the vulnerable version and not on the patched one, where the benign call still works. This check is the holdout's calibration, with the witness at the flaw's own location, so the suite can take servers the holdout dropped because their flaw reaches no place of the holdout rule's list of places or deployment layout. The criteria and the procedure are written in `docs/nuisance-rule.md` and versioned in `docs/nuisance-log.md`.

**Only the acceptance servers are read, and only those with a current target are gated.** Every other server is report-only and never read. The holdout servers, which version 8 of the holdout rule lets in, are among them because a decision fed by their traces would exclude them, whatever version of the server produced the traces ([ADR 028](028-cve-holdout-selection.md)). So are the census servers that are neither excluded nor in the holdout, which a later addition can still draw ([ADR 032](032-holdout-drawn-without-sides.md)). No change to the auditor is made or reverted because of a number of this suite on the report-only servers.

## Alternatives considered

**Admitting every server of the census that the nuisance rule finds eligible.** The admission, the images and the cost of a run would grow with each extension of the census, without anyone deciding it.

**Labeling every FAIL on healthy servers.** A healthy server has no ground truth, so every FAIL would need a label written after reading its verdict. Every run would bring new FAILs to label, since the auditor's payloads change between runs.

**The grammar's own `fail_without_proof` as the counter**, aimed at a flaw that surfaced no nonce and was judged FAIL in a category its class admits. It carries no tool name, so it counts alarms on other tools, and when its aim test is narrow it misses alarms on the flaw's own tool. An "at most" on it would be wrong both ways.

**Auditing a vulnerable twin per server, paired with the patched version.** An alarm there would not show the auditor found the flaw, with no nonce to prove it, and the holdout already measures detection with a proof. The fix check does build a vulnerable image, but it runs mechanically and is never audited.

**Keeping the images built at the first run for every later run.** The fixtures leave their dependencies floating by design ([ADR 024](024-cve-acceptance-gate.md)), so a frozen image would measure the auditor on one resolution of them, and the figure would stop following their drift.

**One flaw as the unit, with an interval clustered by server.** Several flaws of one server share one audit, so their outcomes are correlated. Counting servers removes that correlation and the need for a clustered interval.

## Consequences

The figure, published as "at most" with its interval, bounds the false alarms of a fixed flaw's class on that flaw's tools. A FAIL on one of these tools in another category is not counted, nor is one on another tool, so the false-positive rate a user sees on a healthy server stays unmeasured. The suite counts only a flaw the grammar grades whose effect shows in a tool response, so a server whose only visible flaw is of another class does not enter. A tool whose declared function is the effect of its flaw's class leaves the count, so a judge that takes that function for the flaw does not show in the figure. Some counted alarms are true: the fix can be incomplete or miss a variant, the tool can carry a flaw no advisory reports, or the advisory can get the fixed version wrong.

A server with more counted flaws has more tools on which the auditor can raise an alarm. The draw order sorts flaws, not servers, so a server with many flaws is reached earlier. As long as the walk does not take every server, the figure leans toward servers with many flaws in the draw order.

Between two runs, an update of a floating dependency can change what a tool does without breaking the benign call, and nothing detects it.

The gate holds only the acceptance servers with a current target, which the auditor was tuned on. A change that raises alarms only on report-only servers shows in the figure, but no number of this suite can revert it.

At the sizes the census allows, only a large gap between two models can be resolved. Using the report-only servers to choose a model would need a decision of its own, as for the holdout.
