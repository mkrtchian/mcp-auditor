# ADR 032: The CVE Holdout Is Drawn Without Sides

**Date:** 2026-10-17
**Status:** Accepted
**Supersedes:** in [ADR 028](028-cve-holdout-selection.md), the 10 targets on each side of the cutoff of the default configuration at the draw, the fill to 20, the power claimed for the contrast between the sides, the requirement that adding targets, and the extension of the census that comes with them, opens a new version of the rule, and the error analysis that its consequences allow on a holdout target. In [ADR 031](031-deployment-layout.md), that only a version of the rule that extends the census adds to the layout: a new version committed before the collection of a logged extension does. In [ADR 015](015-eval-instruments-and-claims.md), that a spent target moves to the acceptance layer: under this decision it may, and need not. Also in ADR 015, that a disclosure date is recorded against a cutoff the vendor declares: a release date stands in when none is declared. The sources and criteria of the census, the salted draw order, one target per server and the 20 targets of the draw are unchanged.

## Context

ADR 028 fills the holdout with 10 targets on each side of the knowledge cutoff of the default configuration at the draw, so that a contrast between the sides shows the model's exposure to the disclosure. The holdout runs under several models, and each run already splits its targets on the cutoff of its own models. A quota of 10 on one model's cutoff then fixes, before any run, how many targets every other model finds on each side of its own cutoff, and so whether it has enough for a contrast. Some models a run can use, open-weight ones in particular, have no knowledge cutoff declared by their vendor, only the date they became available.

The rule also lets an error analysis read a holdout target. Reading spends the target, and the next flaw in draw order takes its place. The decision to analyse a target comes once the results are known, typically on a miss, so a replacement usually swaps a missed target for a fresh one and moves the number without any change to the auditor.

This decision rests on aggregate counts and simulations of the census by disclosure date and by server. No one involved computed the draw order.

## Decision

**The draw walks the salted order once, without sides, until 20 targets pass.** Without sides, the composition of the draw is the same whatever models later run on it. As before, one target per server leaves a flaw on a server with several flaws less likely to be drawn.

**Each run splits its targets on the latest cutoff of its models, a model's cutoff being its release date when the vendor declares none.** The advisory of a flaw disclosed after a release date, or after a training data cutoff, cannot be in the model's training data. A flaw disclosed before a release date need not be in the training data either, so with a release date the pre-cutoff side mixes flaws the model saw with flaws it did not. Taking the release date for the cutoff can therefore only pull the expected contrast toward zero, while the population confound that ADR 028 names can still move it either way.

**Two runs that differ only in their provider, models and reasoning levels and their cutoff, in their list of targets, or in both, compare as paired outcomes on the targets both ran.** This makes the runs under several models comparable, and keeps the primary number comparable on the targets that remain after a replacement or an addition.

**Holdout traces are never read: error analysis is done on the acceptance layer.** A trace read anyway spends its target. The log records how the reading happened and the target's detection share in the runs before the reading, so that the replacements that followed a miss can be counted.

**The acceptance layer may take any census flaw whose server gives no holdout target.** An error analysis often needs one particular CVE, because its server already has an image or because it belongs to a class under study. A flaw of a server that gives a holdout target stays out, since an error analysis of that flaw could exclude the server (ADR 028), and the server's holdout target would leave with it. For the same reason, the walk skips a flaw whose server already gives a census flaw to the acceptance layer.

**Extending the census and adding targets apply the rule as written, so they open no new version of it.** Targets are added by resuming the walk on the census in force, so an addition takes the first flaws in draw order that the walk has not reached, whether old or newly added, and moves the holdout closer to a sample of the extended census.

## Alternatives considered

**Two dates around the release of the models chosen for the contrast, with the flaws between them left out.** It fixes in advance which models get a contrast, and it excludes from the number the flaws of the draw order disclosed between the two dates.

**Quotas proportional to the census between the release dates of the models known today.** A proportional quota narrows the spread of the number only by the share of its variance that lies between the strata, which stays small for a detected-or-missed outcome unless detection differs sharply between them.

**A fixed margin before the release date as the end of the pre-cutoff side.** Where a model has both a published cutoff and a release date, the gap between them varies by months from one model to another, so the margin would be a convention deciding which flaws count as seen.

**Topping up a short side for a given model.** It adds targets for whichever model's contrast is wanted. To stay independent of the scores, it would need a rule that names the models it serves before any of them runs.

**An acceptance layer limited to the CVEs of excluded servers, or taking census flaws in reverse draw order.** Either closes every way an acceptance choice could move the holdout, but denies an error analysis the CVE it needs.

## Consequences

For a given model, the share of each side is left to chance. A side can hold fewer than 5 targets, and that model then has no contrast on this census. A model whose cutoff falls shortly before the last date the census covers has almost no post-cutoff side.

A paired comparison of two models measures their difference on these targets, including the effect of their exposure to the disclosures. At 20 targets, only a large difference is resolved.

The salt is public, so whoever logs an extension, sizes an addition or picks an acceptance CVE can compute where any flaw falls in the draw order. On that point, the holdout rests on the rule that none of these acts is decided on a holdout number nor aimed at reaching or skipping a flaw of the draw order, and on the log that records each one.
