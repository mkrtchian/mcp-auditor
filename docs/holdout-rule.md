# CVE holdout selection rule

This is the selection rule of the holdout layer of the CVE benchmark. The decisions behind it are in [ADR 015](adr/015-eval-instruments-and-claims.md) and [ADR 028](adr/028-cve-holdout-selection.md). Its changes, the excluded servers, the dropped targets, the cutoffs, the classes of the grammar and every other act this rule says is logged are in [`holdout-log.md`](holdout-log.md).

## Census

The census and the calibrations are done by LLM agents. The maintainer chooses the model of a census or a calibration before it starts and does not change it while it runs, and the census records the model ID of each agent.

**What counts as an MCP server.** An MCP server is a program that serves the Model Context Protocol to a client and exposes tools, distributed as a package or a public repository. Clients, hosts, inspectors, registries and SDKs are not servers, and a flaw of an SDK is not a candidate. A server is one package, or one repository when it is published only as a repository. When one package of a repository is an excluded server, the other packages of that repository stay candidates.

**The unit of the census is one flaw.** It is identified by its CVE ID in upper case, or by its GHSA ID as GitHub writes it when it has none. When several IDs describe one flaw as it enters the census, the lowest CVE ID that is not rejected (by year, then by number) is kept. The identifier, once recorded, never changes, even when a CVE ID is assigned or found later, so its draw hash never changes. A flaw found again under another ID, in this census or in the census of a later version, is matched to its recorded entry and not added twice.

**Sources.**

1. The GitHub Advisory Database, reviewed advisories only, through its public repository `github/advisory-database`.
2. The NVD, through its JSON data feeds.
3. OSV, through its data export, for the advisories the first two do not carry.

**Collection.** One agent per source runs a broad pre-filter on it, then reads every flaw the pre-filter returns and keeps every flaw of software that implements MCP: servers, clients, hosts and SDKs. The pre-filter, as first written, matches without regard to case the strings `mcp` and `model context protocol` anywhere in the advisory text or in the names of affected packages (on the NVD, in CPE product names). Each agent also looks beyond the pre-filter in its source, for instance at other advisories of the organizations that publish MCP servers, and records each flaw it finds there as a gap of the pre-filter.

**Recall.** Three more agents search, one per angle set in their instructions: the MCP vulnerability aggregators and security blogs, the security advisories of MCP server repositories, and servers whose names do not contain `mcp`. A flaw they find enters the census only through an advisory in one of the three sources. Every MCP CVE that `vulnerablemcp.info` lists with a disclosure date within the census must be found, or recorded as absent from the three sources. For each flaw found outside the pre-filter, by any agent, the pre-filter gains a string or a package name that matches it, and the collection runs again. These widenings are recorded in the census and open no version of this rule. The census is complete when the pre-filter, as last widened, finds every flaw the agents found.

**Classification.** Two agents classify every flaw of the census, each in its own context, from its advisory and the pages it links to, without access to this repository or its prompts. Each records, per flaw: the server package and its versions, whether a vulnerable version and its first patched version can both be pinned, the disclosure date, the transport, the MCP primitive, whether the effect shows in a tool response, whether the server appears able to run in a container (no third-party service, credential or proprietary binary needed), the effect class (one of the grammar's, or another class it names), and for an ineligible flaw the first of the criteria checkable from an advisory (see Eligibility) that it fails, in their listed order. Every field is filled for every flaw, even after a first failed criterion. Their agreement is recorded as the share of flaws on which they agree, field by field. Until a disagreement is settled, a flaw counts as meeting a criterion when either agent finds that it does. A flaw counts in a class outside the grammar only when both agents place it outside the grammar. For the candidates the draw reaches, the maintainer settles each disagreement criterion by criterion, never on a guess about what the auditor would detect, and records each settlement with its reason. The maintainer groups the flaws placed outside the grammar into distinct classes, recording the grouping and its reason, and applies the exclusions to the classified flaws.

**The disclosure date** of a flaw is its earliest publication date across the three sources, compared as a UTC calendar day. The census covers every flaw disclosed on or before the committer date of the commit that introduces version 1 of this file. The census of a later version that adds targets extends to the committer date of that version's commit.

**Output.** The census is committed as `evals/holdout_census.json`, before and after each draw and each replacement. It refers to the large artifacts it read instead of holding them: the commit of `github/advisory-database`, the date and SHA-256 of each NVD and OSV export, and for each pinned version, the integrity hash npm or PyPI publishes, or its commit SHA when it is pinned as a commit. It records the grammar fingerprint at the draw, the calibration records and cards, and two coverage figures: the share of MCP server flaws the auditor can reach (stdio transport, Tools primitive, effect in a tool response), and among those, the share the grammar covers. It also reports, over every MCP server flaw of the census, the shares by transport, by MCP primitive, by effect class, and of effects that do not show in a tool response, and the number of flaws disclosed each month.

## Eligibility

A flaw is eligible when all of these hold:

- it is a flaw of an MCP server, as defined above.
- the server runs over stdio, and the flaw is reached through `tools/call`.
- its effect shows in a tool response.
- its effect falls in one of the classes of the grammar (listed in the log).
- a vulnerable version and the first patched version can both be pinned, as a release or a commit of a public source.
- both versions run in Docker.
- the calibration passes as it does on the acceptance layer: on the vulnerable version, the exploit written from the published mechanism surfaces every proof kind its class admits and reads as aimed under the target's aim predicate, and the benign call surfaces none and does not read as aimed. Beyond what the acceptance layer checks, on the patched version the benign call returns no error and the exploit surfaces no proof.

The first five criteria are checkable from an advisory. With the first two exclusions below, they are the criteria of the draw order.

A flaw is excluded when any of these holds:

- it is a target of the CVE benchmark, now or before (the current targets are in `evals/cve_targets.py`, the dropped ones in the log).
- its server is an excluded server, listed in the log, or a package built from a repository GitHub marks as a fork of an excluded server's repository.
- for a drawn candidate, the maintainer finds that its vulnerable code is taken from an excluded server, and records the evidence in the census.

**Calibration.** Candidates are calibrated in draw order by an LLM agent. From the advisory and the published mechanism, it writes the fixture of the candidate, the place of its sentinel, its aim predicate, the exploit and the benign call. It works from the fixture format and the grammar of the benchmark, without access to the auditor's code, its prompts, its results or its traces. Its instructions are to make each candidate reproduce. It makes as many attempts as it needs, and gives up on a candidate only when it concludes that the calibration cannot pass in a container, with that reason in its own words. The census records the number of attempts and, for a give-up, its reason in one sentence. The maintainer does not exclude a candidate at calibration. When the agent gives up on a candidate, a second calibration follows at once, in a fresh context that receives the record of the first. A second give-up excludes the candidate, and both reasons are recorded.

**Calibration card.** For each candidate that passes, the agent writes a card into the census: the mechanism as the advisory states it, where the sentinel is planted and why only the flaw reaches it, the exploit call, the benign call, and the result on the patched version. A second LLM agent, without access to the auditor either, checks each card against the advisory and the fixture, and reports any gap to the maintainer. The maintainer reads every card before the candidate enters the holdout. A gap the maintainer confirms, criterion by criterion and recorded with its reason, sends the candidate back to calibration. Reading a card spends nothing.

## Sides

The cutoff of a draw is the latest knowledge cutoff the vendors declare for the models of the default configuration (generator and judge) at that draw, with its type (as the vendor words it, for instance training data or reliable knowledge), and with a note when the vendor only gives the cutoff of a base model. It is recorded in the log, as is the cutoff of every model a holdout run uses, with the same type and note. A flaw whose disclosure date is on or before it sits on the pre-cutoff side of that draw, a later one on the post-cutoff side. The sides of a draw only set the composition of the holdout: a run reports its split on the cutoff of its own models (see the split by side).

## Grammar trigger

The trigger is applied on the complete census before the draw, and again on the census of any version that adds targets, before its draw. Classes outside the grammar are the ones the maintainer grouped (see Classification). A class outside the grammar enters when all of these hold:

- it holds at least 10 % of the flaws that meet the criteria of the draw order, the class criterion aside, and whose server appears able to run in a container. That last judgment counts only here: the draw does not skip a flaw on it, and calibration settles it.
- it holds at least 2 of them.
- the maintainer shows that its effect can be proven deterministically in a tool response.

The maintainer adds an entering class to the grammar and calibrates its proof on a fixture written for that class, or on an acceptance target of an excluded server when one exists, never on a holdout candidate, so the flaws that triggered it stay candidates. The change has a labeling log entry and resets the acceptance baseline (ADR 024). The grammar is then frozen again, and the draw uses its new classes. A class below the threshold is reported as a known gap, with its share.

## Draw

The flaws are sorted in ascending order of the lowercase hexadecimal SHA-256 digest of the UTF-8 string `"mcp-auditor-holdout:" + id`, where `id` is the census identifier and the prefix is the salt. The order covers the flaws that meet the criteria of the draw order. Both sides are walked in that one order, each flaw filling its own side until the side holds 10 targets. Each flaw reached goes through these steps, in this order:

1. its disagreements are settled.
2. it is skipped, and the skip recorded, if its server already gives a target to the holdout, on either side.
3. the maintainer checks its vulnerable code against the excluded servers.
4. it is calibrated.

It enters only if it is still eligible, its calibration passes and the maintainer has read its calibration card. A flaw the walk passes over because its side is full is not reached. If the post-cutoff side ends with fewer than 10 targets, the walk takes up again the pre-cutoff flaws it passed over, in draw order, until the holdout holds 20 targets. Classes have no quota. The class of each target is reported. If fewer than 20 flaws pass in all, the holdout takes every one that passes.

## Run conditions and statistic

Before each holdout run, every vulnerable image is built again from its committed Dockerfile, with the build cache, and its target calibrated on the vulnerable version. A target that no longer passes is reported as not run and left out of N, the number of targets the statistic counts, until its fixture is repaired. Repairing a fixture is calibration, done by the calibration agent, and spends nothing. The patched versions are calibrated at the draw only, and are not audited.

A holdout run audits every target at one commit, under these conditions:

- 3 runs, budget 10, no tools filter, and the list of targets.
- the provider, models and reasoning levels of the run, default or not, and their cutoff. A run refuses to start when the cutoff of one of its models is not in the log.
- the grammar fingerprint, and the fixture fingerprint of each target.

The commit of this file, the commit of the census and the image ID of each target are recorded as provenance, not as conditions, as ADR 024 decides for image IDs.

If the cost of a holdout run has to come down, the runs go from 3 down to 1 before any target is cut, since only targets narrow the interval (ADR 015). The change is logged, and the new number of runs is a condition of the runs that follow.

**The primary number is the mean over the runs of k/N**, the share of targets detected in one run, averaged. A target counts as detected in a run when its status is in `DETECTION_RUNGS`. Its detection share is the fraction of the runs that detect it. The cited interval is the 95 % two-sided Wilson score interval, without continuity correction, over the N targets with the sum of the detection shares as the count, never over the N × runs verdicts. The number speaks about the eligible flaws under this rule, in the composition the draw gave each side, and not about MCP flaws at large.

Beside it, each holdout run reports the composition of each side and the full ladder of statuses. Per target, it reports the detection share, the runs where a proof surfaced, the runs where a unit aimed at the flaw, the runs where an aimed unit judged FAIL in a category its class admits surfaced no proof (`fail_without_proof`), and the number of tools. It also reports the cost of the run in dollars, at the vendors' list prices on the day of the run.

**The split by side.** Each holdout run reports the primary number of each side of the cutoff of the models it runs, default or not. A side left short of targets by a later cutoff triggers no new target.

**The contrast between two sides** is a difference of proportions, with each side's sum of detection shares as its count, and its 95 % two-sided Newcombe hybrid score interval, without continuity correction, computed only when each side holds at least 5 targets. Below that, both sides are reported next to each other, without a test.

**Every conclusion drawn from an interval is checked.** A conclusion is a statement that an interval lies above or below a value, zero for the contrast. For the primary number: the Jeffreys and Clopper-Pearson intervals on the same count, Clopper-Pearson in its Beta-quantile form for a non-integer count, and the hierarchical Beta-Binomial credible interval with the target as cluster and its detected runs binomial over the runs (θ ~ Beta(1, 1), and d, the concentration of the per-target rates around θ, ~ Gamma(shape 1, scale 1), then ~ Gamma(shape 2, scale 2)). For the contrast: the Agresti-Caffo interval, and the difference of the two hierarchical posteriors with one d shared by both sides. Only the Wilson and Newcombe intervals are cited. A conclusion that changes with the method is reported as inconclusive, with the intervals that disagree.

**Two primary numbers compare** only under the same run conditions, as paired outcomes on the same targets: a target is gained when its detection share rises and lost when it falls. A target not run in either of the two leaves the comparison. They never compare by the overlap of two intervals. Otherwise they are reported side by side.

**An audit with a step refused by the model provider and no detection counts as not detected in that run**, and the number of such audits is reported, with the targets they touch. A detection stands whatever step was refused. A refused audit is not attempted again, unlike on the acceptance layer, since a retry until no step is refused would keep the best of several attempts. A failure to launch the fixture, or an audit that ends on any other error, is retried at most 2 times. A target that still fails in any run is reported as not run for the whole holdout run and left out of N, so N is the same in every run.

## Reading

A holdout target is spent as ADR 015 defines it. So that running the holdout spends nothing, a holdout run writes and prints no proof text (`evidence`), no judge input and no verdict per case, only the statuses and the counts above. It exports no judged case, and refuses to start when `LANGSMITH_TRACING` or `LANGCHAIN_TRACING_V2` is set. Holdout targets stay out of every other instrument: the acceptance gate of ADR 024, the draw of the judge fixture and the probe corpus. Before the draw, the contamination test of ADR 014 is extended to the text the excluded servers produced in the CVE cases of the judge fixture (tool descriptions, responses and errors, the auditor's own payloads echoed back left out), and it passes on the code of that day. The auditor is then not fitted to the text of an excluded server, which a holdout server built on the same framework or the same conventions could also emit.

When the traces of a target feed a decision (a change to a prompt, a guard or the oracle, or a case of the judge fixture), its server is listed in the log as an excluded server the same day. Reading traces without such a decision spends the target read, not its server. A server excluded after a draw, or a package built from a fork of its repository, takes its drawn target out of the holdout, and the target is replaced.

Holdout traces are never read, except for an error analysis: a deliberate act, logged with its reason, that spends the target it reads. Its server is excluded only if the analysis leads to a decision as defined above.

No change to the auditor is made or reverted because of a holdout number. A change made or reverted because of a holdout number is reversed, and the reversal is logged.

A spent target moves to the acceptance layer, with a tools filter. It is replaced by the first flaw of its side, in draw order, that the walk has not yet reached, or of the pre-cutoff side when the post-cutoff side has none left, and the replacement is logged.

## Versioning

This is version 1. Any edit of this file opens the next version. A new version keeps the salt and the draw order, and applies its criteria again: a target that stays eligible stays drawn, with its calibration. A target that no longer is leaves the holdout and is replaced as above. A flaw that becomes eligible enters only to fill such a vacancy. Adding targets, to grow the holdout or to bring the post-cutoff side to the 5 targets its contrast needs, is a deliberate new version, never automatic. It extends the census to the flaws disclosed since, under its own criteria and the same draw order, and sorts every flaw, old and new, into sides on the cutoff of its own draw. Its quotas and replacements count sides on that cutoff, and the targets already drawn stay drawn.
