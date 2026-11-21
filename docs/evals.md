# Evals

Two measured rates are published for `mcp-auditor`, both at commit `1765d9f`: the holdout detection rate, 0.261 (95 % Wilson interval 0.147 to 0.420), and the holdout nuisance rate, at most 0.408 (0.297 to 0.529). Each term has one meaning, defined in [`glossary.md`](glossary.md).

## What the numbers do not say

**The measured configuration is not the default one.** The detection holdout run and the nuisance holdout run used the `anthropic` provider with `claude-haiku-5-5` as generator and judge at reasoning `high`, 3 chains of 3 steps per tool, a test budget of 10, a tool call timeout of 60 seconds and no tools filter. The provider, model, reasoning and chains are not the auditor's defaults (`openai`, `gpt-6-luna` at `none`, chains off), and the default configuration has no holdout number.

**The detection rate covers only the flaws the detection suite rule makes eligible**, those whose effect a tool response can show and whose calibration passes, in the mix the draw gave: to take its 37 targets, the detection walk reached 90 flaws, gave up on 29 of them at calibration and skipped or excluded 24 others at the draw's other steps (the walk is recorded in `evals/census.json`).

**The two rates count different things.** An alarm needs only a FAIL verdict, where a detection needs a planted nonce in a FAIL. The servers differ too: 26 of the 65 nuisance holdout servers are servers of holdout targets, audited at their patched version. The two rates cannot be read as the detection and false-alarm rates of one test.

**The false-positive rate on a healthy server is not measured.** You want that number before wiring an auditor into CI, and nothing here produces it. The nuisance suite bounds a narrower quantity: the share of servers on which the auditor still raises an alarm on a tool that carried a fixed flaw and that the nuisance suite rule counts, in a category valid for that flaw's class.

**Resource abuse has no positive case.** Of the five categories the generator works from, resource abuse has no positive case anywhere here, neither in the honeypots nor among the targets of the detection suite, so a regression that removed its detection entirely would move no number.

**Only a holdout layer gives a rate.** An acceptance layer is the part of a suite the auditor is tuned on. The four acceptance targets of the detection suite (filesystem, git, kubernetes, fetch) are all spent: two had their traces read and later changes were tuned on what those traces showed, and labeling the judge fixture, whose cases were drawn from detection suite traces, spent the other two, so none can support a capability claim.

## What a detection proves

The example of the README shows an injected `echo` whose output comes back in a response. That is a reflected marker: it shows that the input took effect, but it says nothing about what the input reaches. The detection suite's acceptance target for the same flaw, CVE-2025-53355, launches the vulnerable server with a fresh nonce, a random value of the form `MCPAUDIT-<hex>`, in each of 21 places that only the flaw reaches, such as `/etc/shadow`, `~/.aws/credentials` and the environment of the server process. A detection is counted when one of those nonces comes back in a test case or chain judged FAIL, unless the auditor sent that value itself. The detecting run is then replayed with no LLM on the patched version, and a detection that the patched version also reproduces is not counted.

## Results

### Holdout detection rate

| | Rate | 95 % Wilson interval | Targets |
|:---|:---|:---|:---|
| **All holdout targets** | 0.261 | 0.147 to 0.420 | 37 |
| pre-cutoff side | 0.319 | 0.169 to 0.519 | 24 |
| post-cutoff side | 0.154 | 0.043 to 0.422 | 13 |

The detection holdout run of 2026-11-19 and 2026-11-20, at commit `1765d9f` and under detection suite rule v13, audited every one of the 37 holdout targets in all 3 runs. The rate is the mean over the runs of the share of targets detected, and its interval is taken over the 37 targets.

| Detected in | 3 runs | 2 runs | 1 run | no run |
|:---|:---|:---|:---|:---|
| Targets | 6 | 3 | 5 | 23 |

Of the 22 targets with command execution among their classes, 12 were detected at least once, compared with 2 of the 15 others. None of the 9 targets whose only class is internal fetch was detected, and no test case or chain was aimed at 4 of them. The replay struck credits in 10 audits (a target in one run) on 4 targets, and 9 of those audits lost their detection.

The run's cutoff is 2026-06-30, the last day of the month Anthropic gives as the knowledge cutoff of Haiku 5.5. The pre-cutoff side holds the 24 targets whose drawn flaw was disclosed on or before that date. The Newcombe interval of the difference between the sides (pre-cutoff minus post-cutoff), -0.142 to 0.394, includes zero, so the run cannot tell whether the auditor does better on flaws the model could have read about. The control intervals the rule checks each conclusion against (Clopper-Pearson, Jeffreys, a hierarchical Beta-Binomial under 2 priors, and a recount in which the credits the replay could not check count as misses) do not change that conclusion.

An earlier detection holdout run at `90fa641` gave 0.207 (95 % Wilson interval 0.107 to 0.362). The rate published is that of the run at `1765d9f`, the only commit at which a holdout nuisance rate exists. The entry of 2026-11-20 in [`detection-suite-log.md`](detection-suite-log.md) compares the two runs.

### Holdout nuisance rate

| | Rate | 95 % Wilson interval | Servers |
|:---|:---|:---|:---|
| **All nuisance holdout servers** | at most 0.408 | 0.297 to 0.529 | 65 |
| pre-cutoff side | at most 0.318 | 0.200 to 0.466 | 44 |
| post-cutoff side | at most 0.525 | 0.320 to 0.721 | 20 |

The nuisance holdout run of 2026-11-19, at commit `1765d9f` and under nuisance suite rule v6, audited the 65 nuisance holdout servers of `evals/nuisance_admission.json` in 2 runs, every server in both. It used the provider, models, reasoning levels, test budget, chain settings and tool call timeout of the detection holdout run above. The number of runs, 2, was set in the nuisance suite log before the run (2026-11-11): the interval is taken over the servers, so only more servers narrow it.

| Flagged in | 2 runs | 1 run | no run |
|:---|:---|:---|:---|
| Servers | 19 | 15 | 31 |

The rate describes these 65 servers, in the mix the nuisance walk gave. Of the 121 servers the nuisance walk reached, 55 are outside the nuisance holdout layer under an exit of the rule (the table by reason is in [`nuisance-suite-log.md`](nuisance-suite-log.md), 2026-11-21), and one, whose admission is pending, was not audited. The rate is published as "at most" because a fix can be incomplete, or the tool can carry a flaw no advisory reports, so some counted alarms can be true.

In the split by side, each server is placed on the side of one flaw, its first in the draw order with a counted tool, and counts as flagged only for alarms on that flaw's tools. A server flagged overall can therefore be unflagged in the split, so the sides do not average to the rate. They hold 64 servers: the only flaw of the 65th that has a counted tool lies outside the draw order. The interval of the difference (pre-cutoff minus post-cutoff), -0.436 to 0.045, includes zero, so the run cannot tell whether the two sides differ, and the control intervals of the nuisance suite rule do not change that conclusion.

The reports of the two detection holdout runs and of the nuisance holdout run are in [`evals/cve/holdout_runs/`](../evals/cve/holdout_runs/).

## The instruments

Four instruments measure the auditor, each told apart by the servers it runs and by its grader, and each backs one kind of claim ([ADR 015](adr/015-eval-instruments-and-claims.md)).

| Instrument | Runs on | Backs | Published number |
|:---|:---|:---|:---|
| Honeypot suite | 3 servers written for this project, with planted flaws | a regression guard, which gates the build on main | none |
| Judge eval | judge cases drawn from honeypot and detection suite runs | a regression guard on the judge alone | none |
| Detection suite | real servers pinned at a vulnerable version, 4 acceptance targets and 37 holdout targets | a regression gate on the acceptance layer (no baseline is recorded yet), a capability claim on the holdout layer | holdout detection rate |
| Nuisance suite | real servers at the first release that fixes every counted flaw, 65 nuisance holdout servers | a bound on the alarms raised on the tools of a fixed flaw | holdout nuisance rate |

The honeypot metrics are not published as a measure of quality: a regression guard licenses no quality claim, and the set could not carry one anyway. With 8 expected positives, one false positive moves a run's precision by about 0.11, and the metric has three or four reachable values near any bar set on it.

The two suites of the CVE benchmark take their flaws from one census, the committed list of every public MCP flaw disclosed up to its date bound ([`evals/census.json`](../evals/census.json)), collected from the GitHub Advisory Database, NVD and OSV and classified by two independent classifiers ([`evals/census_method.md`](../evals/census_method.md)). How the flaws are drawn, calibrated, graded and counted is set in advance by [`detection-suite-rule.md`](detection-suite-rule.md) and [`nuisance-suite-rule.md`](nuisance-suite-rule.md). Each detection holdout run and nuisance holdout run is recorded in [`detection-suite-log.md`](detection-suite-log.md) or [`nuisance-suite-log.md`](nuisance-suite-log.md).

## Reproducing

The holdout detection rate was produced by the detection holdout run (`uv run python -m evals.run_detection_holdout run`), and the holdout nuisance rate by the nuisance holdout run (`uv run python -m evals.run_nuisance run`), both under the run conditions `evals/holdout_conditions.json` records and the provider, models and reasoning levels set in the environment (`MCP_AUDITOR_PROVIDER=anthropic`, `MCP_AUDITOR_MODEL=claude-haiku-5-5`, `MCP_AUDITOR_REASONING=high`). The prerequisites, every command and its exit codes, the gates and the safety of the fixtures are in [`CONTRIBUTING.md`](../CONTRIBUTING.md#cve-benchmark).
