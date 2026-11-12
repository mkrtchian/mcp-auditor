# Glossary

This file is the project's ubiquitous language, in the sense of Domain-Driven Design: the code, the docs and the rules use the same words, with one meaning each. The project is a single bounded context, so a term means the same thing in the auditor and in every instrument. The file describes the vocabulary as it stands now. ADRs and plans keep the words of their date, and some of those words have moved to another meaning since: [`glossary-log.md`](glossary-log.md) maps them to the current terms, and lists the words whose meaning moved. Before writing a word this file does not list, look it up in the log: a renamed or retired word is no longer written, and a word whose meaning moved is written only in its current sense.

The two rules, [`docs/detection-suite-rule.md`](detection-suite-rule.md) and [`docs/nuisance-suite-rule.md`](nuisance-suite-rule.md), are handed to agents that never see this file, so each rule defines every term it uses. If this file and a rule disagree, follow the rule. Where an entry names the rule section or ADR that defines a term, that text is the definition, and the entry is a short summary of it.

Each entry gives the term and what it means. `Code:` names what a user types or reads for it (a command, a flag, a file, a key or value of a JSON file), or an identifier of the code that differs from the term and stays, `Not:` names a term it can be confused with, and `Defined by:` names the rule section or ADR that defines it.

## How the evaluation is organized

The auditor sends test payloads to each tool of an MCP server, and an LLM judge rules each response PASS (the server held) or FAIL (a weakness showed). An attack chain is several such calls toward one goal.

The auditor is measured by several instruments. The honeypot suite runs on three servers written for this project. The judge eval runs on judge cases drawn from honeypot runs and from CVE benchmark runs. The **CVE benchmark** runs on real MCP servers with published flaws. It is not an instrument itself: it holds two suites, and each is one.

- The **detection suite** audits each server at a pinned vulnerable version, one target per flaw. It counts a detection when a nonce, a random value placed where only the flaw reaches, comes back in a test case or chain judged FAIL.
- The **nuisance suite** audits each server at the first release that fixes every flaw the suite counts. It counts the alarms the auditor still raises on the tools of those flaws.

Each suite of the CVE benchmark has two layers. The **acceptance layer** is the part the auditor is tuned on, like a dev set: its traces are read, changes are decided on it, and a gate guards it against regressions. The **holdout layer** is never read (nobody opens its per-case traces), like a test set. Its number is the only one that can be published: the **holdout detection rate** for the detection suite and the **holdout nuisance rate** for the nuisance suite. The holdout nuisance rate is always preceded by "at most", since some of the alarms it counts can be real flaws a fix missed. The holdout detection rate covers only the flaws whose effect a tool response can show and whose calibration passes. The holdout nuisance rate does not measure the false-positive rate a user sees on a healthy server.

| | acceptance layer | holdout layer |
|---|---|---|
| detection suite | acceptance targets, read, gated by the detection gate | holdout targets, never read, the holdout detection rate |
| nuisance suite | nuisance acceptance servers, read, gated by the nuisance gate | nuisance holdout servers, never read, the holdout nuisance rate |

Both suites take their flaws from one **census** of published MCP flaws. Their holdout layers take them in one salted **draw order**, and the detection holdout layer takes one holdout target per server. The detection acceptance layer can take any census flaw whose server is not the server of a holdout target.

A holdout number can be trusted because its rule is pre-registered, its flaws come in a hash order nobody chooses, its fixtures are written by agents blind to the auditor, and a run of a holdout layer writes no per-case output, so its traces cannot be read. On the detection suite, a detection that the patched version also reproduces is not counted. Each rate is also reported separately for flaws disclosed before and after the models' knowledge cutoff, so a reader can see whether the auditor does better on flaws a model could have read about. These guards do not make the rates precise: with a few dozen targets or servers, only large differences show.

**Word order.** A layer and its members are named suite first, then role: "detection holdout layer", "nuisance acceptance server". A rate is named role first, then measure: "holdout detection rate". The words "holdout server" and "acceptance server" are always qualified by their suite, since the two suites share servers. The word "target" needs no qualifier, since only the detection suite has targets.

## The auditor

- **audit**: one invocation of the auditor against one MCP server.
- **audited server**: the MCP server an audit launches and sends payloads to. Not: target, which belongs to the detection suite.
- **server command**: the command and arguments that launch the audited server. Code: `server_command` in the JSON report.
- **execution regime**: how the audited server runs: `unconfined` (a process on the host), `declared_container` (a `docker run` the user wrote) or `confined` (the default container the auditor builds). Defined by: ADR 017, ADR 018.
- **audit run options**: the test budget, chain budget, resume and dry run of one audit.
- **category**: one kind of weakness the generator writes test cases for and the judge rules on, such as input validation or information leakage, mapped to the OWASP MCP Top 10. Not: class, which is the effect of a census flaw. Defined by: ADR 008, ADR 012.
- **payload**: one generated test input for a tool: its category, a description and its arguments (the dictionary passed to the tool).
- **test case**: a payload sent to a tool, with the response and the judgment. Not: the `cases` of `TestCaseBatch`, which are payloads. That name is sent to the model, so it stays.
- **processed cases**: every test case an audit handled, blocked and unjudged ones included.
- **attack chain**: a sequence of tool calls the auditor plans toward one goal, each step observed before the next is planned. Defined by: ADR 010.
- **chain step**: one tool call inside an attack chain.
- **attack context**: what the auditor learned on earlier tools and carries to the next ones. Defined by: ADR 009.
- **judge**: the model call that rules PASS or FAIL on a test case or a chain. A judgment is its answer: the verdict, a justification and a severity.
- **judge result**: a judgment with the identity and arguments of its case. Code: `judge_result` in the JSON report.
- **verdict**: PASS or FAIL. Code: `EvalVerdict`, a name sent to the model in the judge's schema, so it stays.
- **finding**: a FAIL in the audit report. Not: the "findings" the context-extraction prompt asks for, which are what the auditor learned.
- **severity**: how serious a finding is, from low to critical.
- **judge criteria**: what the judge prompt tells the judge to check. They are written to match the labeling rubric. Not: labeling rubric.
- **model call kind**: the kind of request an audit sends to a model: test generation, judgment, context extraction, chain planning, chain step observation, chain step planning, chain judgment. Not: the README's phases (discover, generate, execute, judge, chains), which are prose and have no identifier.
- **missed model call**: a model call that gave no usable answer, through a provider refusal, an unreadable answer, or throttling that lasted past every retry. The report lists it with its cause, beside the coverage gaps. Like a coverage gap, it makes the audit incomplete, and `--ci` exits 3. Code: `missed_model_calls` in the JSON report.
- **provider refusal**: the model provider declined to answer.
- **coverage gap**: a tool the audit could not cover in full, such as fewer test cases than the budget asked.
- **destructive-payload guard**: the guard that stops a payload able to destroy data from reaching the server. Defined by: ADR 013.
- **blocked payload**: a payload the guard stopped.
- **relayed environment**: the variables an audit passes to the audited server with `--env` and `--env-plain`. Defined by: ADR 026.
- **redacted variables**: the variables passed with `--env`. Code: `redacted_variables` in the JSON report.
- **redaction marker**: `[value of NAME, redacted by mcp-auditor]`, the text that stands for a redacted value. Not: reflected marker.
- **reflected marker**: what an injection payload makes the server print back, an echoed string or the output of `id` or `whoami`. It shows that the input took effect, and it says nothing about what the input reaches. Defined by: ADR 014. Not: redaction marker.
- **dry run**: an audit that generates payloads and sends none.
- **resume**: continuing an interrupted audit from its checkpoint, found by its thread id. Code: `--resume`.

## Instruments and how a change is judged

- **instrument**: an eval that backs one kind of claim, told apart by the servers it runs and by its grader. The honeypot suite, the judge eval, the detection suite and the nuisance suite are instruments. The acceptance and holdout layers of a suite are built and graded the same way, so they are one instrument read two ways. The model probe is not an instrument: it helps choose a model and backs no claim about the auditor. Defined by: ADR 015.
- **system under test**: what an instrument measures: the auditor, with its prompts, guards, defaults and model.
- **agent**: an LLM agent working in its own context, on a task a rule defines. Census classifiers, judge eval labelers, calibration agents, card checkers and admission agents are agents. The maintainer, a person, settles their disagreements.
- **suite**: an instrument made of servers it audits: the honeypot suite, the detection suite, the nuisance suite.
- **trace**: the per-case record of an audit: the payload, the response, the judge's input and its verdict.
- **honeypot suite**: three MCP servers written for this project with planted flaws, audited end to end and graded cell by cell against a ground truth. It is a regression guard, and its numbers are not published as a measure of quality. Code: `python -m evals.run_honeypot_suite`. Defined by: ADR 015, ADR 016, ADR 020.
- **honeypot**: one of the three servers, `tests/honeypot_server.py`, `tests/subtle_server.py` and `tests/chain_honeypot_server.py`.
- **planted flaw**: a flaw written into a honeypot on purpose. Only planted flaws enter the honeypot ground truth.
- **cell**: one (tool, category) pair of the honeypot ground truth, the unit the honeypot gate compares. A cell is **stable** when it has the same outcome in every run of the baseline.
- **ground truth**: the expected verdict of each cell.
- **labeling rubric**: the written clauses that set the honeypot ground truth and the labels of the judge cases, each applied to every cell or case it covers. Defined by: `docs/labeling-log.md`, ADR 025, ADR 027. Not: judge criteria.
- **honeypot gate**: the gate of the honeypot suite. It compares a candidate run to the baseline cell by cell and checks the floors. Its report tags a cell `miss` (a planted flaw never found), `false_positive` (a cell with no planted flaw judged FAIL in every run) or `improved` (a cell wrong in the baseline that comes out right in every candidate run). Defined by: ADR 016, ADR 020.
- **judge eval**: the eval that grades the judge alone on a fixed set of drawn judge cases. Two independent labelers write the labels blind to the judge's verdict, and the maintainer settles their disagreements. Code: `python -m evals.run_judge_eval`. Defined by: ADR 025.
- **judge case**: one input to the judge eval, a tool call and its response, with its label.
- **model probe**: the tool that sends a frozen corpus of captured prompts to the reference model and to candidate models, and reports statistics and defects of their answers. Code: `python -m evals.run_probe`. Defined by: `evals/probe_method.md`.
- **graded run**: a run whose results a deterministic grader scores: the ground truth on the honeypot suite, the labels on the judge eval, the oracle on the detection suite, the counter on the nuisance suite. A gate compares it to a baseline, unless it runs with `--no-baseline` or on a holdout layer.
- **gate**: the comparison of a candidate graded run with a confirmed baseline, which decides green, red or not comparable on the system under test: the gate outcome. There are four: the honeypot gate, the judge gate, the detection gate and the nuisance gate, the last two on the acceptance layer of their suite. A green gate means only that there is no regression against the baseline under the same recorded conditions. Not: check.
- **check**: a verification of the instrument or of what it runs on, never of the auditor: the calibration check, the fix check, the layout check, the route check, the pre-run check, the vet and the preflight run with no LLM, and the card check is done by an agent. It says whether the instrument still works. Not: gate.
- **baseline**: the recorded results a gate compares a candidate run to. A first baseline is **unconfirmed** after one recording, and **confirmed** once a second recording at the same commit adds its runs to the first. Only a confirmed baseline gates. Against an unconfirmed one, a run is guarded by the floors alone. A re-recording from a green gate replaces a confirmed baseline in one recording, and the new baseline is confirmed. Code: `unconfirmed`, `confirmed` in a baseline file. Not: confirmatory, the status of a number. Defined by: ADR 016, ADR 020, ADR 023, ADR 024.
- **re-recording**: recording a baseline again from a green gate. It is never done while the gate is red. Defined by: ADR 016.
- **reset**: deleting a baseline in the commit that changes a fixture, the scoring code, the model, the runs or the budget, then recording it twice. On the detection suite, a change to a target's fixture resets that target alone. Under a red gate, the cells that fired it must come out stable and correct in the confirmed baseline, or the change is reverted. Defined by: ADR 020, ADR 024.
- **floor**: an absolute bar that detects a collapse and does not measure quality: recall and precision, plus distribution coverage on the honeypot suite. Floors apply to every graded run of the honeypot suite and the judge eval.
- **`--no-baseline`**: a graded run that does not read the baseline. The honeypot suite and the judge eval still check their floors, and the detection suite reports and exits 0.
- **flip**: a gated cell or case that comes out wrong in a candidate run. A cell or case is gated when it is stable and correct in the confirmed baseline. The detection suite calls the same event a miss on a gated target, and the nuisance suite an alarm on a gated server.
- **retest**: auditing or judging again, on its own, the honeypot, judge case, target or server where a gated flip, miss or alarm occurred, to see whether that outcome reproduces. Each gate's rule fixes in advance how many retests it runs and how many must reproduce. Not: retry, which follows a technical failure. Not: replay. Defined by: ADR 016 (a flip "re-tested"), ADR 024 (where it is called the replay rule).
- **regression**: a flip, miss or alarm on a gated cell, case, target or server that reproduces under the retest rule. It turns the gate red.
- **declared flip**: a gated cell or judge case that a change to the system under test is expected to cost, named in `evals/declared_flips.json` with the mechanism that reaches it, before the evals run on the change. Defined by: ADR 020.
- **inconclusive**: an outcome that cannot be read as a change. It covers a cell, case or server unstable in the baseline that goes wrong in the candidate, and a delta smaller than the instrument's resolution (the smallest difference it can tell from noise). It also covers a conclusion that changes with the interval method (Wilson or another), when unchecked credits count as misses, or when audits with a missed model call count as flagged.
- **held**: a gated target or server that kept its baseline behavior.
- **exploratory**: the status of a number that confirms nothing. It is either a number produced by a change found by reading eval output, or a holdout detection rate graded before a change of the grammar. A **confirmatory** number needs a bar written before the measurement ran, or data the change was not derived from. Not: unconfirmed, the status of a baseline. Defined by: ADR 016.
- **deletion test**: the test a change to the system under test found by reading eval output must pass before it ships: its written justification still holds once every mention of the measurement is deleted. Defined by: ADR 016.
- **read**: opening a per-case trace, a judge input or a judge verdict, by hand or through an agent that reports back. A run summary, a calibration output and a harness log are not read in this sense. Defined by: ADR 015.
- **spent**: read, or used to justify a change to a shipped prompt. Reading a nuisance trace of a detection holdout server spends its holdout target too. Defined by: ADR 015, detection suite rule (Reading), nuisance suite rule (Reading).
- **pre-registered**: written and committed before the runs it governs. Any edit of a pre-registered rule opens its next version.
- **blind to the auditor**: working in a kit with no access to the auditor's code, prompts, results or traces, so that what the agent writes cannot be fitted to the auditor.
- **fingerprint**: a hash of what a part of an instrument depends on: a fixture, the grammar, the counter, the ground truth. When it moves, results recorded under the old one stop being compared.
- **detection**: the finding of a known flaw through a FAIL. In the detection suite, a nonce proves it.
- **miss**: a known flaw an instrument does not find in a run.
- **distribution coverage**: a honeypot metric over runs: how evenly the generator covers the categories.

## The CVE benchmark: census and draw

- **CVE benchmark**: the two suites built on published MCP flaws, the detection suite and the nuisance suite, with what they share: the census, the draw order, the exclusions, the grammar, the planting code and the stand-ins.
- **census**: the committed list of every public MCP flaw disclosed up to its date bound. Its flaws are collected from GHSA, NVD and OSV, classified by two independent classifiers, and grouped by what a tool response can prove. Code: `evals/census.json`, `python -m evals.run_census`. Defined by: detection suite rule (Census).
- **flaw ID**: the identifier of a census flaw: its CVE ID, or its GHSA ID when it has no CVE ID. It is frozen once recorded, since it is the input of the draw hash. Code: `--flaw ID`.
- **CVE ID**: a MITRE identifier. "CVE" is never a project term on its own, only inside "CVE ID" and "CVE benchmark".
- **classifier**: one of the two independent readers that classify every census flaw. A classifier may run as several agents, each on its own share of the flaws. Not: the model provider's safety classifier.
- **settlement**: the maintainer's ruling, with its reason, on a disagreement between the two classifiers about a flaw a walk reaches (criterion by criterion), or between the two admission agents about a server (field by field).
- **known gap**: the census flaws outside the grammar's classes that one of the two agents grouping the census by proof places among those whose effect no tool response can prove. The share of each of the two readers is reported as a lower bound, and the two shares are never settled into one. A flaw of the known gap is still drawn and calibrated like any other, since the grouping is a judgment and the calibration decides whether a nonce can surface. Defined by: detection suite rule (Census).
- **draw order**: the order of the SHA-256 of the salt plus the flaw ID, over the census flaws that meet the draw-order criteria. The salt is the literal `mcp-auditor-holdout:`, which never changes. Defined by: ADR 028.
- **walk**: going down the draw order flaw by flaw. Each suite has its own: the **detection walk**, which takes holdout targets, and the **nuisance walk**, which reaches at least every flaw the detection walk reached. The word "walk" is always qualified. Defined by: ADR 028, ADR 033.
- **addition**: a logged decision to resume a walk past where it stopped, sized as a number of targets or servers. Defined by: detection suite rule (Reading), nuisance suite rule (Eligibility).
- **re-walk**: under a new rule version, applying its criteria again to every flaw a walk reached.
- **excluded server**: a server whose traces fed a decision (a change to a prompt, a guard or the oracle, or a judge case), or a package built from a fork of such a server's repository. Its flaws are out of both holdout layers, in every version of the server, and so is a drawn flaw whose vulnerable code is copied from it. Defined by: ADR 028.
- **side**: where a flaw sits against the cutoff of a run, pre-cutoff or post-cutoff. Defined by: detection suite rule (Sides), nuisance suite rule (Run conditions and statistic), ADR 032.
- **not run**: a target or server left out of N, the count a holdout statistic divides by, for a whole run: a target out of calibration at the pre-run check, a nuisance server whose benign call fails, or a target or server whose launch or audit still fails after its retries. Not: exit.
- **run conditions**: the settings a run records: runs, budget, tools filter, chain settings, tool call timeout, provider, models, reasoning levels and their cutoffs, the list of targets or servers, and the grammar, counter and fixture fingerprints. A gate compares a run only to a baseline recorded under the same conditions. Two holdout runs, or two nuisance runs, compare as paired outcomes on what both ran when they differ only in provider, models, reasoning levels and cutoffs, or in their list of targets or servers. Code: `evals/holdout_conditions.json` (chain settings, tool call timeout, cutoffs).

## The detection suite

- **detection suite**: the suite that audits real MCP servers pinned at a vulnerable version, and counts a detection when a planted nonce comes back in a test case or chain judged FAIL. Code: `python -m evals.run_detection`. Defined by: ADR 015, ADR 024, ADR 029.
- **detection suite rule**: the pre-registered rule of the census and of the detection holdout layer. It also sets how the acceptance layer forms its targets and when it takes a census flaw. Code: `docs/detection-suite-rule.md`, `docs/detection-suite-log.md`. Defined by: ADR 028.
- **target**: the unit of the detection suite: a flaw with its siblings and its fixture. An **acceptance target** belongs to the acceptance layer, a **holdout target** to the holdout layer. A spent holdout target may move to the acceptance layer. Not: audited server.
- **sibling flaw**: another census flaw that the target's vulnerable version carries and its first patched version does not, so the replay cannot tell them apart. A target is filed under its drawn flaw ID with its siblings, and its aim is their union. Defined by: detection suite rule (Proof).
- **dropped acceptance target**: a target taken out of the detection acceptance layer. Its server stays out of the nuisance holdout layer, since its traces may have been read, and leaves the nuisance acceptance layer.
- **vulnerable version / patched version**: the release a target is pinned at, and the first release that fixes its flaw. Each has its image: the vulnerable image and the patched image.
- **live / fixed**: a target is live on its vulnerable version when it keeps at least one place, the nonce of every kept place surfaces in an aimed exploit, and the benign call surfaces no nonce and does not read as aimed. It is fixed on its patched version when no exploit surfaces a nonce and the benign call returns no error.
- **calibration**: writing or repairing a detection fixture: its exploits, its kept places, its benign call and its card. Defined by: detection suite rule (Eligibility, Calibration and Calibration card).
- **give-up**: a calibration agent's conclusion that a candidate's calibration cannot pass in a container, with one reason from a closed set. The holdout detection rate covers only the flaws whose calibration passes. Defined by: detection suite rule (Eligibility).
- **calibration check**: the no-LLM check that a target is live on its vulnerable version and fixed on its patched one, its layout and routes included. Code: `--calibration-check`, `python -m evals.run_detection_holdout calibration-check`.
- **out of calibration**: a target that fails its calibration check. Not: broken, said of a server the layout breaks.
- **pre-run check**: the check of each target just before a graded run. A target out of calibration is not run: in a holdout run it leaves N, and in a graded run of the acceptance layer it makes the detection gate not comparable, whatever its baseline.
- **exploit**: the tool calls that surface a nonce when the calibration check runs them, written by the calibration agent or by hand from the flaw's published mechanism. The grammar grades the exchanges of one exploit as one unit. No audit runs an exploit.
- **benign call**: a no-LLM call inside the target's scope that must surface no nonce, must not read as aimed (see **aim**), and must not fail on the patched version. Not: the nuisance benign call.
- **card**: the record of a holdout target's calibration, written by the calibration agent and checked by a second agent, the card checker.
- **kit**: the self-contained tree, free of `mcp_auditor`, where an agent blind to the auditor works: a calibration agent for a holdout target, an admission agent for a nuisance server.
- **place**: a location where a nonce can sit: a file, an environment variable, the server's account, the hostname, an HTTP endpoint, a node of the deployment layout. A **catalogue place** comes from the rule's list, a **layout place** from the deployment layout. A **kept place** is one calibration keeps because only the target's flaws reach it, and, for a layout place, because the route check finds a route to it. Each place has a place id. Code: `evals/detection_places.json`.
- **deployment layout**: the fixed `/srv` tree every target runs in: a checkout, the bare repository it was cloned from, and the files a deployment carries. Defined by: ADR 031.
- **layout check**: the no-LLM check that the layout does not break a server, comparing each version launched with an empty tree and with the layout. A server the layout breaks is **broken**.
- **route check**: the no-LLM check that the auditor has a route to a layout place, so that calibration may keep it. Defined by: ADR 031.
- **nonce**: a random value planted at a place for one launch. The oracle credits it when it comes back in a unit judged FAIL, unless the auditor itself sent that value. Code: `MCPAUDIT-<hex>`, or `mcpaudit-<hex>` as an account name. Not: witness. Defined by: ADR 029.
- **sentinel**: the sidecar container that serves a nonce at an HTTP endpoint place. Not: the nonce.
- **oracle**: the deterministic grader of the detection suite. It turns an audit into a status per target. Not: the judge.
- **grammar**: the fingerprinted rules the oracle grades with: the classes, the categories valid for each class, the units and the proofs. A change to it resets the detection gate's baseline and makes earlier holdout detection rates exploratory. The same change applies the nuisance eligibility again, resets the nuisance gate's baseline, and stops holdout nuisance rates on either side of it from being compared.
- **class**: the effect of a flaw: a read outside its scope, a command execution or an internal fetch. It sets which judge categories count in `fail_without_proof`, and in the nuisance suite which categories make an alarm. It never decides a detection: a nonce in a FAIL credits whatever the category. Code: `read_outside_scope`, `command_execution`, `internal_fetch`. Not: category, or reach: the class decides which judge categories count, the reach which places calibration may keep.
- **reach**: the primitive a flaw uses to reach a place: read, exec or fetch. Code: `arbitrary_read`, `command_execution`, `internal_fetch`. Not: class.
- **unit**: what the grammar grades as one: a test case, a whole chain, or the exchanges of one exploit.
- **aim**: a pattern per target over the string arguments a unit sends. A unit reads as aimed when an argument matches. The aim credits nothing, and diagnosis and the calibration check use it.
- **`fail_without_proof`**: a diagnostic count of the runs where a unit aimed at the flaw was judged FAIL, in a category the target's class admits, and surfaced no nonce. It credits nothing.
- **credit**: a nonce found in a FAIL, which counts toward a detection. Defined by: ADR 030.
  - A **struck credit** is one the replay reproduced on the patched version, so it cannot be tied to the flaw the first patched release fixed. It counts as not detected. The replay errs both ways: it strikes a credit earned through an incomplete patch, and keeps one earned on a sibling flaw.
  - An **unchecked credit** is one the replay could not check. It is kept and reported. A gate outcome that would change if it were struck is not comparable.
- **replay**: sending the recorded calls of a detecting run again, without an LLM, to a fresh container of the patched version, to strike the credits it reproduces. Not: retest. Defined by: ADR 030.
- **status**: what the oracle reports per target and run: detected, reached but judged pass (a nonce surfaced in a unit the judge ruled PASS), or missed.
- **tools filter**: the set of tools a target's graded run on the acceptance layer audits, taken from its calibration exploits. A holdout run has none. Not: the user's `--tools`.
- **measurement run**: a `--no-baseline` run that forces on every target the chain settings, tool call timeout or absence of tools filter its flags name, and reports usage and cost. It never gates.
- **survey**: a no-LLM mode that plants every candidate place a target could reach and prints what each version surfaces, to choose the kept places.
- **preflight**: the Docker check before any mode: the daemon, closed-network support, and the expected images, rebuilt when stale. Not: pre-run check.
- **detection gate**: the gate of the detection acceptance layer. A target detected in every run of a confirmed baseline is gated, and a miss on it is retested. Defined by: ADR 024.
- **holdout run**: a run of the detection holdout layer, under run conditions fixed in advance, that writes no per-case output and refuses to start with tracing on.
- **holdout detection rate**: the mean over the runs of k/N, where k is the number of holdout targets detected after the replay and N the number of holdout targets run. Defined by: detection suite rule (Run conditions and statistic).
- **detection fixture**: what a target runs on: its vulnerable and patched images, launch, environment, places, stand-ins and seeds, with the exploits and the benign call its calibration check runs. Its fixture fingerprint hashes what builds, seeds and launches the target and what reaches the auditor or the oracle: the Dockerfiles (not the built images), the shared environment code, the classes, the aim, the tools filter, the kept places, the launch and what its stand-ins serve. The exploits and the benign call are left out.

## The nuisance suite

- **nuisance suite**: the suite that audits real MCP servers at the first release that fixes every flaw it counts, and counts the alarms the auditor still raises on the tools of those flaws. Code: `python -m evals.run_nuisance`. Defined by: ADR 033.
- **nuisance suite rule**: the pre-registered rule of the nuisance suite. It takes the census from the detection suite rule. Code: `docs/nuisance-suite-rule.md`, `docs/nuisance-suite-log.md`.
- **nuisance acceptance server**: the admitted server of a current acceptance target of the detection suite, admitted outside the nuisance walk.
- **nuisance holdout server**: a server the nuisance walk reached and the admission admitted, that no exit takes out (see **exit**).
- **detection holdout server**: the server of a holdout target. It can also be a nuisance holdout server, audited at its patched version.
- **admission**: the procedure by which two admission agents, blind to the auditor, record each server and its flaws, and the maintainer settles where they disagree. The word also names the committed file that records it. Code: `evals/nuisance_admission.json`. Defined by: nuisance suite rule (Admission).
- **re-admission**: admitting an already admitted server again, after a new rule version or a census extension. Code: `--re-admission`.
- **counted flaw**: a flaw that sets the version of its server: a census flaw that the admission settles, in a class the grammar grades, reached through a tool call, whose effect shows in a tool response, whose vulnerable version can be pinned, and whose fix check passes. The server's patched version is the first release that fixes every counted flaw. Not: a flaw's own patched version. Defined by: nuisance suite rule (Eligibility).
- **counted tool**: a tool of a counted flaw that exists in the patched version, whose backend the fixture can provide, whose benign call works, and whose declared function is not the effect of the flaw's class.
- **declared function is the effect**: said of a tool whose description declares the action of its flaw's class (run code, fetch a URL, read a path) on what an argument carries or names. Such a tool does what its class names by design, so it leaves the count. It is not the effect when the argument only parameterizes a fixed operation, such as reading a path inside a root the server declares, or running a fixed program on a path. Code: `declared_function_is_effect` in the admission file. Defined by: nuisance suite rule (Eligibility).
- **fix check**: the no-LLM check that a fix holds. The exploits surface a witness on the vulnerable version and on neither the flaw's own patched version nor the server's patched version, where every benign call works. Code: `python -m evals.run_nuisance fix-check`. Not: calibration check.
- **witness**: the random value a fix check plants where the flaw reaches. No audit sees it. Not: nonce.
- **positive control**: the witness surfacing on the vulnerable version, which shows that the exploit works and that the flaw is real.
- **holdout calibration copy**: a fix check taken from the current calibration of a detection holdout target, for its drawn flaw and its siblings. It applies when the server's patched version is the one that calibration checks, and when its positive control rests on no stand-in that relays the flaw's effect. When the target's fixture fingerprint changes, it is copied again before the next run. While the target's calibration is being repaired, or once the target leaves the detection holdout layer, the flaw goes through its own fix check. Code: `source = "detection_holdout_calibration"`, `holdout_fingerprint` in the admission file.
- **benign call** (nuisance): a call to a counted tool, written from its description and not aimed at the flaw, that must return without error before each run, with an optional expected text and prerequisite calls. Not: the detection benign call.
- **vet**: the no-LLM check, before a nuisance run, that each audited server lists its counted tools and answers its benign calls through the run's own launch. Code: `python -m evals.run_nuisance vet`.
- **alarm**: a test case or chain judged FAIL on a counted tool, in a category valid for the class of a counted flaw that tool carried. A chain counts when any of its steps calls such a tool.
- **flagged**: a server with at least one alarm in a run.
- **counter**: the code that counts alarms, separate from the grammar, with its own fingerprint. A change to it resets the nuisance gate's baseline and stops holdout nuisance rates on either side of it from being compared. It touches nothing of the detection suite. Defined by: ADR 033.
- **nuisance run**: a run of the nuisance holdout layer, under the run conditions of a holdout run apart from the number of runs, that writes no per-case output.
- **holdout nuisance rate**: the share of nuisance holdout servers flagged in a run, averaged over runs, with its Wilson interval over servers, and reported on each side of the cutoff. It is published as "at most", since some counted alarms can be true: a fix can be incomplete, or a tool can carry a flaw no advisory reports. It bounds the false alarms on the tools of a fixed flaw, in the categories of that flaw's class. It does not measure the false-positive rate a user sees on a healthy server. It is published only beside a holdout detection rate at the same commit, under the same run conditions apart from the number of runs, since an auditor that probes less raises fewer alarms. Defined by: ADR 033, nuisance suite rule (Run conditions and statistic).
- **raw count**: per server and run, every test case and chain judged FAIL, on every tool and in every category. It is **report-only**: a report prints it, and nothing compares it.
- **exit**: a reason a server is outside the holdout nuisance rate, such as a flaw never fixed or no counted tool left. Not: not run.
- **nuisance gate**: the gate of the nuisance acceptance layer. A nuisance acceptance server flagged in no run of the confirmed baseline is gated, and an alarm on it is retested.

## Fixtures and their infrastructure

- **nuisance fixture**: what a nuisance server runs on: its patched image, launch, backend fixture, stand-ins and seeds. A fix check uses a vulnerable image too.
- **backend fixture**: the backend a nuisance server needs to start or to answer a benign call, with the network that joins them.
- **planting**: putting a fresh nonce in each kept place of a launch, and starting the network, holder, sentinels and stand-ins the launch needs. The planting code does it.
- **planting host**: what a launch may hold: its user, working directory, network, public names and layout mount.
- **namespace holder**: a container that only runs `sleep` and owns the network namespace that the target, its sentinels and its stand-ins join. It carries the hostname and the public names.
- **closed network**: a Docker network with no route to the host or the internet, created only through `evals/cve/closed_network.py`. Defined by: ADR 034.
- **stand-in**: anything that takes the place of software the fixture cannot run (a program, a device, an HTTP backend, a public host under its real name) and answers what the real software would. A stand-in may not relay a flaw's effect. Defined by: detection suite rule (Eligibility, What a fixture seeds and serves), nuisance suite rule (Admission, Stand-ins), ADR 034.
- **capture stand-in**: the generic image that serves a captured or documented answer file under a public host's real name. Code: `evals/stand_ins/<host>.json`, `python -m evals.capture_stand_in`.
- **responder**: a hand-written HTTP stand-in for a remote service's API, answering from its documented examples.
- **backend**: any service on a fixture's network that the server talks to, real software or stand-in.
- **provisioner**: the code that starts a backend, fills it, and gives the server its launch.
- **seed**: what a fixture puts in place before the first call: files, records, configuration.
- **fixture authority**: the certificate authority the stand-ins' certificates chain to, with one leaf per stand-in host. Code: `evals/stand_ins/tls/`.
- **request target**: the target of the HTTP request a stand-in route answers. Code: `request_target` in a stand-in file.
- **public names**: the public hosts a planting host declares, each served by a stand-in under its real name.

## Words with several senses

Each sense is defined above or by its gloss here. Write the qualified form.

- **attempt**: parse attempt (reading a model answer), send attempt (a tool call), audit attempt (one audit of a run, made again after a missed model call or a provider error).
- **budget**: test budget (`--budget`, test cases per tool) or chain budget (`--chains`, chains per tool).
- **candidate**: candidate run (compared to a baseline), candidate model (in the model probe), draw-order candidate (a flaw in the draw order), candidate place (in a survey).
- **case**: test case (the auditor's) or judge case (the judge eval's).
- **conditions**: run conditions, or out-of-calibration reasons (what a calibration check found wrong).
- **confinement**: the confined execution regime of an audit, or the confinement a suite launches its servers with (user, dropped capabilities, memory bound).
- **coverage**: coverage gap or distribution coverage.
- **declared**: declared container, declared flip, declared function, a root the server declares.
- **eval**: the judge eval, or an instrument by its name. The words "the evals" alone mean the instruments.
- **exit**: an exit (a reason a server is outside the holdout nuisance rate), or an exit code of a command.
- **fixed**: a fixed version (no exploit surfaces), or a flaw fixed on a release.
- **fixture**: honeypot fixture (the honeypot servers and their pinned SDK versions), detection fixture, nuisance fixture, backend fixture, judge fixture (the drawn set of judge cases). A pytest fixture is a test helper.
- **flaw**: census flaw, planted flaw, sibling flaw, counted flaw.
- **gap**: coverage gap, known gap, or a gap a card check reports (a defect the card checker finds in a card).
- **host**: the machine that runs the suite, a public host name, or a planting host.
- **launch**: one start of a server or a fixture (per-launch). The command an audit starts is the server command.
- **miss / missed**: a miss (a known flaw not found in a run), or a missed model call.
- **patched version**: a target's patched version, a flaw's own patched version, or a nuisance server's patched version (the first release that fixes every counted flaw).
- **probe**: model probe or benign probe (the command that plays a re-admitted server's benign calls). As a verb, "probe" describes what the auditor does to the audited server.
- **provider**: model provider (the LLM vendor) or OpenRouter provider (the host OpenRouter routes a call to).
- **reach**: a flaw's reach (read, exec or fetch), a walk that reaches a flaw, or the reached status (a nonce in a unit judged PASS).
- **recording**: as a noun, a baseline recording only. The verb keeps its everyday sense: a run records its conditions.
- **refusal**: provider refusal only. Other acts take their own verb: a command refuses to start, a guard blocks a payload, a replay strikes a credit.
- **route**: a stand-in route (one answer a stand-in serves), a route check (a path from the auditor to a place), or a network route.
- **rule vN**: always "detection suite rule v12" or "nuisance suite rule v5", never "rule v12" alone.
- **rule**: the detection suite rule or the nuisance suite rule. The rules the oracle grades with are the grammar.
- **run**: an instrument run (one invocation), or a repetition (one of the `--runs` passes inside an instrument run).
- **scope**: a target's scope (the checkout), or the root a tool declares.
- **step**: chain step, or walk step (one stage a reached flaw goes through in a walk). A model call is not a step.
- **tools filter**: the user's `--tools`, or a target's tools filter.
