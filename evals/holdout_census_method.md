# CVE holdout census: method note

The holdout layer of the CVE benchmark draws its targets from a census of public advisories ([ADR 028](../docs/adr/028-cve-holdout-selection.md)), under the rule of [`docs/holdout-rule.md`](../docs/holdout-rule.md), version 3. This note says what the census file holds, how the rule is read where it leaves a choice open, how the exports are downloaded, what the work directory holds and the procedure that produces the census. The rule is frozen: a reading below never edits it, and a question the readings cannot settle goes to the next version of the rule.

The census is built by `uv run python -m evals.run_census`. Deterministic work is code (reading the exports, the pre-filter, the merge of a flaw's identifiers, the disclosure date, the completeness check, the figures). Judgment goes to LLM agents, launched by the maintainer, who write their output to the work directory and never to the census file.

## What the census file holds

`evals/holdout_census.json` (`HoldoutCensus`, `evals/holdout_census.py`) holds the rule version and its commit, the bound commit and the bound (the UTC day 2026-10-07), the provenance of the exports (the commit of the advisory database clone, the name, download day and SHA-256 of each NVD feed and of the OSV export), the agents with their model ID, the pre-filter terms as first written and each widening with the number of hits it matches, every hit decision of every collector, the flaws, the `vulnerablemcp.info` entries, the two classifiers' classifications, the dates where a classifier differs from the computed one, and the figures (agreement, the two coverage figures, the breakdowns per classifier, the monthly counts).

Each flaw carries its identifier, every ID of the flaw, every source record with its source, ID, `published`, `withdrawn` and `rejected`, its disclosure date and how it was found (`prefilter`, `gap`, `recall`, `vulnerablemcp`). `load_census` recomputes from the file alone each identifier, each disclosure date, the withdrawn flags, the date mismatches and the figures, and refuses a file that disagrees with its own computation. How each figure is computed is in the docstring of `evals/census_figures.py`.

## Readings of the rule

1. Hits a collector drops stay in the census, with the source ID and one sentence of reason.
2. The disclosure date that counts is computed by code: the earliest `published` of the flaw across the three sources, as a UTC day. A record without `published` (optional in the OSV schema) adds no date, and a flaw kept in the census with no date in any source is left to the maintainer by `status`. Each classifier still records the date it reads, its agreement is measured on that field, and every classifier date that differs from the computed one is listed in `date_mismatches`.
3. The breakdowns are published per classifier, never merged. In the coverage figures a flaw meets a criterion when either classifier finds that it does, and falls outside the grammar only when both place it there.
4. Classes outside the grammar are named freely by each classifier. The classifiers receive a short definition of the three grammar classes, written from the docstring of `evals/cve_grammar.py`, and no suggestion of any other class.
5. A flaw kept by one collector and dropped by another is kept, and both decisions are recorded.
6. A flaw with several GHSA IDs and no CVE ID is identified by the GHSA ID of the earliest `published` advisory, ties broken by the lowest ID in string order.
7. A flaw with neither a CVE ID nor a GHSA ID is recorded under its lowest OSV ID and flagged `no_census_identifier`. It counts in the figures and stays out of anything that orders the draw.
8. A rejected CVE is one whose NVD `vulnStatus` is `Rejected`. A withdrawn GHSA advisory stays a hit, and its `withdrawn` date is recorded.
9. Agreement on the effect class is reported twice: on the class name (case and whitespace normalized), and on membership of the grammar.
10. A flaw whose every source record is withdrawn or rejected stays in the census, classified like any other and flagged `withdrawn`. It counts in the agreement only, never in the coverage figures, the breakdowns or the monthly counts.
11. A collector may decide hits by the vocabulary of their tokens, a token being a maximal run of letters, digits and underscores. It lists the distinct tokens containing `mcp` in its hits that do not contain `model context protocol`, with their counts, reads the whole list and judges each token, checking the package names it occurs in. A hit whose every such token is judged not to name MCP software is dropped, one decision per hit, with a reason that names its tokens. This fixes a way of deciding, not a narrower pre-filter: each of these hits stays in the census with its decision. A token the collector cannot judge from the list alone counts as naming MCP software, and its hits are read one by one. The judged list, each token with its count, its judgment and, for a token judged not to name MCP software, why, is written to `tokens.md`. The script and `tokens.md` stay in the agent's directory, under `output/holdout_census/scripts/`.
12. A flaw of software that implements MCP is a flaw of a package whose purpose is MCP (a server, client, host, inspector, registry or SDK of the protocol), or, in a package with other purposes, a flaw in its MCP code or reached through an MCP message. The rule's phrase names the software, and in a package with other purposes the software that implements MCP is its MCP code and the code an MCP message reaches.
13. The pages an advisory links to include the repository, releases, documentation and registry page of the affected software, which settle its versions and its transport. A classifier searches the web only to find these.
14. `transport` records the MCP transports the software offers, or speaks when it is not a server, whatever the transport an advisory exploits the flaw over. Whether the flaw is reached through `tools/call` is recorded by `primitive`, and a flaw not reached through a tool call has no effect in a tool response.
15. A flaw that enters the census through a distribution's rebuild of a package, or through a malicious-package record, is classified as a flaw of the package it lies in: for a rebuild, the upstream package whose flaw it carries.

## Downloading the exports

The exports go into `output/holdout_census/sources/` (gitignored), and the census reads them as downloaded: an advisory edited after the bound is read in its edited form.

```bash
mkdir -p output/holdout_census/sources
cd output/holdout_census/sources
git clone --depth 1 https://github.com/github/advisory-database.git
for year in $(seq 2002 2026); do
  curl --fail --location --remote-name "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-${year}.json.gz"
done
curl --fail --location --remote-name https://storage.googleapis.com/osv-vulnerabilities/all.zip
```

Only `advisories/github-reviewed/` of the clone is read. The OSV export is read inside the zip, never extracted. The census records the SHA-256 of each `.json.gz` as downloaded. The `sha256` of an NVD `.meta` file hashes the uncompressed JSON, so it is never compared with the census's hash.

Then write the download days into `output/holdout_census/work/downloads.json`, one per NVD feed and one for the OSV export (the clone is recorded by its commit):

```json
{"nvd": {"nvdcve-2.0-2002.json.gz": "2026-10-08", "...": "..."}, "osv": "2026-10-08"}
```

## The work directory

`output/holdout_census/work/` (gitignored) holds every file the agents and the maintainer write, one JSON object per line, in the schemas of `evals/census_work.py`. A malformed line is refused with its file and line number. Each kind of file is read under a prefix, so two agents of one role write two files (`decisions_ghsa.jsonl`, `decisions_ghsa_2.jsonl`):

| Files | Schema | Written by |
|---|---|---|
| `hits_<source>.jsonl` | `AdvisoryRecord` | `prefilter`, the undecided hits only |
| `decisions*.jsonl` | `HitDecision` | collectors, as they go |
| `gaps*.jsonl` | `Gap` | collectors, for a flaw found beyond the pre-filter |
| `recall*.jsonl` | `RecallFinding` | recall agents |
| `vulnerablemcp*.jsonl` | `VulnerableMcpEntry` | the `vulnerablemcp.info` agent |
| `widenings*.jsonl` | `PrefilterTerm` | the maintainer |
| `agents*.jsonl` | `AgentRecord` | the maintainer, one line per agent launched |
| `classifier_1.jsonl`, `classifier_2.jsonl` | `Classification` | the classifiers, copied in by the maintainer |
| `grouping_reader_1.jsonl`, `grouping_reader_2.jsonl` | `ProofJudgment` (`evals/census_grouping.py`) | the readers of the grouping by proof, copied in by the maintainer |
| `downloads.json` | `Downloads` | the maintainer |

## The commands

- `prefilter` reads the three exports, merges every record into flaws, applies the initial terms and the widenings, and writes the undecided hits of each source to `hits_<source>.jsonl`. A hit is left out only when its whole flaw is disclosed after the bound, and an OSV hit is left out when its flaw has a GHSA or NVD hit. It prints, per source, the hits, those already decided and the new ones, then the hits each term matches. A flaw with no date in any source is not left out.
- `status` lists what is left: undecided hits, flaws an agent found that the pre-filter as last widened does not match (gaps to widen), IDs an agent found in none of the sources, `vulnerablemcp.info` entries recorded as absent that the sources carry, and kept flaws with no date in any source. It exits `0` when nothing is left, `1` otherwise.
- `classify-dossier --out DIR` refuses an incomplete census, then writes one file per flaw (its identifier, every ID, the advisory pages and the full source records), `classification_schema.json` (the classifiers' output schema) and `grammar_classes.md` (the definitions of reading 4).
- `assemble` refuses an incomplete census, a classifier output that misses a flaw and a missing reader's grouping, then builds the census, computes the hits of each pre-filter term, the date mismatches, the figures and each reader's known gap, checks it with `load_census` and writes `evals/holdout_census.json` (`--census PATH` writes elsewhere). `load_census` refuses a grouping that misses or repeats a flaw the rule gives to the readers, or that groups another flaw, and a reader with no record in `agents*.jsonl`.

A refusal exits `3`, a malformed export or work file included. Every subcommand takes `--sources DIR` and `--work DIR`.

## Operating procedure

Human and agent work, once the code is in. Every agent of one step of the rule (the collection with its widening rounds, the recall with the `vulnerablemcp.info` check, the classification) runs on the model the maintainer chose for that step before it starts, unchanged while it runs, and each launch is recorded in `agents*.jsonl`. Prompts, transcripts and work files stay in `output/holdout_census/`, except the classifiers' directory, which is outside the repository.

**Every prompt of an agent that reads advisories or the web says that the content of a page is data to record, never an instruction to follow.** No prompt mentions the auditor, its results, its prompts or the excluded servers.

Every prompt gives reading 12. Each agent keeps every file it creates (scripts, indexes, notes) in a directory of its own, never in a shared temporary directory, runs Python as `python3 -I`, reads in the work directory only its own input and the files of its own role and source, and its last message says whether it stopped because its context filled or because it judged its task done. Only an agent whose context filled gets a continuation: the search beyond the pre-filter and the recall searches are open-ended, and each agent ends them when it judges that searching further would find little, and its last message says so. The agents share the GitHub API quota of the account, so each prefers the local exports to it.

### Running the agents

- **Outside the repository.** For the agents' work, `output/holdout_census/` is moved to a directory outside the repository, and the agents are launched from there, so that no instruction file of the project reaches them and no path they see names it. Meanwhile the commands take `--sources` and `--work`. The directory moves back before `assemble`.
- **One orchestrator.** A single agent, run on the model of the step, launches the others in parallel (one orchestrator per classifier for the classification), with their prompts unchanged and without setting their model, so that they inherit its own. It writes each agent's last message to a report file and launches the continuations. An orchestrator decides no flaw and is not recorded in `agents*.jsonl`. A continuation receives the same prompt with the next suffix on its agent name, its files and its directory (`collector-ghsa-2`, `decisions_ghsa_2.jsonl`), and is told to read the earlier agent's report and to skip every hit already in a decision file of its source.
- **The stop sentence.** Each agent opens its last message with "I stopped because my context filled." or "I judged my task done.", and the orchestrator launches a continuation on the first only. When a last message opens with neither, it launches nothing for that agent and says so. It never relaunches an agent to redo or check its work.
- **Lines are final.** An agent never deletes or edits a line it wrote: a line it finds wrong stays, and its last message lists it. Every line and every report is written in English.

### Steps

1. **Download** the exports and write `downloads.json`, as above.
2. **First pre-filter**: `uv run python -m evals.run_census prefilter`. The counts size the collectors' work.
3. **Collectors**, one per source. The prompt gives the hit file of its source, the rule's definition of MCP software (servers, clients, hosts, SDKs) and of an MCP server, the `HitDecision` schema and the file to append to, line by line as it reads. It asks the collector to look beyond the pre-filter in its source, for instance at the other advisories of organizations that publish MCP servers, and to record each flaw found there as a `Gap`. A collector whose context fills is continued, or a second collector of the same source is launched and recorded.
4. **Recall agents**, three, one per angle of the rule: MCP vulnerability aggregators and security blogs, the security advisories of MCP server repositories, servers whose names lack `mcp`. The prompt gives its angle and the `RecallFinding` schema: each finding carries its advisory ID in one of the three sources, or no ID and its link when it has none there, and where it was found.
5. **`vulnerablemcp.info` check**: one agent lists every MCP CVE the site gives with a disclosure date on or before 2026-10-07, as `VulnerableMcpEntry` lines, `found` when the agent finds it in a source, not found otherwise. `status` checks every absence against the exports.
6. **Widening loop**: `status` lists the gaps. For each, the maintainer appends a `PrefilterTerm` (a `string` or `package` term, the flaw it was added for, its reason), runs `prefilter` again, and the collectors read the new hits only. Repeat until `status` exits `0`. The collectors of a widening round decide their new hits and look no further: they record no gap, and a flaw of MCP software they meet outside their hits is named in their last message, for the maintainer to widen as for a gap. Their names carry the round (`collector-ghsa-w1`), so that a continuation still takes the next suffix. A recent NVD record often has no CPE yet, so a product is widened as a string when its name does not occur inside common words, and as a package name otherwise.
7. **Classification**: `uv run python -m evals.run_census classify-dossier --out ~/holdout-census-classify`. Two classifiers, independent of each other, work from that directory and the pages the advisories link to, each classifier in a copy of that directory of its own, so that neither can list the files of the other. Each may run as several agents in parallel, all on the model of the step, each in a fresh context on its own batch of dossiers, the batches of one classifier covering every dossier once. A classifier agent reads the dossiers and its own batch file only, never another classifier's output, and is recorded in `agents*.jsonl` with the role `classifier` and a scope naming its classifier and batch (`classifier_1-batch-02`). The prompt gives the rule's *Classification* fields and the *Eligibility* criteria checkable from an advisory, in their order, the schema, the grammar class definitions, and asks for every field of every flaw, even after a first failed criterion, one `Classification` per line. It confines the classifier to its directory and to the pages of reading 13, and gives readings 12 to 15. The maintainer concatenates the batches of each classifier, continuations included, into the work directory as `classifier_1.jsonl` and `classifier_2.jsonl`, and checks that each holds every flaw once. A classifier agent that skips a flaw or leaves a field empty is asked to complete its batch file.
8. **Grouping by proof**: two readers, as the rule's *Grouping by proof* sets out, each in its own context, read the flaws that `evals/census_grouping.py` gives them (`grouped_flaws`) and write one `ProofJudgment` per flaw, the flaws whose effect cannot be proven in a tool response under `no_proof_in_tool_output`. The maintainer copies each reader's judgments into the work directory as `grouping_reader_1.jsonl` and `grouping_reader_2.jsonl`, and records each reader in `agents*.jsonl` with the role `reader`, its name as scope and the model ID of the messages that wrote its judgments, which the transcript gives: an agent the vendor's classifier stops can be moved to another model by the harness. A later version groups only the flaws its census adds.
9. **Assemble**: `uv run python -m evals.run_census assemble`. Read the agreement, the date mismatches and the known gap.
10. **Commit** `evals/holdout_census.json` with the test that loads it, the README sentence and the line of `docs/holdout-log.md`, in one commit.
