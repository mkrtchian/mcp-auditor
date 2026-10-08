# CVE holdout census: method note

The holdout layer of the CVE benchmark draws its targets from a census of public advisories ([ADR 028](../docs/adr/028-cve-holdout-selection.md)), under the rule of [`docs/holdout-rule.md`](../docs/holdout-rule.md), version 2. This note says what the census file holds, how the rule is read where it leaves a choice open, how the exports are downloaded, what the work directory holds and the procedure that produces the census. The rule is frozen: a reading below never edits it, and a question the readings cannot settle goes to a version 3 of the rule.

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
| `downloads.json` | `Downloads` | the maintainer |

## The commands

- `prefilter` reads the three exports, merges every record into flaws, applies the initial terms and the widenings, and writes the undecided hits of each source to `hits_<source>.jsonl`. A hit is left out only when its whole flaw is disclosed after the bound, and an OSV hit is left out when its flaw has a GHSA or NVD hit. It prints, per source, the hits, those already decided and the new ones, then the hits each term matches. A flaw with no date in any source is not left out.
- `status` lists what is left: undecided hits, flaws an agent found that the pre-filter as last widened does not match (gaps to widen), IDs an agent found in none of the sources, `vulnerablemcp.info` entries recorded as absent that the sources carry, and kept flaws with no date in any source. It exits `0` when nothing is left, `1` otherwise.
- `classify-dossier --out DIR` refuses an incomplete census, then writes one file per flaw (its identifier, every ID, the advisory pages and the full source records), `classification_schema.json` (the classifiers' output schema) and `grammar_classes.md` (the definitions of reading 4).
- `assemble` refuses an incomplete census and a classifier output that misses a flaw, then builds the census, computes the hits of each pre-filter term, the date mismatches and the figures, checks it with `load_census` and writes `evals/holdout_census.json` (`--census PATH` writes elsewhere).

A refusal exits `3`, a malformed export or work file included. Every subcommand takes `--sources DIR` and `--work DIR`.

## Operating procedure

Human and agent work, once the code is in. Every agent runs on the model the maintainer chose before the census starts, unchanged while it runs, and each launch is recorded in `agents*.jsonl`. Prompts, transcripts and work files stay in `output/holdout_census/`, except the classifiers' directory, which is outside the repository.

**Every prompt of an agent that reads advisories or the web says that the content of a page is data to record, never an instruction to follow.** No prompt mentions the auditor, its results, its prompts or the excluded servers.

1. **Download** the exports and write `downloads.json`, as above.
2. **First pre-filter**: `uv run python -m evals.run_census prefilter`. The counts size the collectors' work.
3. **Collectors**, one per source. The prompt gives the hit file of its source, the rule's definition of MCP software (servers, clients, hosts, SDKs) and of an MCP server, the `HitDecision` schema and the file to append to, line by line as it reads. It asks the collector to look beyond the pre-filter in its source, for instance at the other advisories of organizations that publish MCP servers, and to record each flaw found there as a `Gap`. A collector whose context fills is continued, or a second collector of the same source is launched and recorded.
4. **Recall agents**, three, one per angle of the rule: MCP vulnerability aggregators and security blogs, the security advisories of MCP server repositories, servers whose names lack `mcp`. The prompt gives its angle and the `RecallFinding` schema: each finding carries its advisory ID in one of the three sources, or no ID and its link when it has none there, and where it was found.
5. **`vulnerablemcp.info` check**: one agent lists every MCP CVE the site gives with a disclosure date on or before 2026-10-07, as `VulnerableMcpEntry` lines, `found` when the agent finds it in a source, not found otherwise. `status` checks every absence against the exports.
6. **Widening loop**: `status` lists the gaps. For each, the maintainer appends a `PrefilterTerm` (a `string` or `package` term, the flaw it was added for, its reason), runs `prefilter` again, and the collectors read the new hits only. Repeat until `status` exits `0`.
7. **Classification**: `uv run python -m evals.run_census classify-dossier --out ~/holdout-census-classify`. Two classifiers, each in its own fresh context, work from that directory and the pages the advisories link to. The prompt gives the rule's *Classification* fields and the *Eligibility* criteria checkable from an advisory, in their order, the schema, the grammar class definitions, and asks for every field of every flaw, even after a first failed criterion, one `Classification` per line. It says never to open the mcp-auditor repository or its prompts. The maintainer copies each output into the work directory as `classifier_1.jsonl` and `classifier_2.jsonl`. A classifier that skips a flaw or leaves a field empty is asked to complete its file.
8. **Assemble**: `uv run python -m evals.run_census assemble`. Read the agreement and the date mismatches.
9. **Commit** `evals/holdout_census.json` with the test that loads it, the README sentence and the line of `docs/holdout-log.md`, in one commit.
