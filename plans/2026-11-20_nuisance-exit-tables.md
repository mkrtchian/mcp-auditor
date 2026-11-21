# The exits table of the nuisance run, from recorded data

## Context

The nuisance suite rule (`docs/nuisance-suite-rule.md`, Run conditions and statistic, "The exits") asks each run to publish two tables, one row per reason with its count. The first lists the servers outside the nuisance holdout layer: no counted flaw, a counted flaw never fixed, no counted tool left, a server that does not run over stdio, a patched version that does not run under Docker, an excluded server, a server of a current or dropped acceptance target, and a server spent by a reading. The second lists the servers left out of N for this run only: a benign call that failed, and a server not run after its retries.

The run published at `1765d9f` (`evals/cve/holdout_runs/2026-11-19_nuisance_1765d9f.md`) prints "Exits: none", while 55 of the 120 servers the nuisance walk lists (`uv run python -m evals.run_nuisance walk`) are not in the layer, and a 121st reached server, `npm:@agiflowai/scaffold-mcp` (position 11, reached by the detection walk), is not listed at all. The second table is already produced (the report's "Not run" section) and stays as it is.

The cause: the code derives only the reasons it holds as data. `nuisance_population` (`evals/cve/nuisance/admission/walk.py`) drops a reached server none of whose census flaws may count (`if not candidates: continue`), so scaffold-mcp, which the nuisance log entry of 2026-11-06 says "leaves the population" once CVE-2026-7237 is settled false on `effect_in_tool_response`, reaches no table. `run_population` (`evals/cve/nuisance/holdout_servers.py`) reads the walk's marks (`ServerMark.EXCLUDED`, `ServerMark.ACCEPTANCE_TARGET_SERVER`) and `standing_exit` (`evals/cve/nuisance/admission/admission_walk.py`) reads `runs_over_stdio` and `runs_under_docker` of an admitted server. None of the 120 listed servers carries a walk mark today, and all 65 admitted servers run over stdio under Docker, so the derived exits are empty. The reasons of the 55 listed servers that are not admitted live only in prose, in the dated entries of `docs/nuisance-suite-log.md` ("logged not admitted"). Neither `evals/nuisance_walk_record.json` nor `evals/nuisance_admission.json` carries them, as the docstrings of `run_population` and of `_exits_section` (`evals/cve/nuisance/markdown.py`) say.

This is the code catching up with the rule: no new rule version. The committed report of the 2026-11-19 run is a dated document and stays as it is. A dated nuisance log entry records the gap and the two tables of that run, recomputed from the new data.

## Decisions

### Where the exits are recorded: a top-level `exits` list in the admission file

`NuisanceAdmission` gains `exits: list[RecordedExit]`, beside `servers`. One record per server the nuisance walk lists and the admission did not let into the layer:

```python
class RecordedExit(BaseModel):
    server_package: str
    reason: ExitReason
    logged_on: date
```

`ExitReason`, its display mapping and `RecordedExit` live in a small new module, `evals/cve/nuisance/exits.py`, which imports only `pydantic`, `datetime` and `enum`. `results.py`, `admission_walk.py`, `admission.py` and `markdown.py` import from it, so no import cycle can form through it (`results.py` imports nothing from `admission/`, and `exits.py` imports no repository module). `admission.py` is already past 300 lines (304), so it takes only the import and the new field. No dossier carries the new module: none of `results.py`, `admission.py`, `admission_walk.py` or `markdown.py` is in the import closure of a dossier (`dossier_closure.import_closure` over `closure_roots` of each of the 65 admitted servers, and over the first-admission dossier's roots `evals.cve.kit.backends`, `evals.cve.kit.benign_probe` and `evals.capture_stand_in`, checked on the committed admission).

Why the admission file and not a file of its own (`evals/nuisance_exits.json`):

- The admission is the procedure that decides, for each reached server, whether it enters the layer (the rule: "A server enters the nuisance holdout layer ... once its admission is committed and no exit of the list below holds for it"). An exit recorded by that procedure is its outcome, so it belongs in its record, beside the admitted servers.
- The check "admitted or out, never both" is then local to `admission_problems`, which already cross-checks the admission with the walk (`walk_problems`). A separate file would need both files loaded for that check, a new path constant, a new `--exits` flag on `run`, `vet`, `walk` and `gate`, and a provenance commit of its own.
- Nothing that fingerprints reads the admission file as a whole. The fixture fingerprint (`nuisance_fixture_fingerprint`) reads one admitted server's fields, the counter fingerprint (`evals/cve/nuisance/counter.py`) hashes `counter.py` and `counting.py`, and the grammar fingerprint hashes the grammar. A new top-level list moves none of them.

`logged_on` is the date of the nuisance log entry that states the facts the reason rests on. A later ruling on the category does not move it (the four rulings below keep the date of the entry whose facts they rule on). The nuisance log is the one source because the rule says "Each exit is logged with its reason", in this suite's log. The reason text itself is not copied into the JSON, so the log stays the one prose source. A date names a day, and several entries share one, so `logged_on` narrows the search to that day's entries and does not name one entry. The committed-data test on these dates (Test scenarios) is a typo guard, not provenance: it checks that some entry carries the date, not that this entry states the reason.

### The reasons: one closed enum, its values identifiers, one display mapping

`exits.py` holds the enum, in the rule's list order, and the rule's wording of each reason:

```python
class ExitReason(StrEnum):
    NO_COUNTED_FLAW = "no_counted_flaw"
    COUNTED_FLAW_NEVER_FIXED = "counted_flaw_never_fixed"
    NO_COUNTED_TOOL_LEFT = "no_counted_tool_left"
    NOT_OVER_STDIO = "not_over_stdio"
    NOT_UNDER_DOCKER = "not_under_docker"
    EXCLUDED_SERVER = "excluded_server"
    ACCEPTANCE_TARGET_SERVER = "acceptance_target_server"
    SPENT_BY_A_READING = "spent_by_a_reading"


EXIT_REASON_TEXTS = {
    ExitReason.NO_COUNTED_FLAW: "no counted flaw",
    ExitReason.COUNTED_FLAW_NEVER_FIXED: "a counted flaw never fixed",
    ExitReason.NO_COUNTED_TOOL_LEFT: "no counted tool left",
    ExitReason.NOT_OVER_STDIO: "does not run over stdio",
    ExitReason.NOT_UNDER_DOCKER: "its patched version does not run under Docker",
    ExitReason.EXCLUDED_SERVER: "an excluded server",
    ExitReason.ACCEPTANCE_TARGET_SERVER: "the server of a current or dropped acceptance target",
    ExitReason.SPENT_BY_A_READING: "spent by a reading",
}
```

The persisted values are snake_case identifiers, on the model of `NotRunCause` and `DROPPED_RUN_REASONS` in `results.py`: each value is its member's name in lower case. `not_over_stdio` and `not_under_docker` name the rule's two launch exits as their members do, shorter than the rule's wording, which the display text carries. `EXIT_REASON_TEXTS` is the one display mapping: the markdown's exits section, the gate's "Outside the gate" lines (`gate_console.py` and `gate_report.py`, which print `{e.reason}` today and print `EXIT_REASON_TEXTS[e.reason]` instead) and the load-check messages read it. Its texts keep the four strings the code prints today ("an excluded server", "the server of a current or dropped acceptance target", "does not run over stdio", "its patched version does not run under Docker"), so no printed line changes for them.

`ServerExit.reason` becomes `ExitReason` (a `str` subclass, so `dataclasses.asdict` plus `json.dumps` in `write_result` keep working unchanged), and so does `ExitLine.reason`. The JSON of the report, of the `.result.json` and of the gate report (`outside_gate`) now carries the identifier (`"not_over_stdio"`) where it carried the text. That changes nothing committed: the only committed nuisance report (`2026-11-19_nuisance_1765d9f.json`) has empty exits, and no nuisance gate report is committed. `standing_exit` returns `ExitReason | None`, and the mark-to-reason map moves from `holdout_servers.py` (`_MARK_REASONS`) to `admission_walk.py` as `MARK_REASONS: dict[ServerMark, ExitReason]`, beside `standing_exit`, so that the load checks can print a mark's display text (`admission_walk.py` cannot import `holdout_servers.py`, which imports it).

### The servers reached with no flaw that may count: a derived exit

A reached server none of whose census flaws may count (in the code's words, with no candidate counted flaw) has no counted flaw by construction, so its exit is derived, like a walk mark, never recorded. `walk.py` gains a value object that groups what the walk reaches, and the pure function that builds it:

```python
@dataclass(frozen=True)
class ReachedServers:
    listed: Sequence[NuisanceServer]  # nuisance_population: what `walk` prints
    without_candidates: Sequence[str]  # reached, with no flaw that may count, in walk order


def reached_servers(walk_inputs: WalkInputs) -> ReachedServers: ...
```

`reached_servers` returns `nuisance_population(walk_inputs)` as `listed` and, as `without_candidates`, the servers of `_first_reaches(walk_inputs)` for which `candidate_counted_flaws` is empty. `nuisance_population` itself is unchanged, and `walk` keeps printing the 120 servers it lists. On the committed census and walk record, `without_candidates` is exactly `["npm:@agiflowai/scaffold-mcp"]` (checked read-only, through `committed_walk_inputs` and `_first_reaches`: 121 reached, 120 listed).

`run_population(reached: ReachedServers, admission, acceptance)` takes the value object in place of the listed servers, keeping three parameters, and lists one `ServerExit(package, ExitReason.NO_COUNTED_FLAW)` per server of `without_candidates`. Its two callers build it with `reached_servers(walk_inputs)`: `_run` in `evals/run_nuisance.py` and `vet` in `evals/cve/nuisance/vet_command.py` (whose audited set does not change, since such a server is never admitted).

### Load checks, and the reached servers whose admission is pending

A server with a pending admission is a legitimate state: after an addition, `walk` lists the reached servers precisely so the maintainer can admit them, and `walk` itself loads the admission. One such server exists today, pi-llm-wiki (logged "deferred, not dropped" on 2026-10-31, no later entry), and no reason of the rule's list fits it. A load check "every reached server is admitted or out" would make `walk`, `vet`, `fix-check`, `nuisance-dossier` and `gate` refuse during every admission in progress, and would force a false reason onto pi-llm-wiki. So the load checks hold consistency only, and completeness is shown in the report instead of enforced (the maintainer's ruling, 2026-11-20).

At load (`admission_problems`, through a new `exit_problems(admission, walk_inputs)` in `admission_walk.py`, which owns the admission's agreement with the walk and reads `reached_servers(walk_inputs)`), consistency only:

1. A recorded exit names a server the walk lists. A server the walk does not reach: `"{package}: recorded exit for a server the walk does not reach"`. A server the walk reaches with no flaw that may count has its derived exit, so a record for it is refused like a record on a marked server: `"{package}: recorded exit for a server the walk reaches with no flaw that may count, whose exit it derives (no counted flaw)"`.
2. A recorded exit never names a server the walk marks (excluded or acceptance target): the mark already gives its exit. `"{package}: recorded exit for a server the walk marks ({text})"`, `{text}` the display text of the mark's reason (`EXIT_REASON_TEXTS[MARK_REASONS[mark]]`, "an excluded server" for instance), never the mark's identifier.
3. At most one recorded exit per server: `"{package}: {n} recorded exits"`.
4. A server is never both admitted and recorded out, whatever the reason: `"{package}: admitted and recorded out ({text})"`, `{text}` the display text of the recorded reason.
5. `ExitReason.ACCEPTANCE_TARGET_SERVER` is never recorded, since the walk derives it: `"{package}: recorded exit for the reason '{text}', which only the walk derives"`. Checks 1 and 2 do not cover it: a nuisance acceptance server is admitted outside the walk, and a record of this reason on a listed, unmarked server passes both.

A recorded `excluded_server` is allowed: the rule's Eligibility counts as excluded "a package built from a repository GitHub marks as a fork of an excluded server's repository", which the walk's mark, read from `EXCLUDED_SERVERS`, does not catch. A recorded `spent_by_a_reading` is allowed on a server that is not admitted, and check 4 refuses it on an admitted one, with no exception: the case of an admitted server spent by a reading is designed with the first real reading. The enum keeps `SPENT_BY_A_READING` and the table prints its row, at 0 today.

At run, completeness is reported, never refused: `RunPopulation` gains `pending: Sequence[str]`, the servers the walk lists that are unmarked, not admitted and not recorded out, in walk order. `run_population` computes it. The run carries it to `NuisanceRunResult.pending_admission: Sequence[str]` (default empty, so the tests that build a result without it are unaffected, and a partial result, which goes through `_assemble_run` too, carries it) and to `NuisanceReport.pending_admission: list[str]`, and the exits section prints, after the rule's eight rows, one line outside the rule's list: `- admission pending (not an exit of the rule): 1 server(s): npm:@zosmaai/pi-llm-wiki`, or nothing when none is pending. Every reached server is then accounted for, either audited, in the exits table (recorded or derived) or pending, with no reason forced onto a server the log does not give one. `vet` and `gate` ignore it (they publish no exits table).

The committed-data test on the dates checks that each `logged_on` is the date of an entry of `docs/nuisance-suite-log.md` (a line starting `- YYYY-MM-DD:`). It is a test on the committed files, beside `test_the_committed_admission_loads`, not a load check: the loader stays free of reading the log, and `admission_problems` keeps its four parameters.

### The run and the report

`run_population` lists, in this order, the walk marks, the derived no counted flaw exits, the exits of admitted servers (acceptance target server, `standing_exit`), then one `ServerExit` per recorded exit. An admitted server is skipped when the walk marks it or reaches it with no flaw that may count, as a marked one is today. `run_population` is already near 20 lines, so the recorded exits and the pending servers each go to a private helper right below it, and `exit_problems` likewise reads its five checks from helpers below it.

`_exits_section` (`evals/cve/nuisance/markdown.py`) prints every reason of `ExitReason`, in the rule's order, by its display text, each with its count and, when non-zero, its servers in report order:

```
## Exits
- no counted flaw: 33 server(s): npm:@agiflowai/scaffold-mcp, npm:a, ...
- a counted flaw never fixed: 0 server(s)
- ...
- spent by a reading: 0 server(s)
```

A row per reason, zero rows included, is what the rule asks ("one row per reason with its count") and lets two runs be read side by side. The `- none` line goes. The pending line, when there is one, closes the section. The `.json` report (`ExitLine`) and the `.result.json` (`ServerExit`) already carry `exits` as a list of `{server_package, reason}`: their content changes (the reasons are identifiers and include the recorded and derived ones). The docstrings of `run_population`, `_exits_section` and `_not_run_section` that say the other exits "live in the log" are corrected.

The "Not run" section (the second table) is unchanged.

### The admission's commit in the run's provenance

The admission now decides which servers a run lists outside the layer as well as which it audits, so the run records its commit beside the census's and the walk record's. `RunProvenance` (`evals/cve/nuisance/run.py`) gains `admission_commit` beside `census_commit` and `walk_record_commit`, read the same way in `evals/run_nuisance.py` (`last_commit(args.admission)`), carried by `_assemble_run` to `NuisanceRunResult.admission_commit` and by `build_report` to `NuisanceReport.admission_commit`, and the markdown's `Commits:` line ends with `admission <commit>`. Provenance, never a condition, as `RunProvenance`'s docstring says of the other two.

### Tie-break rule for a server with several recorded reasons

Fixed before the classification and applied mechanically, over the recorded reasons only: take only the reasons the log itself establishes for the server, in the entry that states the facts its record rests on (the entry `logged_on` dates). When it establishes several, record the first in the rule's list order (no counted flaw, a counted flaw never fixed, no counted tool left, does not run over stdio, does not run under Docker, excluded server, spent by a reading). The other established reasons are kept in the classification table below for the maintainer, not in the JSON.

A walk mark and the derived no counted flaw exit take precedence over any recorded reason: the load refuses a record on a server the walk marks or reaches with no flaw that may count (checks 1 and 2). Between the two marks, the rule gives the acceptance row precedence over the excluded row (its Eligibility counts an excluded server "unless it is the server of a current or dropped acceptance target, which has its own row below"), and `_mark` does the same (`test_acceptance_wins_over_excluded`). The walk drops a server with no flaw that may count before it marks it, so such a server's row is no counted flaw, the first of the rule's list, whatever mark it would have carried.

The rule's order goes from the flaw to the server: a server with no counted flaw has nothing to count before any tool or launch question arises, a never-fixed counted flaw makes the patched version undefined before its tools are looked at, and the launch reasons come after.

How the log's wording maps to the list, used for the classification: a flaw outside a graded class, not reached through `tools/call`, whose effect shows in no tool response, not pinnable, or whose fix check does not pass is not a counted flaw (`no counted flaw` when none is left). A tool removed by the fix, needing a backend the fixture cannot provide, whose benign call cannot return without error, whose software is no longer distributed, or whose declared function is the effect is not a counted tool (`no counted tool left`). A proprietary binary, a licence the maintainer cannot use, or a credential the maintainer lacks is `does not run under Docker`.

## The classification of the 55 listed servers outside the layer

Classified before the code from only `docs/nuisance-suite-log.md`, `docs/nuisance-suite-rule.md`, `docs/detection-suite-log.md`, `evals/nuisance_admission.json`, `evals/nuisance_walk_record.json` and the output of `walk`, under the tie-break rule above, and validated by the maintainer. `logged_on` is the date of the nuisance log entry that states the facts the reason rests on. Rows marked (ruled) were ambiguous and are ruled on by the maintainer, each ruling going into the log entry with its reason. The reason column gives the display text, and the JSON records the matching identifier (`no_counted_flaw`, `no_counted_tool_left`, `not_under_docker`).

| pos | server package | reason | `logged_on` | other reasons the log establishes |
|---|---|---|---|---|
| 1 | npm:@akoskm/create-mcp-server-stdio | no counted flaw (ruled) | 2026-10-27 | the entry concludes "no counted tool remains", but the fact it gives is an injection `z.number()` rejects before the handler, so the flaw is not reached through `tools/call` |
| 9 | npm:claude-in-mobile | no counted tool left | 2026-11-08 | |
| 10 | npm:appium-mcp | no counted flaw | 2026-11-09 | |
| 14 | PyPI:mcp-server-fetch | no counted tool left | 2026-10-27 | logged as "fetch" |
| 16 | PyPI:stata-mcp | its patched version does not run under Docker (ruled) | 2026-10-27 | a proprietary binary, named by the rule only in this exit. No counted tool left if Stata is needed by the tools only |
| 25 | https://github.com/A-G-U-P-T-A/wireshark-mcp | no counted tool left | 2026-11-08 | |
| 27 | npm:repomix | no counted tool left | 2026-10-30 | an incomplete fix at 1.14.1, no later release named |
| 29 | npm:auth-fetch-mcp | no counted flaw | 2026-10-30 | no counted tool left (declared function, a headful browser) |
| 35 | PyPI:ha-mcp | no counted flaw | 2026-11-09 | |
| 18 | npm:mcp-searxng | no counted tool left | 2026-10-27 | |
| 19 | PyPI:awslabs-documentdb-mcp-server | no counted flaw | 2026-11-09 | |
| 22 | Go:github.com/grafana/mcp-grafana | no counted flaw | 2026-10-29 | |
| 28 | npm:openclaw | no counted flaw | 2026-11-09 | |
| 34 | npm:@dynatrace-oss/dynatrace-mcp-server | no counted flaw | 2026-11-01 | the 2026-10-29 "external tenant" superseded |
| 37 | PyPI:mcp-memory-service | no counted flaw | 2026-11-09 | |
| 39 | https://github.com/IBM/mcp-context-forge | no counted tool left | 2026-11-09 | admitted 2026-10-31, left under nuisance suite rule v4 |
| 42 | PyPI:adx-mcp-server | no counted flaw | 2026-11-11 | the Kusto emulator's licence (does not run under Docker). The entry concludes the flaw cannot be a counted flaw |
| 43 | Go:github.com/sonirico/mcp-shell | no counted tool left | 2026-10-28 | |
| 44 | npm:@arikusi/deepseek-mcp-server | no counted flaw | 2026-11-09 | |
| 46 | PyPI:awslabs-aws-healthomics-mcp-server | no counted tool left | 2026-11-08 | |
| 48 | npm:@cardano402/mcp-server | no counted flaw (ruled) | 2026-10-29 | "never fixed", read since 2026-11-08 as a flaw that does not set the version of its server. No counted tool left (declared function) |
| 50 | npm:@jshookmcp/jshook | no counted flaw | 2026-11-09 | no counted tool left (`CAP_NET_RAW` dropped) |
| 51 | https://github.com/nhost/nhost | no counted flaw | 2026-11-09 | |
| 55 | Go:github.com/github/github-mcp-server | no counted flaw | 2026-11-09 | |
| 67 | npm:open-websearch | no counted tool left | 2026-10-27 | |
| 69 | npm:@nor2/heim-mcp | no counted tool left | 2026-11-08 | |
| 71 | PyPI:gemini-bridge | no counted flaw | 2026-11-08 | |
| 72 | npm:a11y-mcp | no counted tool left | 2026-10-28 | |
| 77 | https://github.com/fatbobman/mail-mcp-bridge | no counted flaw | 2026-11-09 | |
| 90 | https://github.com/611711Dark/mcp_calculate_server | no counted tool left | 2026-11-09 | admitted 2026-10-31, left under nuisance suite rule v4 |
| 91 | npm:@mastra/mcp-docs-server | no counted flaw | 2026-10-31 | |
| 95 | npm:xcode-mcp-server | no counted tool left | 2026-10-31 | |
| 100 | npm:@jsonbored/gittensory-mcp | no counted flaw | 2026-10-31 | an external GitHub API backend. Record A found no patch (never settled) |
| 102 | npm:@zosmaai/pi-llm-wiki | no record: admission pending | (2026-10-31) | "deferred, not dropped", no later entry: no reason of the rule's list fits, so it gets no exit record and the report lists it as pending |
| 103 | PyPI:ciguard | no counted flaw | 2026-10-31 | |
| 104 | npm:browse-mcp | no counted flaw | 2026-11-09 | |
| 111 | https://github.com/Kong/mcp-konnect | no counted flaw | 2026-11-09 | |
| 112 | npm:@bytebase/dbhub | no counted flaw | 2026-11-09 | |
| 113 | PyPI:mcp-kubernetes-server | no counted tool left | 2026-10-31 | a cluster neither record had |
| 114 | https://github.com/tugcantopaloglu/godot-mcp | no counted flaw | 2026-11-09 | logged as "godot-tugcan" |
| 117 | npm:chrome-devtools-mcp | no counted flaw | 2026-11-09 | |
| 124 | npm:@adenot/mcp-google-search | no counted tool left | 2026-10-31 | |
| 128 | PyPI:maa-mcp | no counted flaw | 2026-10-31 | |
| 133 | PyPI:tooluniverse | no counted tool left | 2026-10-31 | |
| 134 | npm:neo.mjs | no counted flaw | 2026-10-31 | |
| 141 | npm:functype-mcp-server | no counted tool left (ruled) | 2026-11-09 | logged as a cost-of-proportion departure (a registry mirror). The 2026-10-31 entry gives the declared function |
| 146 | RubyGems:rails-mcp-server | no counted tool left | 2026-11-09 | admitted 2026-10-31, left under nuisance suite rule v4 |
| 149 | https://github.com/BeehiveInnovations/pal-mcp-server | no counted tool left | 2026-10-31 | logged as zen-mcp-server |
| 159 | PyPI:mcp-salesforce-connector | no counted tool left | 2026-11-09 | |
| 161 | Go:github.com/apache/skywalking-mcp | no counted flaw | 2026-10-31 | |
| 163 | https://github.com/Kirachon/context-engine | no counted flaw | 2026-10-31 | |
| 175 | npm:@roomi-fields/notebooklm-mcp | no counted flaw | 2026-11-09 | an external account |
| 177 | https://github.com/radareorg/radare2-mcp | no counted tool left | 2026-10-31 | |
| 178 | npm:@simonb97/server-win-cli | no counted flaw | 2026-10-31 | no counted tool left (declared function) |
| 185 | PyPI:zscaler-mcp | no counted flaw | 2026-11-09 | |

Beside the table, `npm:@agiflowai/scaffold-mcp` (position 11, reached by the detection walk) gets no record: the walk derives its exit, no counted flaw, since the nuisance log entry of 2026-11-06 settles CVE-2026-7237 false on `effect_in_tool_response` and leaves the server no flaw that may count.

Counts with the rulings, ruled by the maintainer on 2026-11-20: 54 exit records, no counted flaw 32, no counted tool left 21, its patched version does not run under Docker 1, the other five reasons 0, and pi-llm-wiki pending. With scaffold-mcp's derived exit, the first table reads no counted flaw 33 (32 recorded, 1 derived), no counted tool left 21, its patched version does not run under Docker 1, the other five reasons 0: 55 exits. 65 audited + 54 recorded exits + 1 derived exit + 1 pending = 121 reached, the 121 servers `_first_reaches` returns, of which `walk` prints the 120 that have a flaw that may count. The four rulings, with their reasons for the log entry. For create-mcp-server-stdio, an injection rejected before the handler is not reached through `tools/call`. For stata, a proprietary binary is named by the rule in the Docker exit only and the census forbids standing in for it. For cardano402, a flaw that no release shows fixed does not set the version of its server, the reading applied since 2026-11-08 (fast-filesystem). For functype, its one tool needs a registry mirror the fixture does not provide, and the 2026-10-31 entry also gives the declared function. No server of the 55 is an excluded server or the server of an acceptance target, and neither is scaffold-mcp.

The tie-break decided three rows against the entry's own concluding reason, each time on a reason the entry states earlier in the list: server-win-cli (an unreachable sink before the declared function), jshook (a failed positive control before the confinement), auth-fetch (a blind effect before the declared function).

Twenty-seven of the 55 rows are dated before the nuisance suite rule v4 entry (2026-11-04): the 25 rows at 2026-10-31 or earlier, dynatrace at 2026-11-01, and pi-llm-wiki, so 26 of the 54 exit records. The nuisance suite rule v4 entry says the servers the walk reached and left without an admission go through the admission, and no later entry names the 25 or pi-llm-wiki again. Dynatrace is apart: the nuisance log entry of 2026-11-05 lists it again among the servers going through the admission (the walk no longer reading the walk record's class settlement that had taken it out), and no later entry admits it or logs a new reason for it. Its record keeps no counted flaw, dated 2026-11-01, the entry that settles its one flaw left that may count, GHSA-pqh8-p93p-2rx7, outside the grammar. The 26 records are published as logged: this plan records the log, it does not re-admit.

## Files to modify

- `evals/cve/nuisance/exits.py` (new): `ExitReason`, `EXIT_REASON_TEXTS`, `RecordedExit`, with a one-line module docstring.
- `evals/cve/nuisance/results.py`: `ServerExit.reason: ExitReason`. `NuisanceRunResult.admission_commit: str` after `walk_record_commit`. `NuisanceRunResult.pending_admission: Sequence[str] = ()`.
- `evals/cve/nuisance/admission/walk.py`: `ReachedServers` and `reached_servers`.
- `evals/cve/nuisance/admission/admission.py`: `NuisanceAdmission.exits: list[RecordedExit]` (required, no default: the committed file carries it, and a crafted admission in a test states it). `admission_problems` appends `exit_problems(admission, walk_inputs)`. The module docstring names the new list.
- `evals/cve/nuisance/admission/admission_walk.py`: `MARK_REASONS`. `exit_problems` (checks 1 to 5). `standing_exit` returns `ExitReason | None`. The module docstring.
- `evals/cve/nuisance/holdout_servers.py`: `_MARK_REASONS` replaced by `MARK_REASONS` from `admission_walk.py`. `RunPopulation.pending`. `run_population(reached: ReachedServers, ...)` lists the derived and recorded exits and the pending servers. Docstrings corrected.
- `evals/run_nuisance.py`: `_run` builds the population from `reached_servers(walk_inputs)`. `_audit_admitted_servers` passes `last_commit(args.admission)` to `RunProvenance`.
- `evals/cve/nuisance/vet_command.py`: `vet` builds the population from `reached_servers(walk_inputs)`.
- `evals/cve/nuisance/run.py`: `RunProvenance.admission_commit`. `_assemble_run` carries it and `population.pending` to the result.
- `evals/cve/nuisance/report.py`: `ExitLine.reason: ExitReason`. `NuisanceReport.admission_commit: str` and `NuisanceReport.pending_admission: list[str]`, filled by `build_report`.
- `evals/cve/nuisance/markdown.py`: `_exits_section` prints the eight rows by their display text, then the pending line when a server is pending. The `Commits:` line names the admission's commit. Docstrings of `_exits_section` and `_not_run_section` corrected.
- `evals/cve/nuisance/gate/gate_console.py` and `evals/cve/nuisance/gate/gate_report.py`: the "Outside the gate" lines print `EXIT_REASON_TEXTS[e.reason]`, so their text does not change.
- `evals/cve/nuisance/gate/gate_session.py`: no edit expected, `outside_gate` unchanged in behavior, its reasons now `ExitReason` members through `standing_exit`.
- `evals/nuisance_admission.json`: the `exits` list, 54 records (pi-llm-wiki and scaffold-mcp have none), in the order `walk` prints its servers (the detection walk's reaches first, then the addition's, which is the order of the table above and not a strict draw-position sort).
- Tests (see Test scenarios) and their `given`/`then` modules: every crafted `NuisanceAdmission` gains `exits=[]` through its `given` builder (`an_admission()` in `tests/unit/nuisance/admission/support/test_nuisance_admission_given.py` is the only constructor in the tests, the others derive from it with `model_copy`). Every `ServerExit` a test builds with a literal string takes an `ExitReason` member instead, or pyright strict refuses it: `tests/unit/nuisance/test_nuisance_holdout_servers.py`, `tests/unit/nuisance/test_nuisance_report.py`, `tests/unit/nuisance/test_nuisance_run.py` (its `"marked by the walk"` is no reason of the rule, any member does), `tests/unit/nuisance/gate/test_nuisance_gate_selection.py` and `tests/unit/nuisance/gate/support/test_nuisance_gate_report_given.py`. The two gate tests that expect `{OUTSIDE.reason}` in printed output (`tests/unit/nuisance/gate/test_nuisance_gate_console.py`, `tests/unit/nuisance/gate/test_nuisance_gate_report.py`) expect the display text, `does not run over stdio`. The one `RunPopulation(servers, exits)` of the tests, in `run()` of `tests/unit/nuisance/support/test_nuisance_run_given.py`, gains the `pending` argument, and its `RunProvenance` the admission's commit. The provenance tests (`tests/unit/nuisance/test_run_nuisance_run.py` with `support/test_run_nuisance_run_given.py`, `tests/unit/nuisance/test_nuisance_run.py`, `tests/unit/nuisance/test_nuisance_report.py` with `support/test_nuisance_report_given.py`) carry the admission's commit. `tests/unit/nuisance/admission/test_nuisance_walk.py` tests `reached_servers`.
- `docs/nuisance-suite-log.md`: the dated entry (see Log entry).
- `CLAUDE.md`: the `run_nuisance run` line gains two clauses, the exits table ("prints the exits table, one row per reason of the rule with its count and its servers, from the walk's marks, the servers it reaches with no flaw that may count, the admitted servers' launch fields and the exits the admission records, then the reached servers whose admission is pending") and the provenance ("records the commits of the census, the walk record and the admission in its run result, its report and the markdown's `Commits:` line").
- `README.md` (line 175, the published nuisance paragraph): "Of the 120 servers the nuisance walk reached, these are the ones no exit of the rule takes out." implies an exit for each of the other 55 listed servers, which pi-llm-wiki lacks, and leaves scaffold-mcp out. It becomes: "Of the 121 servers the nuisance walk reached, 55 are outside the nuisance holdout layer under an exit of the rule, and one, whose admission is pending, was not audited." With the 65 audited servers of the sentence before, the paragraph accounts for 121. No number of the published rate moves.
- `CONTRIBUTING.md` (the nuisance paragraph, line 56): the admission file records, beside the admitted servers, each listed server it leaves out with its reason and the date of its log entry. The admission's refusals gain the new ones (a recorded exit for a server the walk does not list, or for one it marks, two recorded exits for one server, a server admitted and recorded out, a recorded acceptance target reason). The run's report prints the exits table, a reached server neither admitted nor out listed as pending. The sentence "It records the commits of the census and the walk record in its run result, its report and the markdown's `Commits:` line" becomes "It records the commits of the census, the walk record and the admission in its run result, its report and the markdown's `Commits:` line".
- `CHANGELOG.md`, `[Unreleased]`, under Changed: a bullet saying that the nuisance run's report prints the first exits table of the rule, one row per reason with its count and its servers, from the walk's derived exits and the exits the admission records (`exits` in `evals/nuisance_admission.json`, which the admission load checks against the walk), followed by the reached servers whose admission is pending, which the run result and the report carry in `pending_admission`. The existing bullet that records `walk_record_commit` beside `census_commit` gains `admission_commit`, the last commit of the admission.
- `docs/glossary.md`: the **exit** entry gains `Code: exits in the admission file (evals/nuisance_admission.json), ExitReason`, and the **admission** entry's `Code:` gains `pending_admission` in a nuisance run result and its report (the reached servers neither admitted nor out). No new term ("admission pending" is plain wording, no new noun), no meaning moves, so `docs/glossary-log.md` is not touched.

## What stays unchanged

- The counter (`counter.py`, `counting.py`) and its fingerprint, the grammar and its fingerprint, every fixture fingerprint: no baseline reset, and no nuisance acceptance server is admitted, so the nuisance gate has nothing to reset either.
- The 65 admitted server records, the walk record, the census.
- The "Not run" section and its causes.
- The population the run audits: the 56 servers outside the layer were never audited, so N, the statistic and the rate do not move. No labeling log entry: nothing that grades, labels or decides N changes.
- The committed report `evals/cve/holdout_runs/2026-11-19_nuisance_1765d9f.{md,json}`.
- The rule texts (`docs/nuisance-suite-rule.md`, `docs/detection-suite-rule.md`): no new version.
- `vet`, `gate`, `fix-check`, `walk` and `nuisance-dossier` behavior: they load the admission and keep loading it with `exits`, `vet` audits the same servers, the gate prints the same reason texts, `walk` lists the same 120 servers, and the re-admission dossier copies one server's record and does not see the list.

## Edge cases

- A server the walk reaches with no flaw that may count: one exit, no counted flaw, derived. The walk drops it before it marks it, so its row is no counted flaw even when it is an excluded server or the server of an acceptance target. A record for it is refused at load (check 1). A nuisance acceptance server admitted outside the walk that is also in this list is listed once, under no counted flaw.
- A server the walk marks and also admitted (existing behavior): one exit, the mark's, as today.
- A recorded exit on a server the walk does not reach (typo, a package spelled as the census spells it while the walk normalizes it): refused at load. The JSON uses the walk's normalized spelling (`normalized_package`), the one `walk` prints.
- A recorded exit with the reason `acceptance_target_server`: refused at load (check 5), whatever the server.
- A recorded `excluded_server` on an unmarked server (a fork of an excluded server's repository): accepted, listed under an excluded server.
- An admitted server recorded out, `spent_by_a_reading` included: refused at load (check 4).
- An empty `exits` list with every listed server admitted: the table prints eight rows, every row at `0 server(s)` but the derived ones, and no pending line.
- A listed server neither admitted nor recorded out: the run proceeds, the server is neither audited nor in the table, and the pending line names it.
- The addition: `addition_entries` counts admitted servers only, and a recorded exit does not count toward the addition's size, as today a non-admitted server does not. `addition_entries` is not changed.

## Test scenarios

Tests first, each run red before the code, given/then extracted only where they abstract something.

`tests/unit/nuisance/admission/test_nuisance_walk.py`:

- `reached_servers` over the census of `test_a_server_whose_every_flaw_fails_leaves_the_population` (two flaws, `npm:bad` settled not pinnable in the record): `listed` holds `npm:ok` only and `without_candidates == ["npm:bad"]`.

`tests/unit/nuisance/admission/test_nuisance_admission_walk.py` (load checks, through `admission_given.problems_of`):

- a recorded exit for a listed server, not admitted: no problem.
- a recorded exit for a package the walk does not reach: exactly the "does not reach" problem naming it.
- a recorded exit for a server the walk reaches with no flaw that may count: exactly the problem naming it and "no counted flaw".
- a recorded exit for a server the walk marks: one problem naming the mark's display text, "an excluded server". Walk inputs from the existing walk given, `walk_given.walk_inputs_of(walk_given.a_census_walking([("exc1", "drawn", walk_given.AN_EXCLUDED_SERVER)]))`, as `test_an_excluded_server_is_marked_excluded` builds them, with an admission whose `servers` list is empty, so no new walk given is written.
- two recorded exits for one server: one problem.
- a server admitted and recorded out for "no counted tool left": one problem naming the reason's display text. The same with "spent by a reading": one problem.
- a recorded `acceptance_target_server` for a listed, unmarked, unadmitted server: exactly the problem naming the reason.

`tests/unit/nuisance/test_nuisance_holdout_servers.py`:

- a recorded exit is in `exits` with its reason, and its server is not audited.
- a server of `without_candidates` is in `exits` under no counted flaw, and neither audited nor pending.
- `pending` lists a listed, unmarked server neither admitted nor recorded out, and not one that is admitted, recorded out, or marked.

`tests/unit/nuisance/test_nuisance_report.py`:

- `test_exit_rows_are_grouped_by_reason` becomes: every reason of the rule prints one row in the rule's order, by its display text, with its count, a reason with no server reading `0 server(s)` and listing none.
- `test_no_exit_reads_none_in_both_sections` is rewritten: with no exit, the exits section still prints its eight rows at zero, and the not-run section still reads `- none`.
- the JSON dump carries `exits` with the reason's identifier (existing test, its `ServerExit` built with the enum member, its expected `"reason"` now `"excluded_server"`), and `pending_admission`.
- a pending server prints the line `- admission pending (not an exit of the rule): 1 server(s): <package>` after the eight rows, and a report with none prints no such line.
- the `Commits:` line names the census, walk record and admission commits.

`tests/unit/nuisance/test_nuisance_run.py`:

- the run result carries the population's pending servers in `pending_admission`.
- the run result carries the census, walk record and admission commits apart.

`tests/unit/nuisance/test_run_nuisance_run.py`:

- `test_run_records_the_census_and_walk_record_commits_in_its_result` becomes `test_run_records_the_census_walk_record_and_admission_commits_in_its_result`, its result's `admission_commit` reading `commit-of-nuisance_admission.json`.

`tests/unit/nuisance/admission/test_nuisance_admission_loads.py` (committed data):

- every `logged_on` of the committed admission is the date of an entry of `docs/nuisance-suite-log.md` (a typo guard).
- over the committed walk and admission, every server the walk reaches (`listed` and `without_candidates` of `reached_servers`) is in exactly one of `audited`, `exits` (recorded or derived) or `pending`. No count and no pending list is pinned: the counts go in the log entry and the scratch checks.

The gate tests (`tests/unit/nuisance/gate/`) keep passing with `ServerExit` built from `ExitReason` members, their printed strings unchanged.

## Log entry

A dated entry appended to `docs/nuisance-suite-log.md`, in English, in the commit that adds the data (step 1), dated that day, so the committed reasons and the log agree in one commit. It names no hash of its own commit, which `git log` on the entry finds. It describes the whole change, whose report side lands in the next commit. It says:

- The gap: the run of 2026-11-19 at `1765d9f` printed "Exits: none" in its first table, while 56 of the 121 servers the nuisance walk reaches were not in the nuisance holdout layer (55 of the 120 it lists, pi-llm-wiki among them with its admission pending, and scaffold-mcp, which it does not list), their reasons logged in this log but not held as data. Its committed report stays as it is.
- The change: the admission file now records each listed server it leaves out with its reason, from the rule's closed list, and the date of the entry of this log that states the facts the reason rests on. The walk derives no counted flaw for a server it reaches with no flaw that may count (scaffold-mcp, 2026-11-06). The run's report prints the first table from the walk's marks and derived exits, the admitted servers' launch fields and the recorded exits, and names after it, outside the rule's list, a listed server neither admitted nor recorded out (pi-llm-wiki today, deferred on 2026-10-31 with no later entry). The run records the admission's commit beside the census's and the walk record's. The tie-break rule, stated once. No rule version: the code catches up with the rule. No fingerprint moves, no baseline resets, N does not change.
- The two tables of the 2026-11-19 run, recomputed: the first with one row per reason, its count and its servers (no counted flaw 33, no counted tool left 21, its patched version does not run under Docker 1, the other five reasons 0, from step 1's scratch check), then the pending line. The second as that run printed it, no server left out of N (65 servers run, none not run, no second pass).
- The four rulings on ambiguous cases (create-mcp-server-stdio, stata, cardano402, functype), each with its reason, as stated under the classification.
- That 26 of the 54 exit records are published with the reason logged before nuisance suite rule v4 and no later entry, as logged, not re-admitted: the 25 dated 2026-10-31 or earlier, and dynatrace, which the entry of 2026-11-05 lists again among the servers going through the admission with nothing logged for it since, and which keeps no counted flaw from 2026-11-01. pi-llm-wiki, the 27th such server, has no record.

## Verification

```bash
uv run pytest tests/unit/nuisance -n 0          # while writing the tests, the files touched
uv run pytest tests/unit -n auto --maxprocesses 6
uv run python -m evals.run_nuisance walk        # the admission with its exits loads and 120 servers are listed, no LLM, no Docker
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
```

No Docker command, no LLM call, no eval run. Two scratch checks on the committed data, without a run, in the session scratchpad (not in the repository). After step 1, the counts: compute `run_population(reached_servers(walk_inputs), admission, acceptance_target_servers(walk_inputs))` and group its `exits` by reason: no counted flaw 33 (scaffold-mcp among them), no counted tool left 21, not under Docker 1, the five others 0, 65 audited, `pending == ["npm:@zosmaai/pi-llm-wiki"]`. After step 2, the rendering: build a `NuisanceReport` with `model_construct(exits=..., pending_admission=...)` (`_exits_section` reads only those two fields, and `build_report` needs a full run) and print `_exits_section`: its rows must match the log entry's first table.

No per-case trace of any holdout server is read at any step: the sources are the nuisance log, the admission file, the census, the walk record and the output of `walk`.

## Due diligence record

What the due-diligence pass concluded about the facts this plan takes from outside the repository, read by the implementation-phase fact check. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits the corresponding fact by hand deletes the line rather than updating it.

The plan cites no third-party API, library version or CI action, and defers no external value to implementation (the 54 `logged_on` dates are repository data, inlined in the table above). The platform behavior it relies on:

- SETTLED: `class ExitReason(StrEnum)` with the value `"no_counted_flaw"` serializes to its value through `dataclasses.asdict` plus `json.dumps`, and formats to its value in an f-string, which is why every printed line goes through `EXIT_REASON_TEXTS` (verified against the project's interpreter, Python 3.13.16, `requires-python = ">=3.13"`)
- SETTLED: a pydantic `BaseModel` field typed `ExitReason` and one typed `date` load from the JSON strings `"no_counted_flaw"` and `"2026-10-27"` and dump back to them (verified against the project's pydantic 2.14.1)

## Implementation steps

Two steps. The first holds the enum and its display mapping, the derived exit of a server reached with no flaw that may count, the load checks, the run population, the 54 committed exit records and the log entry together. `NuisanceAdmission.exits` has no default, so the committed file must carry the list in the commit that adds the field, or `test_the_committed_admission_loads` fails. The identifiers reach the gate's printed lines and the report's markdown in the same commit, so the display mapping comes with them, or `test_run_nuisance_gate` fails on its printed `does not run over stdio`. And the log entry agrees with the committed reasons in the commit that adds them. The second carries the pending servers and the admission's commit through the run result and the report, renders the eight-row table, and writes the remaining living docs. One step would touch 13 production files, the admission JSON, 6 docs and about 20 test modules, past one session's budget.

### Step 1: `ExitReason`, the derived and recorded exits, their load checks, the run population, the committed data and the log entry

**Files**

- Tests first: `tests/unit/nuisance/admission/test_nuisance_walk.py`, `tests/unit/nuisance/admission/test_nuisance_admission_walk.py`, `tests/unit/nuisance/admission/support/test_nuisance_admission_walk_given.py`, `tests/unit/nuisance/admission/support/test_nuisance_admission_given.py` (`an_admission()` gains `exits=[]`), `tests/unit/nuisance/test_nuisance_holdout_servers.py`, `tests/unit/nuisance/admission/test_nuisance_admission_loads.py`.
- Mechanical test edits forced by pyright strict on `ServerExit.reason: ExitReason`, `RunPopulation.pending` and `run_population`'s first parameter, and by the identifiers in JSON: `tests/unit/nuisance/test_nuisance_report.py` (enum members, the JSON dump's `"reason"` now `"excluded_server"`, the grouped rows unchanged since they print the display text), `tests/unit/nuisance/test_nuisance_run.py` (its `"marked by the walk"` becomes any member, say `ExitReason.EXCLUDED_SERVER`), `tests/unit/nuisance/gate/test_nuisance_gate_selection.py`, `tests/unit/nuisance/gate/support/test_nuisance_gate_report_given.py`, `tests/unit/nuisance/gate/test_nuisance_gate_console.py` and `tests/unit/nuisance/gate/test_nuisance_gate_report.py` (they expect `does not run over stdio` where they formatted `{OUTSIDE.reason}`), `tests/unit/nuisance/support/test_nuisance_run_given.py` (`RunPopulation(servers, exits, ())` for now, the `pending` keyword on `run()` comes in step 2).
- Production: `evals/cve/nuisance/exits.py` (new), `evals/cve/nuisance/results.py`, `evals/cve/nuisance/admission/walk.py`, `evals/cve/nuisance/admission/admission_walk.py`, `evals/cve/nuisance/admission/admission.py`, `evals/cve/nuisance/holdout_servers.py`, `evals/run_nuisance.py`, `evals/cve/nuisance/vet_command.py`, `evals/cve/nuisance/report.py`, `evals/cve/nuisance/markdown.py`, `evals/cve/nuisance/gate/gate_console.py`, `evals/cve/nuisance/gate/gate_report.py`, `evals/nuisance_admission.json`.
- Docs: `docs/nuisance-suite-log.md`, `CONTRIBUTING.md`.

**Do**

1. Write the tests below and run them red with `uv run pytest <files> -n 0`.
2. `exits.py`: `ExitReason` with the eight members and identifier values of the plan (Decisions, "The reasons"), in the rule's order, `EXIT_REASON_TEXTS` with the eight display texts, and `class RecordedExit(BaseModel)` with `server_package: str`, `reason: ExitReason`, `logged_on: date`. It imports no repository module.
3. `results.py`: `ServerExit.reason: ExitReason`, imported from `exits.py`.
4. `walk.py`: `ReachedServers` (`listed: Sequence[NuisanceServer]`, `without_candidates: Sequence[str]`) and `reached_servers(walk_inputs)`, which returns `nuisance_population(walk_inputs)` as `listed` and, in walk order, the servers of `_first_reaches(walk_inputs)` whose `candidate_counted_flaws` is empty. `nuisance_population` is unchanged.
5. `admission_walk.py`: `MARK_REASONS: dict[ServerMark, ExitReason]` (`EXCLUDED` to `EXCLUDED_SERVER`, `ACCEPTANCE_TARGET_SERVER` to `ACCEPTANCE_TARGET_SERVER`). `standing_exit(server) -> ExitReason | None` returns `ExitReason.NOT_OVER_STDIO` or `ExitReason.NOT_UNDER_DOCKER`. New `exit_problems(admission: NuisanceAdmission, walk_inputs: WalkInputs) -> list[str]`, reading `nuisance_walk.reached_servers(walk_inputs)` and its five checks from private helpers right below it (newspaper rule), with the exact messages of the plan (Decisions, "Load checks"), every reason and mark printed by its display text through `EXIT_REASON_TEXTS`. Update the module docstring to name the recorded exits' agreement with the walk.
6. `admission.py`: `NuisanceAdmission.exits: list[RecordedExit]` (required, no default), imported from `exits.py`. `admission_problems` appends `exit_problems(admission, walk_inputs)`, imported from `admission_walk` beside `walk_problems`. The module docstring names the new list. Keep the file's additions to these lines (it is at 304).
7. `holdout_servers.py`: drop `_MARK_REASONS` for `MARK_REASONS`. `RunPopulation` gains `pending: Sequence[str]` (third field). `run_population(reached: ReachedServers, admission, acceptance)` lists the walk marks of `reached.listed`, one no counted flaw exit per server of `reached.without_candidates`, the admitted servers' exits (an admitted server marked or in `without_candidates` skipped, as a marked one is today), then one `ServerExit` per recorded exit, and fills `pending` with the servers of `reached.listed`, in walk order, that are unmarked, not admitted and not recorded out. Move the recorded exits and the pending computation into two private helpers right below `run_population`. Correct the docstrings of `RunPopulation` and `run_population` (the exits no longer "live in the log").
8. `evals/run_nuisance.py` (`_run`) and `evals/cve/nuisance/vet_command.py` (`vet`): call `run_population(reached_servers(walk_inputs), admission, acceptance_target_servers(walk_inputs))`, dropping their now unused `nuisance_population` import where nothing else uses it (`_walk` in `run_nuisance.py` keeps it).
9. `report.py`: `ExitLine.reason: ExitReason`. `markdown.py`: `_exits_section` keys its grouping by `ExitReason` and prints each reason by `EXIT_REASON_TEXTS[reason]`, its format otherwise unchanged until step 2. `gate_console.py` and `gate_report.py`: the "Outside the gate" lines print `EXIT_REASON_TEXTS[e.reason]`. `gate_session.py`: no edit expected, confirm with pyright that `outside_gate` still types.
10. `evals/nuisance_admission.json`: add a top-level `"exits"` list with the 54 records of the classification table (pi-llm-wiki and scaffold-mcp have none), each `{"server_package", "reason", "logged_on"}`, `reason` the identifier (`no_counted_flaw`, `no_counted_tool_left`, `not_under_docker`), `logged_on` the table's date. Use the walk's normalized spelling of each package and the order `uv run python -m evals.run_nuisance walk` prints (the detection walk's reaches first, then the addition's): run the command first and match each table row to a printed server, a table package that the walk spells differently taking the walk's spelling. Keep the file's existing formatting (indentation, key order of the top level: put `exits` after `servers`).
11. Scratch count check (Verification): the counts and the pending list must read as the plan states. Its output, grouped by reason in report order, gives the servers of the log entry's first table.
12. `docs/nuisance-suite-log.md`: append the dated entry described in the plan's "Log entry" section, dated the day of this step's commit, in English, with no em dash, following the format of the log's existing entries. It names no hash of its own commit.
13. `CONTRIBUTING.md` (the nuisance paragraph, line 56): the admission file records each listed server it leaves out with its reason and the date of its log entry, and the sentence listing the admission's refusals ("the admission is refused when it admits a server the walk does not reach ...") gains the five new ones of the plan's "Files to modify". The report and provenance sentences come in step 2.

**Test**

`test_nuisance_walk.py`:
- `reached_servers(settled)` on the census and record settlement of `test_a_server_whose_every_flaw_fails_leaves_the_population`: `[s.server_package for s in reached.listed] == ["npm:ok"]` and `reached.without_candidates == ["npm:bad"]`.

`test_nuisance_admission_walk.py`, through `admission_given.problems_of`, with two builders in `support/test_nuisance_admission_walk_given.py` that hide the irrelevant date: `a_recorded_exit(package, reason=ExitReason.NO_COUNTED_TOOL_LEFT)` and `recording(admission, *exits)` (a `model_copy` that sets `exits`).
- a recorded exit for `SERVER_PACKAGE`, listed and not admitted (`an_admission()` with its `servers` emptied): `[]`.
- a recorded exit for a package the walk does not reach: exactly the "does not reach" problem naming it.
- a recorded exit for `npm:bad` over the walk inputs of the `reached_servers` test above, with an admission whose `servers` list is empty: exactly the problem naming `npm:bad` and `no counted flaw`.
- a recorded exit for the excluded server the walk lists (walk inputs `walk_given.walk_inputs_of(walk_given.a_census_walking([("exc1", "drawn", walk_given.AN_EXCLUDED_SERVER)]))`, the package as `nuisance_population` lists it, an admission whose `servers` list is empty): one problem naming `an excluded server`.
- two recorded exits for one listed server: one problem `"{package}: 2 recorded exits"`.
- `an_admission()` (which admits `SERVER_PACKAGE`) plus a recorded `no counted tool left` exit for it: one problem naming `no counted tool left`. The same with `spent by a reading`: one problem naming `spent by a reading`.
- a recorded `ExitReason.ACCEPTANCE_TARGET_SERVER` exit for `SERVER_PACKAGE`, listed, unmarked and not admitted: exactly the problem naming `the server of a current or dropped acceptance target`.

`test_nuisance_holdout_servers.py` (the existing calls wrap their listed servers as `ReachedServers(walked, ())`):
- a recorded exit appears in `exits` with its `ExitReason` and its server is not in `audited`.
- `ReachedServers([], ["npm:left"])` with an admission admitting no server: `exits == [ServerExit("npm:left", ExitReason.NO_COUNTED_FLAW)]`, `audited == []`, `pending == []`.
- `pending` lists a listed, unmarked server neither admitted nor recorded out, and does not list an admitted one, a recorded-out one, or a marked one.
- existing tests keep passing with `ServerExit` built from enum members.

`test_nuisance_admission_loads.py` (committed data):
- every `logged_on` of the committed admission's `exits` is the date of an entry of `docs/nuisance-suite-log.md`, an entry being a line starting `- YYYY-MM-DD:` (read the log with `REPO_ROOT`, collect the dates with a regex). A typo guard only.
- over the committed walk and admission, with `reached = reached_servers(walk_inputs)` and `population = run_population(reached, admission, acceptance_target_servers(walk_inputs))`, each package of `reached.listed` and `reached.without_candidates` appears exactly once across `population.audited`, `population.exits` and `population.pending`. Read the inputs as `evals/run_nuisance.py`'s `_run` reads them. No count is pinned.

**Verify**

- `uv run pytest <changed test files> -n 0` while red, then `uv run pytest tests/unit -n auto --maxprocesses 6` (`--lf` on failures, then the full short loop again).
- `uv run python -m evals.run_nuisance walk`: the admission with its `exits` loads, no refusal, 120 servers listed.
- The scratch count check prints the counts of the plan.
- Closing pass: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright` (no file argument), all green.
- No Docker, no LLM. Do not grow Docker disk usage.

### Step 2: the exits table in the report, the pending servers and the admission's commit through the run, the living docs

**Files**

- Tests first: `tests/unit/nuisance/test_nuisance_report.py` and `support/test_nuisance_report_given.py` (`a_run_result` gains `admission_commit`, a builder takes `pending_admission` if a test needs it), `tests/unit/nuisance/test_nuisance_run.py`, `tests/unit/nuisance/support/test_nuisance_run_given.py` (`run()` gains a `pending: Sequence[str] = ()` keyword passed to `RunPopulation`, and its `RunProvenance` an `admission_commit`), `tests/unit/nuisance/test_run_nuisance_run.py` and `support/test_run_nuisance_run_given.py` (`an_admitted_run_keeping_its_provenance` carries `admission_commit` too).
- Production: `evals/cve/nuisance/results.py`, `evals/cve/nuisance/run.py`, `evals/run_nuisance.py`, `evals/cve/nuisance/report.py`, `evals/cve/nuisance/markdown.py`.
- Docs: `CLAUDE.md`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/glossary.md`.

**Do**

1. Write the tests below, run them red.
2. `results.py`: `NuisanceRunResult.admission_commit: str` right after `walk_record_commit`, and `pending_admission: Sequence[str] = ()` (a field with a default, so placed after the last non-default field).
3. `run.py`: `RunProvenance.admission_commit: str`. `_assemble_run` passes `admission_commit=ctx.provenance.admission_commit` and `pending_admission=list(population.pending)` (a partial result goes through `_assemble_run` too and carries both). `evals/run_nuisance.py`: `RunProvenance(last_commit(args.census), last_commit(args.walk_record), last_commit(args.admission))`.
4. `report.py`: `NuisanceReport.admission_commit: str` and `pending_admission: list[str]`, filled by `build_report` from the run.
5. `markdown.py`: the `Commits:` line ends with `, admission {report.admission_commit}`. `_exits_section` prints one row per member of `ExitReason`, in enum order, `- {EXIT_REASON_TEXTS[reason]}: {n} server(s)` followed by `: {packages}` (comma-joined, report order) when `n > 0`, then, when `report.pending_admission` is non-empty, `- admission pending (not an exit of the rule): {n} server(s): {packages}`. The `- none` line goes. Correct the docstrings of `_exits_section` and `_not_run_section` (no exit "lives in the log" any more). The "Not run" section is otherwise unchanged.
6. Scratch rendering check (Verification): its rows must match the first table of the log entry written in step 1. A mismatch is fixed in the code, or in the log entry when the entry is wrong, before this step closes.
7. Living docs, wording given by the plan's "Files to modify":
   - `CLAUDE.md`: the `uv run python -m evals.run_nuisance run` line gains the exits-table clause and the provenance clause.
   - `README.md` (the published nuisance paragraph, near line 175): replace "Of the 120 servers the nuisance walk reached, these are the ones no exit of the rule takes out." with the plan's sentence. No published number moves.
   - `CONTRIBUTING.md` (nuisance paragraph, near line 56): the run's report prints the exits table, a reached server neither admitted nor out listed as pending, and the commits sentence names the admission.
   - `CHANGELOG.md` `[Unreleased]`, under Changed: the new bullet of the plan, and `admission_commit` added to the existing `walk_record_commit` bullet.
   - `docs/glossary.md`: the **exit** entry gains `Code: exits in the admission file (evals/nuisance_admission.json), ExitReason`, and the **admission** entry's `Code:` gains `pending_admission`. `docs/glossary-log.md` is not touched.
   - Do not touch `plans/`, `docs/adr/`, the rule texts, or the committed report `evals/cve/holdout_runs/2026-11-19_nuisance_1765d9f.*`.

**Test**

`test_nuisance_report.py`:
- `test_exit_rows_are_grouped_by_reason` becomes: every reason of `ExitReason` prints one row in enum order, by its display text, with its count. A reason with servers lists them in report order. A reason with none reads `- {text}: 0 server(s)` and lists nothing.
- `test_no_exit_reads_none_in_both_sections` rewritten: with no exit, the exits section prints its eight rows at `0 server(s)` and no `- none`. The not-run section still reads `- none`.
- a report with one pending server prints `- admission pending (not an exit of the rule): 1 server(s): <package>` right after the eight rows. A report with none prints no such line.
- the JSON dump (`test_the_report_writes_the_holdout_nuisance_rate_and_the_exits_under_the_glossary_keys`, or a new test beside it) carries `pending_admission` and `admission_commit`.
- `test_the_provenance_line_names_the_census_and_walk_record_commits` becomes `test_the_provenance_line_names_the_census_walk_record_and_admission_commits`: `Commits: run deadbeef, census cafe1234, walk record beef5678, admission <the given's commit>`.

`test_nuisance_run.py`:
- `run(..., pending=["npm:pending"])` returns a result whose `pending_admission == ["npm:pending"]`.
- `test_a_run_records_the_census_and_walk_record_commits_apart` becomes `test_a_run_records_the_census_walk_record_and_admission_commits_apart`, reading the three commits of the given's `RunProvenance`.

`test_run_nuisance_run.py`:
- `test_run_records_the_census_walk_record_and_admission_commits_in_its_result`: the result's `admission_commit == "commit-of-nuisance_admission.json"`, beside the two existing assertions.

The gate tests (`tests/unit/nuisance/gate/`) keep passing unchanged.

**Verify**

- `uv run pytest <changed test files> -n 0` while red, then `uv run pytest tests/unit -n auto --maxprocesses 6` (`--lf` on failures, then the full short loop again).
- The scratch rendering check matches the log entry's first table.
- `uv run python -m evals.run_nuisance walk` still loads.
- Closing pass: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright` (no file argument), all green.
- No Docker, no LLM, no eval run, no per-case trace of any holdout server read.
