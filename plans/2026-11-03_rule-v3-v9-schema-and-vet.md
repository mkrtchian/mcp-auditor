# Rule v3 and v9: the admission and card schema, the vet, two fixture checks

## Context

Version 3 of the nuisance rule (`docs/nuisance-rule.md`, commit `06ab00a`, log entry of 2026-11-02 in `docs/nuisance-log.md`) and version 9 of the holdout rule (`docs/holdout-rule.md`, same commit, log entry of 2026-11-02 in `docs/holdout-log.md`) add fields the code has no place for, and a benign call criterion the vet does not apply. This plan brings the schema, the card, the vet and two fixture checks in line, and repairs the praisonai fixture. It does not rewrite the stand-ins and responders for realism (later plans), and it takes no tool out of the count: a re-admission campaign, two blind agents per server outside the repository, fills the new nuisance fields for the 59 servers, and the holdout calibration campaign fills the card fields. The `tools/list` pagination is already fixed (`698c568`, `ee84296`).

What the code does today, checked at `1ecfad0`:

1. **The admission schema** (`evals/nuisance_admission.py`, 270 lines). `ToolRecord{vulnerable_name, patched_name, status}`, `BenignCall{tool, arguments}`, `FixCheckRecord{source, witness, exploit_calls, vulnerable_surfaces, patched_surfaces, server_patched_surfaces, patched_benign_errored}`, `FlawRecord`, `AdmittedServer` have every field required except `AdmittedServer.backend`. Nothing records whether a tool's benign call can return without error on the real software and under the confinement (rule v3, Eligibility, The real software), where a stand-in's outputs come from (Admission, Stand-ins), what the fixture seeds and from which sample (Admission, Seeding), or whether a fix check's positive control rests on a stand-in that relays the flaw's effect (Admission, What no fixture serves, and A fix verified by reproduction).
2. **The counted tools** (`evals/nuisance_counting.py`). `flaw_counted_tools` keeps every patched name of a tool not removed, unless the flaw has no class, needs an external backend or has `declared_function_is_effect`. `counted_tools` takes the union over the counted flaws, so one tool listed by two flaws (arcadedb `execute_command`, aws-api `call_aws`, ckan, doris, flyto, neo4j, googleapis) carries the union of their verdicts.
3. **The benign call** (`evals/nuisance_audit.py`, `benign_call_failure`, the file is 294 lines). It makes the first benign call per counted tool of the counted flaws and fails on an exception or on `response.is_error`. It never reads the response text and never checks that a counted tool is in the server's `tools/list`. A prerequisite call on a tool that is not counted (mysql's `connect_to_database`) cannot be expressed, since calls on non-counted tools are filtered out. A vet that prints `59 of 59` at `1ecfad0` therefore passes three benign calls whose answer is no success: praisonai `praisonai.workflow.show` answering `File not found: agents.yaml` with `isError: false`, mysql `run_query` answering `{"error": "No database connection available ..."}` without its prior `connect_to_database`, and wireshark `quick_capture` answering a capture failure under the confinement (no `NET_RAW`) without an error flag.
4. **`MCPClient.call_tool`** (`src/mcp_auditor/adapters/mcp_client.py` l.90) joins the `TextContent` items only, so a tool answering an image alone yields `content == ""`. A source sweep of the run images of the servers whose counted tools could answer media (android, claude-in-mobile, ios-simulator, figma, markdownify, godot-mcp, adb-mcp) found image content only in claude-in-mobile, and only on its screen tools, never on its counted `system` tool (whose benign call runs `shell getprop`). No counted tool's benign call answers an image alone.
5. **Benign calls are duplicated across flaws.** kanban repeats identical calls. ckan's `ckan_package_search` has two different calls: `{"server_url": "https://www.dati.gov.it", "q": "water", "rows": 1}` on its counted flaw CVE-2026-73844, and `{"server_url": "https://demo.ckan.org", "q": "water"}` on four flaws that do not count. `benign_call_failure` keeps the first call per tool in counted-flaw order, so a second differing call on a counted flaw would be ignored silently.
6. **The fix-check comparison** (`evals/nuisance_calibrate_command.py`, `_field_mismatches`) iterates `FixCheckRecord.model_fields` and reads each name off the kit's `FixCheckResult` with `getattr`. A field of the record that the kit does not observe would raise `AttributeError` there.
7. **The fix-check parity test** (`tests/unit/test_nuisance_fix_checks.py`, `test_each_target_mechanism_and_tools_match_the_admission_flaw`) compares the tools an exploit calls with `flaw_counted_tools(record)`. A tool that leaves the count for its real software is still the tool the exploit reaches the flaw through.
8. **The calibration card** (`evals/census_draw.py`, 249 lines). `CalibrationCard` has `seeded_in_layout` and `launch_options` but no field for what is seeded outside the layout or for the stand-ins (holdout rule v9, Calibration card). `CardCheck{flaw, reported_gaps, confirmed_gaps}` does not say under which rule version the second agent checked the card. Nothing reads a card at run time: `run_holdout run` audits `holdout_targets.HOLDOUT_TARGETS` (30 targets) without looking at the census cards.
9. **Fingerprints.** `nuisance_fixture_fingerprint` (`evals/nuisance_fingerprint.py`) hashes the benign calls as `(tool, arguments)`. No run Dockerfile and no backend Dockerfile in `evals/docker/` has a `COPY` or an `ADD`, so "the patched Dockerfile with every file it copies in" holds today by accident, not by construction. `cve_baseline.fixture_fingerprint` covers `_ENVIRONMENT_PATHS` but not `evals/doris_backend.py`, whose `_provision_doris_schema` creates `t1` in the database CVE-2025-66335 runs against. `cve_environments.py` imports `doris_backend` (l.76) and no other backend module outside `_ENVIRONMENT_PATHS`. `backend_images` are hashed by their tag, and both of CVE-2025-66335's tags carry their `@sha256:` digest (`DORIS_IMAGE`, `MYSQL_CLIENT_IMAGE`). `evals/baselines/cve/` holds no file today (reset at `54db730`), so no stored acceptance fingerprint exists to compare against, and `evals/baselines/nuisance/` does not exist.
10. **praisonai** (`PyPI:praisonai`, service `praisonai`, 4.6.40). `evals/docker/Dockerfile.praisonai` seeds `/tmp/.praison/rules/seed.txt` holding `seed rule content`, which breaks the v3 limit on words (What no fixture serves). The server runs in `/` with `HOME=/tmp` (`unprivileged_user_args`, `evals/cve_planting_base.py` l.205), and `workflow_show` resolves `file_path` inside the working directory (`_resolve_cwd_yaml_path`), so nothing answers the benign call `{"file_path": "agents.yaml"}`. `rules_show` reads `~/.praison/rules/<rule_name>`. The upstream tree at tag `v4.6.40` (commit `a72e156c4d01ef06c64529d302c21381d6485716`) holds no rules file under `.praison/rules`, and the `rules` CLI (`src/praisonai/praisonai/cli/commands/rules.py`: `list`, `add`, `clear`) generates none.
11. **The dossiers.** `nuisance_dossier._fixture_format` embeds `FlawRecord` and `AdmittedServer` JSON schemas and explains the fields in prose. `calibration_dossier._fixture_format` embeds the `CalibrationCard` schema, and its README step 5 lists the card fields in prose. The models carry no `Field(description=)`. The kit's `check_fix` returns a `FixCheckResult` and prints nothing of the benign responses, so an agent cannot apply the v3 text criterion it does not see.

## Decisions (taken with the maintainer)

1. **Transition by `None`.** Every new field is optional with the pydantic default `None`, which reads "not yet recorded under v3 or v9". An empty list means recorded, nothing to declare. The committed `evals/nuisance_admission.json` and `evals/holdout_census.json` and their loading tests keep working. Loading accepts `None`, and `run_nuisance vet` and `calibrate` run. `run_nuisance run`, `run_nuisance gate` and `run_holdout run` refuse to start while a field that bears on what is counted or run is `None`, listing what is missing: the counted tools of counted flaws, the benign calls of counted tools, the fix checks of counted flaws, the stand-ins and seeds of an audited server, and for the holdout the new card fields and the card check version of a drawn target. A flaw that does not count never blocks (the dead benign call of CVE-2025-67364, fast-filesystem). This acceptance of `None` is a shim: it is removed in the commit of the campaign that fills the last field, where the defaults go, the fields become required, and `unrecorded_fields`, its refusals and the transitional tests are deleted. For the holdout, the same happens in the commit of the calibration campaign that fills the last card. The card check version refusal stays after that commit, since a later version of the rule raises it.
2. **`ToolRecord.real_software: RealSoftwareRecord | None = None`**, with `answers: bool`, `cause: Literal["software_error", "not_distributed", "container_unrepairable"] | None` and `evidence: str | None`. Cause and evidence are required when `answers` is false and absent when it is true. The three causes are the three cases of Eligibility (The real software): an error of the software with every argument the description allows, no distribution channel left, a container failure the fixture cannot repair. The counted-tool predicate excludes `answers=false`, and `None` stays counted ("a tool without such a record stays counted"). Load checks: one verdict per `patched_name` across the server's flaws, since `counted_tools` takes the union; the field is forbidden on a removed tool. A server left with no counted tool is not loaded with an exception path of its own: `_counted_tool_problems` keeps refusing it, and the campaign commit that records the last `answers=false` removes the server's record from the admission and logs it "not admitted, no counted tool left" in `docs/nuisance-log.md`, as the 2026-10-27 entries did for create-mcp-server-stdio and fetch (`nuisance_population.run_population` already documents that this exit never reaches the admission file). The agreement and settlement of this field follow the others, under the canonical field name `real_software` that the dossier states. The parity test compares exploit tools with the flaw's tools, not its counted tools.
3. **Provenance in the admission JSON**, as the rule requires ("the admission records it as invented", "cites it and pins it in the admission", "The admission is committed in one file"). A module shared by the admission and the card, `evals/fixture_provenance.py`, holds `StandInRecord`: what it replaces, why the real software cannot run under the confinement, the repository file that implements it, an optional capture, and its outputs, each with the fixed words of the request it answers, its source kind (`real_software`, `capture`, `software_sources`, `server_tests`, `invented`, where `software_sources` covers the software's documentation, fixtures, tests and published API examples), its citation, the form source of an invented output, and its identifier replacements. A capture-backed stand-in may carry no output entry and reference its capture instead. A unit test checks that every recorded request key appears in the stand-in's file. `SeedRecord` is nuisance-only: item, kind (`published_sample`, `generated`, `project_document`, `written`), citation and pin. `written` covers launch and environment values and the names the benign calls use (Seeding: "each recorded as written, including the names the benign calls use"). The card gains `seeded_outside_layout` (item, reason, the tools that return it in a response, the tools that use it by default, kept apart) and `stand_ins`. `AdmittedServer` gains `stand_ins` and `seeds`. A launch or environment value the card already lists in `launch_options` is listed in `seeded_outside_layout` too, naming the option as its item, because the card check asks of every seeded item which tools return it, a question `launch_options` does not answer.
4. **`BenignCall.expect: str | None = None`**: a substring the response text must contain, and the vet fails when it is absent. A substring is stronger than the rule's negative clause ("no result whose text reports that the call failed"), and when it breaks the server leaves N for one run with its reason, which the rule repairs. No regular expression. Load checks: non-empty, and not contained in the serialized arguments of the call or of its prerequisite calls, since an error text often quotes the arguments. Image-only responses: the adapter is not changed (what the auditor reads is the product, a change there is a system change under ADR 016), and the inventory found no counted tool whose benign call answers an image alone (Context 4). The vet reports an empty response text as "returned no text" when an `expect` is set, so a future such tool is named, and the campaign then writes a benign call whose answer carries text. Duplicate benign calls for one tool are refused across the server's counted flaws, and only there: ckan's differing call on its uncounted flaws stays loadable (Context 5).
5. **`BenignCall.before: list[ToolCall] | None = None`**, the calls made before the checked call, each of which must not error (no protocol error, no `isError`), without an `expect` of its own: the checked call's `expect` covers the chain. The vet also fails when a counted tool or a prerequisite tool is absent from the run client's `tools/list`, under its patched name. The nuisance fingerprint includes `expect` and `before`. A connection at launch is not an alternative: "Every option the server does not need in order to start stays at its documented default, unless a fix needs it set" (Admission), and awslabs-mysql starts without one, so its connection is a prerequisite call.
6. **`FixCheckRecord.relies_on_relaying_stand_in: bool | None = None`.** The rule: "a witness that surfaces only because a stand-in relays it fails the positive control", and a reused holdout calibration counts only "provided the admission records that its positive control does not rest on a stand-in that relays the flaw's effect". `True` counts as a failed positive control in `_counts`, `None` is refused at run under decision 1. The kit does not observe it, so `_field_mismatches` skips it.
7. **`CardCheck.rule_version: int | None = None`.** `run_holdout run` refuses a drawn target whose card check is not at version 9 or later.
8. **Holdout fixture fingerprint, per target.** `CVETarget` gains `backend_sources: tuple[Path, ...] = ()`, the modules through which its builder seeds a backend, fingerprinted only when non-empty, set to `evals/doris_backend.py` for CVE-2025-66335. Adding the module to the global `_ENVIRONMENT_PATHS` would move every acceptance fingerprint and force a reset of the acceptance baseline under ADR 020. Backend images are already content-addressed by their `@sha256:` tag, so a test makes that a requirement rather than hashing image contents. A verification step shows that no acceptance fingerprint moves.
9. **Nuisance fingerprint tests**: no local `COPY` or `ADD` in a run Dockerfile or a backend Dockerfile (`COPY --from` a build stage allowed), a remote `ADD` only with a checksum in Docker's documented form, `--checksum=sha256:<64 hex>` on an HTTP source and `--checksum=<full 40-hex commit SHA>` on a git source, anything else failing, every `SeedRecord` pin in content the fingerprint covers, and every `StandInRecord.file` and `StandInRecord.capture` among the files the fingerprint covers. The holdout twin: every card stand-in's file, and its capture when set, among the files the holdout target's `fixture_fingerprint` covers (holdout rule v9, Run conditions), in a holdout test file of its own.
10. **Dossiers.** Prose for every new field in `nuisance_dossier._FIXTURE_FORMAT` and `_README` and in the README step 5 of `calibration_dossier`, saying each is required for an admission or a card despite its `None` default in the schema. `check_fix` prints the text of the benign responses.
11. **Repairs in this plan: praisonai only.** Seed `/agents.yaml` from the first `agents.yaml` sample the documentation names at 4.6.40, inline in a `RUN`. Replace the rules seed with a document the project publishes, per the Seeding order: the rules-directory example `python.md` of the project's rules page, taken whole under that name in the directory the server reads. Record both as `SeedRecord`s, update both praisonai fix checks, run `calibrate --cve` on both flaws, and log the repair under the maintainer's repair window (rule v3, The benign call). Not in this plan: awslabs-mysql's `before` (adding a prerequisite call is not one of "the arguments of a benign call", the last item of the maintainer's closed repair list, so it goes to the campaign, and the vet stays green meanwhile since `expect` is `None`); renaming the backends whose names carry `mcp-auditor` and `cve`; the `rule_commit` update (with the campaign); tool exits (wireshark, android `monitor-events`: the campaign, since "Taking a tool out of the count falls to the admission agents"). A counted tool the new vet finds absent from `tools/list` on a real fixture is handled by its cause: a cause in the launch is repaired by the maintainer and logged, within the repair window of rule v3, and any other cause is logged and handed to the campaign. Neither fails the plan's verification.
12. **Parity between the admission's benign calls and the fix check's Python benign calls** is settled without code. The clause is "surfaces neither on the flaw's patched version nor on the server's patched version, where every benign call the admission records returns without error": the calls are the admission's data, played on the server's patched version, which is what the vet does. `patched_benign_errored` stays the kit's `is_error` observation.
13. **Dependencies.** The nuisance twins of CVE-2026-85788 (mysql) and CVE-2025-53818 (github-kanban) reuse a holdout calibration that v9 sends back to calibration (holdout log, 2026-11-02), so their `relies_on_relaying_stand_in` waits for the recalibration or a fix check of their own. The campaign's brief, which still names the fields `runs_in_container` and `needs_backend` the schema no longer has, is rewritten for the v3 fields before the campaign, a precondition outside this plan. The card check reading the server's documentation and source is procedural: no card check dossier exists in the repository.
14. **Logs and docs.** Entries in `docs/nuisance-log.md` and `docs/holdout-log.md` (these instruments log their own changes there, as every entry since 2026-10-22 does), not in `docs/labeling-log.md`, which logs the honeypot and acceptance instruments. `CLAUDE.md` Commands, `CONTRIBUTING.md`, `CHANGELOG.md` `[Unreleased]`.

## Approach

The new admission fields and their load checks live in a new module beside `nuisance_admission.py`, which stays the schema's entry point and stays under 300 lines. The run-time refusal is one pure function over the audited servers, called by `run` and `gate`, with a twin over the drawn cards called by `run_holdout run`. The benign call check moves out of `nuisance_audit.py` into a module of its own, because its new branches (listing, prerequisites, expected text) would push that file past 300 lines, and the vet, the run's pre-run check and the gate keep reaching it through `nuisance_vetting.benign_call`. The stand-in record is shared by the admission and the card through `evals/fixture_provenance.py`, which imports neither side. The fingerprints change in two places: the nuisance benign-call part grows, and the holdout fingerprint gains a per-target part that only CVE-2025-66335 sets. The praisonai repair is data and Dockerfile lines, checked by `calibrate --cve` and by the vet.

## Files

### `evals/fixture_provenance.py` (new)

```python
SourceKind = Literal["real_software", "capture", "software_sources", "server_tests", "invented"]
# software_sources: the software's documentation, fixtures, tests and published API examples

class IdentifierReplacement(BaseModel):
    original: str
    replacement: str

class StandInOutput(BaseModel):
    request: str  # the fixed words at fixed positions of the request it answers
    source: SourceKind
    citation: str
    form_source: str | None = None  # the source whose form an invented output follows
    replacements: list[IdentifierReplacement] = []

class StandInRecord(BaseModel):
    replaces: str  # the program, device, HTTP backend or public host
    reason: str  # why the real software cannot run under the confinement
    file: str  # repository path of what implements it: a responder Dockerfile, a backend module, a stub-writing run Dockerfile
    capture: str | None = None  # an evals/stand_ins/ capture that sources every route
    outputs: list[StandInOutput]

def stand_in_problems(stand_in: StandInRecord) -> list[str]: ...
```

`stand_in_problems` is pure and returns, prefixed with `stand_in.replaces`: an `invented` output without `form_source`, a non-invented output with one, an invented output with replacements (an invented output copies nothing to edit), a stand-in with neither an output nor a capture, and an empty `reason`. Newspaper order: the function first, one private helper per output below it.

### `evals/nuisance_admission_records.py` (new)

```python
class RealSoftwareRecord(BaseModel):
    answers: bool
    cause: Literal["software_error", "not_distributed", "container_unrepairable"] | None = None
    evidence: str | None = None  # the run, the capture or the source line, the missing channel, or why the container failure cannot be repaired

class SeedRecord(BaseModel):
    item: str  # a path, a record, a launch or environment value, a name a benign call uses
    kind: Literal["published_sample", "generated", "project_document", "written"]
    citation: str | None = None
    pin: str | None = None  # a commit, a version or a digest

def record_problems(server: AdmittedServer) -> list[str]: ...
```

`AdmittedServer` is imported under `TYPE_CHECKING` with `from __future__ import annotations`, the pattern of `nuisance_counting.py`, so `nuisance_admission.py` can import the two models at run time with no cycle. `record_problems` concatenates, each prefixed with the server package:

- `_real_software_problems(server)`: a removed tool carrying `real_software`; `answers=false` without a non-empty `cause` and `evidence`; `answers=true` with either.
- `_verdict_conflicts(server)`: a `patched_name` whose `real_software` differs between two flaws of the server (`None` against a record is a conflict too), named once with the flaws.
- `_expectation_problems(server)`: on the benign calls of the counted flaws, an empty or blank `expect`, and an `expect` contained in `json.dumps(arguments, ensure_ascii=False)` of the call or of one of its `before` calls.
- `_duplicate_benign_calls(server)`: a tool with two different benign calls across the counted flaws (model equality, so kanban's identical repeats pass and ckan's uncounted calls are not read).
- `_seed_problems(server)`: a `published_sample` without `citation` or `pin`, a `project_document` without `citation`.
- `_stand_in_problems(server)`: `fixture_provenance.stand_in_problems` over `server.stand_ins` when recorded.

Each helper stays under 20 lines. The counted flaws come from `nuisance_counting.counted_flaws`.

### `evals/nuisance_admission.py`

- `class ToolCall(BaseModel): tool: str; arguments: dict[str, Any]`, and `class BenignCall(ToolCall)` gains `expect: str | None = None` and `before: list[ToolCall] | None = None`.
- `ToolRecord.real_software: RealSoftwareRecord | None = None`.
- `FixCheckRecord.relies_on_relaying_stand_in: bool | None = None`.
- `AdmittedServer.stand_ins: list[StandInRecord] | None = None` and `seeds: list[SeedRecord] | None = None`.
- `admission_problems` adds `problems += record_problems(server)` in its per-server loop.
- The module docstring gains one sentence: the fields defaulting to `None` are those rule v3 added, not yet recorded, which `nuisance_unrecorded` refuses at run.

The file grows by about 15 lines, to about 285.

### `evals/nuisance_counting.py`

```python
def flaw_tools(flaw: FlawRecord) -> frozenset[str]: ...        # patched names of the tools not removed
def flaw_counted_tools(flaw: FlawRecord) -> frozenset[str]: ...  # flaw_tools less the tools whose real_software answers false, under the flaw-level conditions
```

`flaw_counted_tools` keeps its flaw-level conditions and filters `flaw_tools` on `tool.real_software is None or tool.real_software.answers`. `_counts` adds `and check.relies_on_relaying_stand_in is not True`. The docstring names both new conditions.

### `evals/nuisance_benign_call.py` (new) and `evals/nuisance_audit.py`

`benign_call_failure(server: AdmittedServer, mcp_client: MCPClientPort) -> str | None` moves here out of `nuisance_audit.py` (which drops it and its `BenignCall`, `counted_flaws` and `MCPClientPort` imports, `counted_tools` staying for `gate_run`). It keeps its contract (the first failure reason, or `None`) and checks, in order:

1. `listed = {tool.name for tool in await mcp_client.list_tools()}`. A listing that raises fails with `"listing the server's tools failed: <exc>"`. A counted tool, or a tool of a `before` call of a counted tool's benign call, missing from `listed` fails with `"counted tool 'x' is not in the server's tools/list"` (or `"prerequisite tool 'y' of 'x' ..."`).
2. Per counted tool, its benign call (the first in counted-flaw order, now the only one by the load check): each `before` call in order, failing on an exception or `is_error` with `"prerequisite call of 'y' before 'x' ..."`, then the call itself, failing as today, then, when `expect` is set, `"benign call of 'x' returned no text"` on an empty content and `"benign call of 'x' did not return 'expect': <content>"` when the text lacks it.

Helpers below the public function: `benign_calls(server) -> dict[str, BenignCall]`, public because `nuisance_unrecorded` reads the same selection, `_listing_failure(...)`, `_call_failure(client, call, tool)` for one call, `_expectation_failure(call, content)`. `evals/nuisance_vetting.py` imports it from here. `nuisance_audit.py` drops to about 280 lines.

### `evals/nuisance_unrecorded.py` (new)

```python
def unrecorded_fields(servers: Sequence[AdmittedServer]) -> list[str]: ...
def refuse_unrecorded(servers: Sequence[AdmittedServer], title: str) -> None: ...
```

`unrecorded_fields` returns one line per server with a gap, naming each field and how many records lack it, e.g. `PyPI:praisonai: real_software (2 tools), expect (2 benign calls), before (2 benign calls), relies_on_relaying_stand_in (2 flaws), stand_ins`. Its scope: the tools of `counted_tools(server)` (which keeps `None` counted) whose record has no `real_software`; the benign calls `nuisance_benign_call.benign_calls` selects (one per counted tool) with `expect` or `before` unset; the counted flaws whose `fix_check.relies_on_relaying_stand_in` is unset; `stand_ins` and `seeds` unset. Removed tools and flaws that do not count are never read. `refuse_unrecorded` raises `Refused(title, ["fields rule v3 adds are not yet recorded", *gaps])` when the list is not empty. Two callers, the run and the gate.

### `evals/run_nuisance.py`, `evals/nuisance_gate_command.py`, `evals/nuisance_vet_command.py`

- `run_nuisance._run`: once `population` is built, and before `load_settings`, `refuse_unrecorded(population.audited, "nuisance run refused")`, so the refusal needs no LLM key and no Docker. `main` maps `Refused` to exit 3 as today.
- `nuisance_gate_command.gate`: after the unknown-server check and before `_run_gate`, `refuse_unrecorded([s for s in servers if not args.server or s.server_package in args.server], "nuisance gate refused")`, so a `--server` reset is refused only for the servers it audits. Not inside `_run_gate` after `_gate_options`: that calls `load_settings()` (and `_run_gate` calls `read_tree()` first), so the refusal would come after them. `main` maps `Refused` to exit 3. No acceptance server is admitted, so this path is unreachable on the committed files today.
- `nuisance_vet_command.vet`: after `_print_verdicts`, when `unrecorded_fields(servers)` is not empty, it prints one line, `<k> of <n> servers have fields rule v3 adds not yet recorded (run and gate refuse them)`. The vet itself runs and its exit code is unchanged.

### `evals/nuisance_fingerprint.py`

The benign-call part becomes `(call.tool, call.arguments, call.expect, None if call.before is None else [(prior.tool, prior.arguments) for prior in call.before])`. The docstring says the benign calls are covered with their expected text and their prerequisite calls, and that the provenance records (`stand_ins`, `seeds`) are out, their content being covered through the Dockerfile and the backend's served files, which the new tests enforce. Every nuisance fingerprint moves once. No nuisance run, gate run or baseline exists.

### `evals/nuisance_calibrate_command.py`

`_field_mismatches` adds `relies_on_relaying_stand_in` to `skip`, with a comment: a judgment the admission records, which the kit does not observe. `fix_check_mismatches`'s docstring says so. The kit-isolation parity test `tests/unit/test_holdout_kit_isolation.py::test_fix_check_result_mirrors_the_admission_record_fields` asserts `fields(FixCheckResult) == FixCheckRecord.model_fields` and would fail: it compares against the record's fields less `relies_on_relaying_stand_in`, and `evals/holdout_kit/fix_check.py`'s module docstring ("FixCheckResult mirrors nuisance_admission.FixCheckRecord field for field") names the exception.

### `evals/holdout_kit/fix_check.py`

```python
def benign_transcript(flaw: str, service: str, exercise: Exercised) -> str: ...
```

One line per benign exchange, `f"{flaw} {service}: benign {tool} -> {'error' if response.is_error else 'ok'} {response.content!r}"`, the content in full through `repr` so a multi-line answer stays on one line. `check_fix` prints the transcript of each version once that version is exercised, one `print` per version so concurrent calibrations do not interleave within a block. `fix_check_result` and `FixCheckResult` are unchanged, so nothing new is pasted into the admission. `run_nuisance calibrate` prints the transcripts too, since it calls `check_fix`. The module stays under 180 lines.

### `evals/census_draw.py`

```python
class SeededOutsideLayout(BaseModel):
    item: str
    reason: str
    returned_by: list[str]  # tools that return it in a response
    used_by_default_by: list[str]  # tools that use it by default

class CardStandIn(BaseModel):
    stand_in: StandInRecord
    returned_by: list[str]
    used_by_default_by: list[str]
```

`CalibrationCard` gains `seeded_outside_layout: list[SeededOutsideLayout] | None = None` and `stand_ins: list[CardStandIn] | None = None`. `CardCheck` gains `rule_version: int | None = None`, the version of the holdout rule under which the second agent checked the card. `draw_problems` gains `*_stand_in_problems(draw)`, `fixture_provenance.stand_in_problems` over every recorded card stand-in, prefixed with the card's flaw. The file grows to about 280 lines.

### `evals/holdout_card_readiness.py` (new)

```python
CARD_CHECK_RULE_VERSION = 9

def unready_cards(draw: DrawRecord | None, drawn: Sequence[str]) -> list[str]: ...
```

One line per drawn identifier with a gap: no draw record, no card, `seeded_outside_layout` or `stand_ins` unset, no card check, or a card check whose `rule_version` is unset or below `CARD_CHECK_RULE_VERSION`. Pure.

### `evals/run_holdout.py`

`_run` loads the census once, after the `HOLDOUT_TARGETS` emptiness check: `census = _census(args.census)`, then `gaps = unready_cards(census.draw, [target.cve_id for target in holdout_targets.HOLDOUT_TARGETS])`, raising `Refused("holdout run refused", ["drawn targets whose card is not ready under holdout rule v9", *gaps])` when not empty, before `load_settings`. `_audit_drawn_targets` takes the loaded census instead of loading it again, through a frozen `_ReadyHoldoutRun(census, conditions, settings)` dataclass, which keeps it at two arguments (the shape of `run_nuisance._ReadyRun`).

### `evals/cve_targets.py`, `evals/cve_baseline.py`, `evals/holdout_fixtures/cve_2025_66335_doris.py`

- `CVETarget.backend_sources: tuple[Path, ...] = ()`, commented as the modules through which the builder seeds a backend outside the target's images. `cve_targets.py` is already 376 lines, and one field adds one line.
- `fixture_fingerprint`: `if target.backend_sources: parts.append(fingerprint_sources([path.read_text() for path in target.backend_sources]))`, beside the `backend_images` part, and the docstring's "In" list names it. A target with none keeps its fingerprint exactly, which keeps the acceptance targets' fingerprints in place.
- `cve_2025_66335_doris.TARGET` sets `backend_sources=(Path(doris_backend.__file__),)`. The module imports only `DORIS_IMAGE, MYSQL_CLIENT_IMAGE` from `evals.doris_backend` today, so it gains `from evals import doris_backend` (or reads the path another way) and `from pathlib import Path`.

### `evals/nuisance_dossier.py` and `evals/calibration_dossier.py`

- `_FIXTURE_FORMAT` (nuisance) gains a section "Fields rule v3 adds, required for an admission", one bullet each: `ToolRecord.real_software` (the three causes, the evidence, "recorded for every tool of the flaw in the patched version, the same verdict on every flaw that lists the tool", the agreement field name `real_software`); `BenignCall.expect` (a substring of the success text, taken from the seeded content or the software's documented output, never a part of the arguments, a stable fragment for a dynamic output); `BenignCall.before` (prerequisite calls, each must not error, `[]` when none); `FixCheckRecord.relies_on_relaying_stand_in`; `AdmittedServer.stand_ins` and `seeds` (the source order of Stand-ins and Seeding, `[]` when the fixture has none). It says the schema shows them optional with a `null` default because the committed admission predates them, and that an admission leaves none of them `null`. The `benign_calls` bullet says the patched server must also answer the admission's benign calls with their expected text, which `run_nuisance vet` checks, and that `check_fix` prints each benign response.
- `_README` step 5 (nuisance) adds: fill the rule v3 fields, none left `null`.
- `calibration_dossier._README` step 5 lists the two new card fields ("each item seeded outside the layout and each stand-in with the source of its outputs, with the tools that return it or use it by default"), and a short paragraph says they are required on a card despite their `null` default. It stays under 300 lines.

### praisonai: `evals/docker/Dockerfile.praisonai`, `Dockerfile.praisonai-vuln`, `Dockerfile.praisonai-flaw-4.6.34`

- The agents sample. The first `agents.yaml` the documentation names at 4.6.40 is "Example 1: Two Agents Working Together" in `README.md` at commit `a72e156c4d01ef06c64529d302c21381d6485716`, section "Using YAML (No Code)" (section heading l.398, Example 1 heading l.400, fenced block l.404 to l.418, content l.405 to l.417, verified with `gh api repos/MervinPraison/PraisonAI/contents/README.md?ref=a72e156...`). The `src/praisonai/agents.yaml` file of the same tree is a repository file the documentation does not present as a sample. Seeding: "When the documentation names several samples, it seeds the first one." It is written to `/agents.yaml` (the working directory `/`, where `_resolve_cwd_yaml_path` resolves it), whole, by one `RUN printf '%s\n' '<line>' ... > /agents.yaml && chmod a+r /agents.yaml`, one quoted argument per content line, l.413's four spaces included. `printf` with one argument per line keeps blank and whitespace lines exactly, which a heredoc's blank lines would keep in the file but not in `dockerfile_instructions`. No `ADD`: the sample is part of the README, not a file of its own.
- The rules document. No rules sample exists in the 4.6.40 tree and the software generates none at build time, so the next source is a document the project publishes: `docs/features/rules.mdx` of `MervinPraison/PraisonAIDocs`, pinned at commit `bba9a51a6669db7b12004785539c051b9d3e109e` (the last commit touching the file, 2026-10-22, the docs are not versioned with the package). The page names one file of the rules directory, `.praisonai/rules/python.md`, and its first full example is in section "Path-Scoped Rules in Action": the Python block fenced at l.383 gives it at l.386 to l.392, the name on l.386 (`# File on disk: .praisonai/rules/python.md`) and the content on l.387 to l.392, each line behind the `# ` comment marker of the Python block (`---`, `description: Python style`, `globs: ["**/*.py"]`, `activation: glob`, `---`, `Use type hints on every function.`). The content is seeded whole, the comment markers dropped, as `/tmp/.praison/rules/python.md`, the name the page gives it, in the directory the server reads by default (`_resolve_rule_path`, `~/.praison/rules`, with `HOME=/tmp`), which replaces `seed.txt`. The citation records the reading used: the server's own default directory, the page's rules-directory file. The page documents a `.praisonai/rules` directory, and the server reads `.praison/rules`: the server's own default wins, as the rule takes it (a documented default of the software is kept, and the fixture writes nothing else). `rules_show` returns the file's text whole (`rule_path.read_text()`), so the benign response carries `Use type hints on every function.`
- The two pins enter the fingerprinted instructions through two `ARG` lines, `ARG AGENTS_SAMPLE=MervinPraison/PraisonAI@a72e156c4d01ef06c64529d302c21381d6485716:README.md#L405-L417` and `ARG RULES_DOCUMENT=MervinPraison/PraisonAIDocs@bba9a51a6669db7b12004785539c051b9d3e109e:docs/features/rules.mdx#L386-L392`. A build argument is not in the image's environment, so nothing passes it to the server. The header comment says the two seeds are taken whole from these sources, the rules example without its comment markers.
- The vulnerable and 4.6.34 images seed the same two files with the same lines, so the benign call answers the same on every version the fix check plays. The `seed.txt` lines go from all three.

### praisonai: `evals/nuisance_fix_checks/cve_2026_47394_praisonai.py` and `cve_2026_44336_praisonai.py`

- 47394: the docstring's benign paragraph says the benign call reads the seeded README sample at `/agents.yaml`, which 4.6.40 resolves inside the working directory and 4.6.33 opens relative to it. `_BENIGN_FILE_PATH` stays `"agents.yaml"`.
- 44336: `_SEEDED_RULE_NAME = "seed.txt"` becomes `_RULE_NAME = "python.md"`, the docstring names the seeded document (the rules page's `python.md` example). The traversal and the witness are unchanged.

### praisonai: `evals/nuisance_admission.json`

- CVE-2026-44336's benign call becomes `{"tool": "praisonai.rules.show", "arguments": {"rule_name": "python.md"}}`. CVE-2026-47394's stays `{"file_path": "agents.yaml"}`.
- The server gains `seeds`: `{"item": "/agents.yaml", "kind": "published_sample", "citation": "PraisonAI README.md, section Using YAML (No Code), Example 1: Two Agents Working Together, lines 405-417", "pin": "a72e156c4d01ef06c64529d302c21381d6485716"}` and `{"item": "/tmp/.praison/rules/python.md", "kind": "project_document", "citation": "PraisonAIDocs docs/features/rules.mdx, Path-Scoped Rules in Action, .praisonai/rules/python.md, lines 386-392, comment markers dropped, seeded in the server's default rules directory ~/.praison/rules", "pin": "bba9a51a6669db7b12004785539c051b9d3e109e"}`. Every other new field of praisonai stays `null` for the campaign, `expect` included: the verification reads the two responses through the transcript.
- `fix_check` records stay as they are, which `calibrate --cve` confirms.

### Logs and living docs

- `docs/nuisance-log.md`, one entry each: (a) the instrument change: the new fields with their `None` transition and its end, the counted-tool and counted-flaw predicates, the vet's listing, prerequisite and expected-text checks and the gate and run's use of them, the run and gate refusal, the fingerprint now covering expected texts and prerequisite calls (every server's fingerprint moves once, before any run), the dossier and the kit's benign transcript; no admission value changes, so no tool or server leaves; no nuisance run or gate run has taken place; (b) the praisonai repair: what was seeded and why it broke the words limit and left the benign call proving nothing, the two sources with their pins and lines, the benign argument, the vulnerable images aligned, made by the maintainer within the window "until the auditor first audits any nuisance fixture" and within its list ("the seeded files", "the arguments of a benign call"), `calibrate --cve` results and the vet line, with the commit; (c) when the vet finds a counted tool absent from `tools/list`, one line per tool with its cause: repaired in the launch by the maintainer within the repair window of rule v3, or handed to the re-admission campaign.
- `docs/holdout-log.md`: the card fields and `CardCheck.rule_version`, the refusal of `run_holdout run`, the CVE-2025-66335 fingerprint moving for `doris_backend.py` while every other holdout and acceptance fingerprint stays, the backend image digest requirement, and that the card check reading the server's source stays procedural. No rule version opens (the code catches up with v9). No holdout run has taken place.
- `CLAUDE.md` Commands: `run_nuisance vet` (lists the counted tools in `tools/list`, makes each benign call's prerequisite calls, fails on a response without its expected text, prints how many servers have fields rule v3 adds not yet recorded); `run_nuisance run` and `run_nuisance gate` (refuse, exit 3, while a field rule v3 adds is unrecorded for an audited server, listing them); `run_holdout run` (refuses while a drawn target's card lacks a field rule v9 adds or its card check is below version 9); `run_nuisance calibrate` (prints each benign response of the fix check).
- `CONTRIBUTING.md` l.56 paragraph: the vet's new checks, the run refusal, and that the vet is the check of the fix-check clause "every benign call the admission records returns without error".
- `CHANGELOG.md` `[Unreleased]`: `### Changed` for the vet, the refusals and the fingerprint, `### Fixed` for the praisonai benign call reading nothing.

## What stays unchanged

- The product: `src/mcp_auditor/` is untouched, `MCPClient.call_tool` keeps text content only.
- The admission values of the 58 other servers, every `fix_check` record, every counted tool and the figure's population. awslabs-mysql keeps its benign call without `before`.
- The acceptance targets, their fingerprints and the `CVE_TARGETS` list. `_ENVIRONMENT_PATHS` is unchanged.
- The kit's `FixCheckResult`, `fix_check_result` and `patched_benign_errored`, and the holdout `KitTarget` path.
- `rule_commit` of the admission (`93de2d8`), updated with the campaign.
- The words in backend names, responder outputs, stubs and other seeded files (markdownify's `/opt/benign.*`, the `adb-device-stub`, the `mcp-auditor-cve-*` names): the realism plans.
- `docs/nuisance-rule.md`, `docs/holdout-rule.md`, `plans/` and `docs/adr/`.

## Dependencies and blockers outside this plan

- **Blocker before the first nuisance run: names written for the fixture about the audit.** `mcp-auditor` and `cve` in values the fixture passes to the server: the doris launch `--db-host mcp-auditor-cve-doris`, `Dockerfile.mysql`'s `ENV AWS_ENDPOINT_URL=http://mcp-auditor-cve-mysql-moto:5000`, `Dockerfile.neo4j`'s `ENV NEO4J_URI=bolt://mcp-auditor-cve-neo4j:7687`, and the mysql benign call's `db_endpoint: mcp-auditor-cve-mysql`, which every backend named `mcp-auditor-cve-*` shares. They break the v3 limit on words, and the refusal of this plan does not detect them. They go to the responders plan, before the first run.
- awslabs-mysql's `before` (`connect_to_database`), the tool exits (wireshark `quick_capture`, android `monitor-events`) and every value the campaign records: the re-admission campaign, whose brief is rewritten first.
- The `relies_on_relaying_stand_in` of the nuisance twins of CVE-2026-85788 and CVE-2025-53818 waits for their holdout recalibration under v9, or a fix check of their own.
- The cards' new fields and the second agent's check at version 9: the holdout calibration campaign.

## Edge cases

- A server whose last counted tool gets `answers=false`, or whose only counted flaw gets `relies_on_relaying_stand_in=true`: loading refuses it ("no counted tool", its only problem, since `_patched_version_problems` stays silent on a server with no counted flaw). The campaign removes the record in the same commit and logs the exit, so no load path tolerates it.
- One tool on two flaws with `answers=true` on one and `None` on the other: a load problem, so a partially recorded campaign does not load.
- `expect` equal to a part of a `before` call's arguments (mysql's `app` in `database`): a load problem.
- A benign call with `before=[]` and `expect` set: only the checked call is made.
- A counted tool listed but its prerequisite tool missing from `tools/list`: the vet names the prerequisite.
- A response whose text is empty with `expect` set: "returned no text". With `expect` unset: passes, as today.
- `list_tools` raising on the run client: the vet's reason names the listing. A launch failure before it keeps the retry policy of `nuisance_vetting.benign_call`.
- ckan's differing calls on uncounted flaws: loaded, never made, never fingerprinted.
- `run_holdout run` with `census.draw` absent: every drawn target is named. A drawn target in `HOLDOUT_TARGETS` with no card: "no card".
- A card check at `rule_version` 10 passes, at 8 is refused.
- `gate --server PKG`: refused only for the servers selected.
- A counted tool absent from `tools/list` on a real fixture at Step 8: the vet names it and the server is not `ok`. A cause in the launch is repaired by the maintainer and logged (repair window of rule v3), any other cause is logged and handed to the re-admission campaign, and the expected vet count becomes "59 of 59, or fewer with each shortfall logged and its cause named".
- A remote `ADD` with `--checksum=sha256:` on a git source, or a commit SHA on an HTTP source: refused, each source kind has one accepted form.
- A card stand-in whose file is a repository file the target's `fixture_fingerprint` does not hash (a fixture module, read only through the builder's name): refused by the holdout fixture-source test.
- `run_nuisance run` with no admission or an empty one: prints "no server is admitted" and exits 0 before the refusal, as today.

## Test scenarios

Tests first, each red before its code. Given/then files where they abstract something.

### Unit

`tests/unit/test_fixture_provenance.py`:
- a sourced output passes; an invented output without its form source, a copied output with a form source, an invented output with a replacement, and a stand-in with neither output nor capture are each one problem naming the stand-in.

`tests/unit/test_nuisance_admission_records.py` with `tests/unit/support/test_nuisance_admission_records_given.py` (new, since `test_nuisance_admission_given.py` is already 355 lines): a `_MUTATORS` list over `admission_given.an_admission()`, each yielding exactly one problem through `admission_problems`, as `test_nuisance_admission.py` does:
- a removed tool with a `real_software` record; `answers=false` without cause; without evidence; `answers=true` with a cause; one tool with two verdicts across flaws; an empty `expect`; an `expect` inside the arguments; an `expect` inside a `before` call's arguments; two different benign calls for one tool across counted flaws; a published sample without pin; a project document without citation; an invented stand-in output without form source.
- and, outside the mutators: two different calls for one tool where only one flaw counts load clean; a committed-style admission with every new field `None` loads clean.

`tests/unit/support/test_nuisance_admission_given.py`: `an_admission()` becomes fully recorded (`a_tool` with `RealSoftwareRecord(answers=True)` on a tool not removed, `None` on a removed one, `a_flaw_record`'s benign calls with an `expect` absent from their arguments and `before=[]`, `a_passing_fix_check` with `relies_on_relaying_stand_in=False`, `_a_server` with `stand_ins=[]` and `seeds=[]`), so the run and gate command tests that build on it are not refused. The `FakeMCPClient`-based tests that use it list the counted tools.

`tests/unit/test_nuisance_counting.py`:
- a tool whose real software does not answer is not counted, and its flaw still counts; a tool with no record stays counted; a flaw whose positive control rests on a relaying stand-in does not count; `flaw_tools` keeps a tool that does not answer.

`tests/unit/test_nuisance_benign_call.py` with `tests/unit/support/test_nuisance_benign_call_given.py` (the three benign tests of `test_nuisance_audit.py` move here):
- clean listed calls whose text holds the expected text give no failure; a text without the expected text fails naming the tool and the expected text; an empty text with an expected text fails as "returned no text"; a counted tool missing from `tools/list` fails naming it; a prerequisite tool missing from `tools/list` fails naming it; a prerequisite call answering an error fails naming both tools; a server whose checked tool answers only once its prerequisite ran (a stateful fake, given file) passes; an unset `expect` passes on any text that is not an error; an error and a raising call name the tool (moved); a listing that raises names the listing.

`tests/unit/test_nuisance_unrecorded.py` with `tests/unit/support/test_nuisance_unrecorded_given.py`:
- a recorded admission has no gap; each unset field is named for its server with its count; the unset `expect` of a non-counted flaw's benign call is not a gap; a removed tool without `real_software` is not a gap; `refuse_unrecorded` raises `Refused` with the gaps and does nothing without them.

`tests/unit/test_run_nuisance_run.py`: `run` on an admission with an unrecorded field exits 3 and prints the server's gap, before any dep (the given's `a_run_reaching_nothing` pattern). `tests/unit/test_run_nuisance_gate.py`: same for the gate on a one-server gate set. `tests/unit/test_run_nuisance_vet.py`: `vet` prints the not-yet-recorded count line and keeps its exit code.

`tests/unit/test_nuisance_fingerprint.py`:
- the fingerprint moves when a benign call's `expect` changes and when its `before` calls change; it is unchanged by a change to `stand_ins` or `seeds` records.

`tests/unit/test_nuisance_fixture_sources.py` (new, over the committed files, parametrized by admitted server like `test_nuisance_compose.py`):
- no run Dockerfile and no Dockerfile a backend serves holds a local `COPY` or `ADD` (`COPY --from` allowed); every remote `ADD` of an HTTP source carries `--checksum=sha256:<64 hex>` and every remote `ADD` of a git source carries `--checksum=<full 40-hex commit SHA>`; every `SeedRecord.pin` appears in the patched Dockerfile's instructions or in the text of a file the backend serves; every `StandInRecord.file`, and every `StandInRecord.capture` when set, is the patched Dockerfile or one of the backend's served files, and every recorded request key appears in the file. Vacuous today except for praisonai's two pins.
- the checksum rule, on Dockerfile texts built in the test: an HTTP `ADD` with `--checksum=sha256:` and 64 hex digits passes, an HTTP `ADD` without a checksum, with a short digest or with a non-`sha256` algorithm fails; a git `ADD` with `--checksum=` and a full 40-hex commit SHA passes, a git `ADD` without a checksum, with an abbreviated SHA or with a `sha256:` checksum fails.

`tests/unit/test_holdout_fixture_sources.py` (new, over the committed census and `HOLDOUT_TARGETS`, parametrized by drawn target with a card):
- every card stand-in's file, and its capture when set, is among the files the target's `cve_baseline.fixture_fingerprint` covers (the environment modules, the Dockerfiles of the target's images and of its patched twin, the planting host's stand-in captures, the target's `backend_sources`), and every recorded request key appears in its file. Vacuous today, no card records a stand-in.

`tests/unit/test_nuisance_fix_checks.py`:
- `test_each_target_mechanism_and_tools_match_the_admission_flaw` compares the exploit tools with `flaw_tools(record)`; the `_a_record` mismatch tests gain one: a record with `relies_on_relaying_stand_in` set matches a result that cannot carry it.

`tests/unit/test_holdout_kit_isolation.py`:
- the `FixCheckResult` and `FixCheckRecord` field-set parity excludes `relies_on_relaying_stand_in` (see `evals/nuisance_calibrate_command.py` above).

`tests/unit/test_fix_check.py`:
- `benign_transcript` names the flaw, the service, the tool, the error flag and the full content on one line per exchange.

`tests/unit/test_census_draw.py` with its given:
- a card with an invented stand-in output and no form source is a draw problem; a card with the new fields unset validates clean (the committed census test already covers loading).

`tests/unit/test_holdout_card_readiness.py`:
- a ready card and check give no gap; each unset card field, a missing card, a missing check, a check with no version and a check at version 8 is named for its target; no draw names every drawn target; a check at version 10 passes.

`tests/unit/test_run_holdout_run.py` with `tests/unit/support/test_run_holdout_run_given.py`, and `tests/unit/test_run_holdout.py`:
- `run` refuses with exit 3 and prints the gap when `unready_cards` reports one; the givens `a_drawn_run_ending_in` and `a_run_reaching_nothing`, and `test_run_refuses_an_acceptance_target_for_its_tools_filter`, stub `run_holdout.unready_cards` to return no gap, so each keeps testing its own refusal. Both givens set `HOLDOUT_TARGETS` to `(object(),)`, on which `_run`'s `[target.cve_id for target in ...]` raises `AttributeError` before the stub is reached: they set a stand-in carrying a `cve_id` instead.

`tests/unit/test_cve_baseline.py` with its given:
- the fingerprint moves when a backend source's code changes; a target without backend sources has the fingerprint it had before the field existed (the parts list built without the new part, compared through the existing "ignores" pattern).

`tests/unit/test_holdout_targets.py`:
- CVE-2025-66335 declares `doris_backend.py` among its backend sources; every `backend_images` entry of `HOLDOUT_TARGETS` and `CVE_TARGETS` carries an `@sha256:` digest.

`tests/unit/test_nuisance_dossier.py`:
- the fixture format names each new field and says it is required; the calibration kit's README names the two new card fields.

### Integration

No new integration test. No integration test calls `benign_call_failure` (`tests/integration/test_nuisance_doris_backend.py` makes the holdout fixture's benign call through `KitMCPClient`), so the move touches none.

## Verification

```bash
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
uv run python -m evals.run_nuisance calibrate --cve CVE-2026-47394
uv run python -m evals.run_nuisance calibrate --cve CVE-2026-44336
uv run python -m evals.run_nuisance vet
uv run python -m evals.run_nuisance run --report output/nuisance_refusal_check.json
uv run python -m evals.run_holdout calibrate
uv run python -m evals.run_holdout run --report output/holdout_refusal_check.json
```

- `calibrate` rebuilds the three praisonai images from `evals/docker/` itself (`kit_launch.build_images`), and `vet` rebuilds the run image. Both `calibrate --cve` exit 0, each result matching its recorded `fix_check`, and their transcripts show `praisonai.workflow.show -> ok` with the README sample's text (`Research Analyst`) on 4.6.40, and `praisonai.rules.show -> ok` with `Use type hints on every function.` on 4.6.34 and 4.6.40.
- `vet` prints `59 of 59 servers answer their benign calls`, or fewer with each shortfall logged and its cause named, then the not-yet-recorded line for 59 servers. The praisonai line is `ok`. A counted tool absent from `tools/list` on a real fixture does not fail the verification: a cause in the launch is repaired by the maintainer and logged, within the repair window of rule v3, and any other cause is logged and handed to the re-admission campaign, since taking a tool out of the count belongs to the admission agents.
- `run_nuisance run` exits 3 before any LLM call or Docker work, listing the 59 servers' gaps, and leaves no report file. `run_holdout run` exits 3 listing the 30 drawn targets. Neither needs an LLM key.
- `run_holdout calibrate` exits 0 with the 30 targets live on their vulnerable version and dead on their patched one, unchanged.
- The acceptance fingerprint check: in a temporary worktree at `1ecfad0` and in the tree, `uv run python -c` printing `fixture_fingerprint(target, load_places(HOLDOUT_PLACES))` for every target of `CVE_TARGETS` and `HOLDOUT_TARGETS` (the places file both commands load), diffed: no acceptance target moves, and among the holdout targets only CVE-2025-66335 does.
- The praisonai entry of the nuisance log names the commit of the tree these commands ran on.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, written on 2026-11-03 for the implementation-phase fact check. No pass may treat a line here as a reason to skip a verification: the record says what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `a72e156c4d01ef06c64529d302c21381d6485716` is the commit tag `v4.6.40` of `MervinPraison/PraisonAI` points to (verified against the GitHub API, `git/ref/tags/v4.6.40`)
- SETTLED: `MervinPraison/PraisonAI@a72e156c4d01ef06c64529d302c21381d6485716:README.md#L405-L417`, "Example 1: Two Agents Working Together" (heading l.400), fence l.404 to l.418, l.413 a whitespace-only line of four spaces, `Research Analyst` in the block, no earlier `agents.yaml` sample in the README (verified against raw.githubusercontent.com at that commit)
- SETTLED: `MervinPraison/PraisonAIDocs@bba9a51a6669db7b12004785539c051b9d3e109e:docs/features/rules.mdx#L386-L392`, the last commit touching the file (2026-10-22), section "Path-Scoped Rules in Action", Python block fenced at l.383, l.386 `# File on disk: .praisonai/rules/python.md`, l.387 to l.392 the file behind `# ` markers (`---`, `description: Python style`, `globs: ["**/*.py"]`, `activation: glob`, `---`, `Use type hints on every function.`), the first full example of `.praisonai/rules/python.md` on the page, the next being the "Relative Import" block at l.510 (verified with `gh api` raw contents at that commit)
- SETTLED: `rules_show` at 4.6.40 returns `rule_path.read_text()` whole once `_resolve_rule_path` accepts the name, and rejects only names with a separator, a NUL byte or a leading dot, so `python.md` is accepted (verified against `src/praisonai/praisonai/mcp_server/adapters/cli_tools.py` at `a72e156`)
- SETTLED: the docs page documents `.praisonai/rules`, while `_resolve_rule_path` at 4.6.40 reads `~/.praison/rules` (`Path(os.path.expanduser("~/.praison/rules"))`), and `_resolve_cwd_yaml_path` resolves inside `Path.cwd()` (verified against `src/praisonai/praisonai/mcp_server/adapters/cli_tools.py` at `a72e156`)
- SETTLED: `rules.show` on a missing file answers `Rule not found: <name>` and `workflow.show` answers `File not found: <path>`, both as plain text without an error flag (same source)
- SETTLED: the `rules` CLI at 4.6.40 defines `list`, `add`, `clear` and writes no sample (verified against `src/praisonai/praisonai/cli/commands/rules.py` at `a72e156`)
- SETTLED: `ADD --checksum=sha256:<hash>` verifies an HTTP source, and `ADD --checksum=<commit SHA>` a git source, Dockerfile syntax 1.6 or later (verified against docs.docker.com Dockerfile reference)
- SETTLED: in `README.md` at `a72e156`, the "Using YAML (No Code)" heading is l.398 and the "Example 1: Two Agents Working Together" heading l.400 (verified with `gh api` raw contents at that commit)

## Implementation steps

Commands used by every step (from `CLAUDE.md`): the red loop `uv run pytest <test files> -n 0`, the short loop `uv run pytest tests/unit -n auto --maxprocesses 6` (with `--lf` on failures, then the full short loop again), `uv run pyright <changed files>` in the loop. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .` and `uv run pyright` with no file argument, all green. Tests live in `tests/unit/`, their given/then files in `tests/unit/support/`. The living docs and the two log entries of the instrument change are written once, in Step 7, the praisonai repair entry in Step 8.

### Step 1: admission schema, provenance records and load checks

- **Files**: `tests/unit/test_fixture_provenance.py` (new), `tests/unit/test_nuisance_admission_records.py` (new), `tests/unit/support/test_nuisance_admission_records_given.py` (new), `tests/unit/support/test_nuisance_admission_given.py`, `tests/unit/test_holdout_kit_isolation.py`, `tests/unit/test_nuisance_fix_checks.py` (the `_a_record` mismatch test only), `evals/fixture_provenance.py` (new), `evals/nuisance_admission_records.py` (new), `evals/nuisance_admission.py`, `evals/nuisance_calibrate_command.py`, `evals/holdout_kit/fix_check.py` (module docstring only).
- **Do**:
  1. Tests first (see Test). In `test_nuisance_admission_given.py` make `an_admission()` fully recorded: `a_tool` with `real_software=RealSoftwareRecord(answers=True)` when its status is not `removed` (a removed tool carrying one is a load problem), `a_flaw_record`'s benign calls with an `expect` absent from their arguments and `before=[]`, `a_passing_fix_check` with `relies_on_relaying_stand_in=False`, `_a_server` with `stand_ins=[]` and `seeds=[]`.
  2. `evals/fixture_provenance.py` exactly as in Files: `SourceKind`, `IdentifierReplacement`, `StandInOutput`, `StandInRecord`, and pure `stand_in_problems(stand_in) -> list[str]` (problems prefixed with `stand_in.replaces`: invented output without `form_source`, non-invented output with one, invented output with replacements, no outputs and no capture, empty `reason`). Imports neither the admission nor the card.
  3. `evals/nuisance_admission_records.py`: `RealSoftwareRecord`, `SeedRecord`, `record_problems(server)` concatenating `_real_software_problems`, `_verdict_conflicts`, `_expectation_problems`, `_duplicate_benign_calls`, `_seed_problems`, `_stand_in_problems`, each as specified in Files, each prefixed with the server package and under 20 lines. Counted flaws via `nuisance_counting.counted_flaws`. `AdmittedServer` under `TYPE_CHECKING` with `from __future__ import annotations`, as `nuisance_counting.py` does.
  4. `evals/nuisance_admission.py`: `ToolCall(tool, arguments)`, `BenignCall(ToolCall)` with `expect: str | None = None` and `before: list[ToolCall] | None = None`; `ToolRecord.real_software`, `FixCheckRecord.relies_on_relaying_stand_in: bool | None = None`, `AdmittedServer.stand_ins: list[StandInRecord] | None = None`, `seeds: list[SeedRecord] | None = None`; `admission_problems` adds `problems += record_problems(server)` in its per-server loop; one docstring sentence on the `None` fields (rule v3, not yet recorded, refused at run by `nuisance_unrecorded`). Stays under 300 lines.
  5. `evals/nuisance_calibrate_command.py`: `_field_mismatches` adds `relies_on_relaying_stand_in` to `skip`, with a comment (a judgment the admission records, the kit does not observe it); `fix_check_mismatches`'s docstring says so. `evals/holdout_kit/fix_check.py` module docstring names the exception to "mirrors field for field".
- **Test**:
  - `test_fixture_provenance.py`: a sourced output passes; invented output without form source, copied output with form source, invented output with a replacement, stand-in with neither output nor capture: each exactly one problem naming the stand-in.
  - `test_nuisance_admission_records.py`: a `_MUTATORS` list over `admission_given.an_admission()`, each yielding exactly one problem through `admission_problems` (pattern of `test_nuisance_admission.py`): removed tool with `real_software`; `answers=false` without cause; without evidence; `answers=true` with a cause; one tool with two verdicts across flaws (including `None` against a record); empty `expect`; `expect` inside the arguments; `expect` inside a `before` call's arguments; two different benign calls for one tool across counted flaws; published sample without pin; project document without citation; invented stand-in output without form source. Outside the mutators: two different calls for one tool where only one flaw counts load clean; an admission with every new field `None` loads clean.
  - `test_holdout_kit_isolation.py::test_fix_check_result_mirrors_the_admission_record_fields`: compares `fields(FixCheckResult)` to `FixCheckRecord.model_fields` less `relies_on_relaying_stand_in`.
  - `test_nuisance_fix_checks.py`: a record with `relies_on_relaying_stand_in` set matches a result that cannot carry it (no mismatch, no `AttributeError`).
  - The existing `test_nuisance_admission_loads.py` (committed admission) stays green unchanged.
- **Verify**: the closing commands, all green. `test_nuisance_admission.py` and the command tests built on `an_admission()` stay green.

### Step 2: counted-tool and counted-flaw predicates, benign transcript in the kit

- **Files**: `tests/unit/test_nuisance_counting.py`, `tests/unit/test_nuisance_fix_checks.py` (parity test), `tests/unit/test_fix_check.py`, `evals/nuisance_counting.py`, `evals/holdout_kit/fix_check.py`.
- **Do**:
  1. Tests first.
  2. `nuisance_counting.py`: new `flaw_tools(flaw) -> frozenset[str]` (patched names of the tools not removed); `flaw_counted_tools` keeps its flaw-level conditions and filters `flaw_tools` on `tool.real_software is None or tool.real_software.answers`; `_counts` adds `and check.relies_on_relaying_stand_in is not True`. Docstring names both new conditions.
  3. `test_each_target_mechanism_and_tools_match_the_admission_flaw` compares the exploit tools with `flaw_tools(record)`.
  4. `holdout_kit/fix_check.py`: `benign_transcript(flaw: str, service: str, exercise: Exercised) -> str`, one line per benign exchange, `f"{flaw} {service}: benign {tool} -> {'error' if response.is_error else 'ok'} {response.content!r}"`. `check_fix` prints the transcript of each version once that version is exercised, one `print` per version. `FixCheckResult` and `fix_check_result` unchanged. The kit must stay `mcp_auditor`-free (the isolation test guards it). Module stays under 180 lines.
- **Test**:
  - `test_nuisance_counting.py`: a tool whose real software does not answer is not counted and its flaw still counts; a tool with no record stays counted; a flaw whose positive control rests on a relaying stand-in does not count; `flaw_tools` keeps a tool that does not answer.
  - `test_fix_check.py`: `benign_transcript` names the flaw, the service, the tool, the error flag and the full content (a multi-line content stays on one line through `repr`), one line per exchange.
- **Verify**: the closing commands, all green.

### Step 3: the benign call check moves out and grows (listing, prerequisites, expected text), nuisance fingerprint

- **Files**: `tests/unit/test_nuisance_benign_call.py` (new), `tests/unit/support/test_nuisance_benign_call_given.py` (new), `tests/unit/test_nuisance_audit.py`, `tests/unit/test_nuisance_fingerprint.py`, `evals/nuisance_benign_call.py` (new), `evals/nuisance_audit.py`, `evals/nuisance_vetting.py`, `evals/nuisance_fingerprint.py`.
- **Do**:
  1. Tests first: move the three benign tests of `test_nuisance_audit.py` into `test_nuisance_benign_call.py`. The given holds a `FakeMCPClient` setup that lists the counted tools and answers each with a text holding its `expect`, and a stateful fake whose checked tool answers only once its prerequisite ran. Any other `FakeMCPClient`-based test built on `an_admission()` (vet, gate, run tests) must now list the counted tools and answer with the expected text: adjust its given.
  2. `evals/nuisance_benign_call.py`: `benign_call_failure(server, mcp_client) -> str | None` moved from `nuisance_audit.py`, same contract, checking in order: (a) `list_tools()`; a raise gives `"listing the server's tools failed: <exc>"`; a counted tool missing gives `"counted tool 'x' is not in the server's tools/list"`, a prerequisite tool missing gives `"prerequisite tool 'y' of 'x' is not in the server's tools/list"`; (b) per counted tool, each `before` call in order (exception or `is_error` gives `"prerequisite call of 'y' before 'x' ..."`), then the call itself failing as today, then when `expect` is set `"benign call of 'x' returned no text"` on empty content and `"benign call of 'x' did not return '<expect>': <content>"` when absent. Helpers below it: public `benign_calls(server) -> dict[str, BenignCall]` (one per counted tool, first in counted-flaw order), `_listing_failure`, `_call_failure(client, call, tool)`, `_expectation_failure(call, content)`.
  3. `nuisance_audit.py` drops `benign_call_failure` and its now-unused imports (`counted_tools` stays for `gate_run`), about 280 lines. `nuisance_vetting.py` imports from `nuisance_benign_call`; callers keep reaching it through `nuisance_vetting.benign_call`.
  4. `nuisance_fingerprint.py`: the benign-call part becomes `(call.tool, call.arguments, call.expect, None if call.before is None else [(prior.tool, prior.arguments) for prior in call.before])`; docstring says expected texts and prerequisite calls are covered and `stand_ins` / `seeds` are out (covered through the Dockerfile and the backend's served files).
- **Test**:
  - `test_nuisance_benign_call.py`: clean listed calls whose text holds the expected text give `None`; a text without the expected text fails naming the tool and the expected text; empty text with `expect` fails as "returned no text"; a counted tool missing from `tools/list` is named; a prerequisite tool missing is named; a prerequisite call answering an error names both tools; the stateful prerequisite server passes; `before=[]` with `expect` makes only the checked call; unset `expect` passes on any non-error text; an error and a raising call name the tool (moved); a raising listing names the listing.
  - `test_nuisance_fingerprint.py`: moves when a benign call's `expect` changes and when its `before` calls change; unchanged by a change to `stand_ins` or `seeds`.
- **Verify**: the closing commands, all green. `uv run pytest tests/integration -n auto -k "nuisance"` stays green (no integration test calls `benign_call_failure`, this confirms the move broke no import).

### Step 4: run and gate refusal on unrecorded fields, vet count line

- **Files**: `tests/unit/test_nuisance_unrecorded.py` (new), `tests/unit/support/test_nuisance_unrecorded_given.py` (new), `tests/unit/test_run_nuisance_run.py`, `tests/unit/test_run_nuisance_gate.py`, `tests/unit/test_run_nuisance_vet.py` (and their givens if needed), `evals/nuisance_unrecorded.py` (new), `evals/run_nuisance.py`, `evals/nuisance_gate_command.py`, `evals/nuisance_vet_command.py`.
- **Do**:
  1. Tests first.
  2. `evals/nuisance_unrecorded.py`: `unrecorded_fields(servers) -> list[str]`, one line per server with a gap, e.g. `PyPI:praisonai: real_software (2 tools), expect (2 benign calls), before (2 benign calls), relies_on_relaying_stand_in (2 flaws), stand_ins`. Scope: tools of `counted_tools(server)` without `real_software`; the calls `nuisance_benign_call.benign_calls` selects with `expect` or `before` unset; counted flaws with `fix_check.relies_on_relaying_stand_in` unset; `stand_ins` and `seeds` unset. Removed tools and uncounted flaws never read. `refuse_unrecorded(servers, title)` raises `Refused(title, ["fields rule v3 adds are not yet recorded", *gaps])` when not empty.
  3. `run_nuisance._run`: once `population` is built, before `load_settings`, `refuse_unrecorded(population.audited, "nuisance run refused")` (the "no server is admitted" exit 0 path stays before it). `nuisance_gate_command.gate`: after the unknown-server check, before `_run_gate`, `refuse_unrecorded([s for s in servers if not args.server or s.server_package in args.server], "nuisance gate refused")`. Both `main`s already map `Refused` to exit 3: confirm. `nuisance_vet_command.vet`: after `_print_verdicts`, when `unrecorded_fields(servers)` is not empty, print `<k> of <n> servers have fields rule v3 adds not yet recorded (run and gate refuse them)`, exit code unchanged.
- **Test**:
  - `test_nuisance_unrecorded.py`: a recorded admission has no gap; each unset field is named for its server with its count; an unset `expect` on an uncounted flaw's benign call is not a gap; a removed tool without `real_software` is not a gap; `refuse_unrecorded` raises `Refused` with the gaps and does nothing without them.
  - `test_run_nuisance_run.py`: `run` on an admission with an unrecorded field exits 3 and prints the server's gap before any dependency is reached (the given's `a_run_reaching_nothing` pattern).
  - `test_run_nuisance_gate.py`: same on a one-server gate set, and a `--server` selection is refused only for the selected server.
  - `test_run_nuisance_vet.py`: `vet` prints the not-yet-recorded count line and keeps its exit code.
- **Verify**: the closing commands, all green.

### Step 5: calibration card fields, card readiness, holdout run refusal

- **Files**: `tests/unit/test_census_draw.py`, `tests/unit/support/test_census_draw_given.py`, `tests/unit/test_holdout_card_readiness.py` (new), `tests/unit/test_run_holdout_run.py`, `tests/unit/support/test_run_holdout_run_given.py`, `tests/unit/test_run_holdout.py`, `evals/census_draw.py`, `evals/holdout_card_readiness.py` (new), `evals/run_holdout.py`.
- **Do**:
  1. Tests first.
  2. `census_draw.py`: `SeededOutsideLayout(item, reason, returned_by, used_by_default_by)`, `CardStandIn(stand_in: StandInRecord, returned_by, used_by_default_by)`; `CalibrationCard.seeded_outside_layout: list[SeededOutsideLayout] | None = None`, `stand_ins: list[CardStandIn] | None = None`; `CardCheck.rule_version: int | None = None`; `draw_problems` gains `*_stand_in_problems(draw)` (`fixture_provenance.stand_in_problems` over every recorded card stand-in, prefixed with the card's flaw). About 280 lines.
  3. `evals/holdout_card_readiness.py`: `CARD_CHECK_RULE_VERSION = 9`, pure `unready_cards(draw: DrawRecord | None, drawn: Sequence[str]) -> list[str]`, one line per drawn identifier with a gap: no draw record, no card, `seeded_outside_layout` or `stand_ins` unset, no card check, `rule_version` unset or below 9.
  4. `run_holdout._run`: after the `HOLDOUT_TARGETS` emptiness check, `census = _census(args.census)`, `gaps = unready_cards(census.draw, [target.cve_id for target in holdout_targets.HOLDOUT_TARGETS])`, raise `Refused("holdout run refused", ["drawn targets whose card is not ready under holdout rule v9", *gaps])` before `load_settings`. `_audit_drawn_targets` takes the loaded census through a frozen `_ReadyHoldoutRun(census, conditions, settings)` dataclass (shape of `run_nuisance._ReadyRun`), at most two arguments.
- **Test**:
  - `test_census_draw.py`: a card with an invented stand-in output and no form source is a draw problem; a card with the new fields unset validates clean.
  - `test_holdout_card_readiness.py`: ready card and check give no gap; each unset card field, a missing card, a missing check, a check with no version and a check at version 8 is named for its target; no draw names every drawn target; a check at version 10 passes.
  - `test_run_holdout_run.py`: `run` exits 3 and prints the gap when `unready_cards` reports one. The givens `a_drawn_run_ending_in` and `a_run_reaching_nothing`, and `test_run_refuses_an_acceptance_target_for_its_tools_filter` in `test_run_holdout.py`, stub `run_holdout.unready_cards` to return no gap; the givens replace `HOLDOUT_TARGETS = (object(),)` with a stand-in carrying a `cve_id`.
- **Verify**: the closing commands, all green.

### Step 6: fixture fingerprints, backend sources and fixture-source tests

- **Files**: `tests/unit/test_cve_baseline.py`, `tests/unit/support/test_cve_baseline_given.py`, `tests/unit/test_holdout_targets.py`, `tests/unit/test_nuisance_fixture_sources.py` (new), `tests/unit/test_holdout_fixture_sources.py` (new), `evals/cve_targets.py`, `evals/cve_baseline.py`, `evals/holdout_fixtures/cve_2025_66335_doris.py`.
- **Do**:
  1. Before any change, in a temporary worktree at the step's parent commit (`git worktree add <temporary directory> HEAD`, outside the repository), print `fixture_fingerprint(target, load_places(HOLDOUT_PLACES))` for every target of `CVE_TARGETS` and `HOLDOUT_TARGETS` with `uv run python -c`, saved to a temporary file. Remove the worktree afterwards.
  2. Tests first.
  3. `cve_targets.py`: `CVETarget.backend_sources: tuple[Path, ...] = ()`, one-line comment (the modules through which the builder seeds a backend outside the target's images). `cve_baseline.fixture_fingerprint`: `if target.backend_sources: parts.append(fingerprint_sources([path.read_text() for path in target.backend_sources]))` beside the `backend_images` part, docstring "In" list names it. `cve_2025_66335_doris.TARGET` sets `backend_sources=(Path(doris_backend.__file__),)` (add `from evals import doris_backend`, `from pathlib import Path`).
  4. `test_nuisance_fixture_sources.py` over the committed files, parametrized by admitted server like `test_nuisance_compose.py`: no run Dockerfile and no Dockerfile a backend serves holds a local `COPY` or `ADD` (`COPY --from` allowed); every remote `ADD` of an HTTP source carries `--checksum=sha256:<64 hex>` and every remote `ADD` of a git source `--checksum=<full 40-hex commit SHA>`, anything else failing; every `SeedRecord.pin` appears in the patched Dockerfile's instructions or in a file the backend serves; every `StandInRecord.file`, and every `StandInRecord.capture` when set, is the patched Dockerfile or a backend-served file, and every recorded `request` key appears in the file. Reuse the fingerprint's own file discovery (`nuisance_fingerprint` and the backend's served files) rather than re-deriving paths. Vacuous today on seeds and stand-ins (praisonai's pins land in Step 8).
  5. `test_holdout_fixture_sources.py` over the committed census and `HOLDOUT_TARGETS`, parametrized by drawn target with a card: every card stand-in's file, and its capture when set, is among the files the target's `fixture_fingerprint` covers (holdout rule v9, Run conditions), and every recorded request key appears in its file. Reuse the fingerprint's own paths (`_ENVIRONMENT_PATHS`, `image_dockerfile` over the target's images and patched twin, the planting host's captures, `backend_sources`) rather than re-deriving them. Vacuous today.
- **Test**:
  - `test_cve_baseline.py`: the fingerprint moves when a backend source's code changes; a target without backend sources has the fingerprint it had before the field existed (existing "ignores" pattern).
  - `test_holdout_targets.py`: CVE-2025-66335 declares `doris_backend.py` among its backend sources; every `backend_images` entry of `HOLDOUT_TARGETS` and `CVE_TARGETS` carries an `@sha256:` digest.
  - `test_nuisance_fixture_sources.py` as above, with the checksum cases of Test scenarios (HTTP: `sha256:` and 64 hex passes, none, short or another algorithm fails; git: a full 40-hex commit SHA passes, none, abbreviated or `sha256:` fails).
  - `test_holdout_fixture_sources.py` as above.
- **Verify**: the closing commands, all green. Re-run the fingerprint print of Do 1 on the tree and diff: no acceptance target moves, and among the holdout targets only CVE-2025-66335 does. The diff result goes into the holdout log entry of Step 7.

### Step 7: dossiers, logs and living docs of the instrument change

- **Files**: `tests/unit/test_nuisance_dossier.py`, `evals/nuisance_dossier.py`, `evals/calibration_dossier.py`, `docs/nuisance-log.md`, `docs/holdout-log.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do**:
  1. Tests first.
  2. `nuisance_dossier._FIXTURE_FORMAT`: a section "Fields rule v3 adds, required for an admission", one bullet each for `ToolRecord.real_software` (three causes, the evidence, the same verdict on every flaw listing the tool, the agreement field name `real_software`), `BenignCall.expect` (a substring of the success text from the seeded content or the documented output, never part of the arguments, a stable fragment for a dynamic output), `BenignCall.before` (each must not error, `[]` when none), `FixCheckRecord.relies_on_relaying_stand_in`, `AdmittedServer.stand_ins` and `seeds` (source order of Stand-ins and Seeding, `[]` when none). It says the schema shows them optional with a `null` default because the committed admission predates them, and that an admission leaves none `null`. The `benign_calls` bullet adds that the patched server must answer with the expected text, checked by `run_nuisance vet`, and that `check_fix` prints each benign response. `_README` step 5 adds "fill the rule v3 fields, none left `null`". `calibration_dossier._README` step 5 lists the two card fields and a short paragraph says they are required despite their `null` default. Both files stay under 300 lines.
  3. `docs/nuisance-log.md`, entry (a) dated 2026-11-03 as specified in Files, Logs and living docs (the new fields and their `None` transition and its end, the predicates, the vet checks, the run and gate refusal, the fingerprint moving once for every server before any run, the dossier and the kit transcript, no admission value changes, no run or gate has taken place). `docs/holdout-log.md` entry: the card fields and `CardCheck.rule_version`, the `run_holdout run` refusal, CVE-2025-66335's fingerprint moving for `doris_backend.py` while every other holdout and acceptance fingerprint stays (Step 6's diff), the backend image digest requirement, the card check reading the source staying procedural, no rule version opens, no holdout run has taken place. Follow the register of the existing entries.
  4. `CLAUDE.md` Commands: amend the `run_nuisance vet`, `run`, `gate`, `calibrate` and `run_holdout run` lines as in Files. `CONTRIBUTING.md` paragraph at l.56: the vet's new checks, the run refusal, the vet as the check of "every benign call the admission records returns without error". `CHANGELOG.md` `[Unreleased]` `### Changed`: vet, refusals, fingerprint.
- **Test**: `test_nuisance_dossier.py`: the fixture format names each new field and says it is required; the calibration kit's README names the two card fields.
- **Verify**: the closing commands, all green. Then `uv run python -m evals.run_nuisance run --report output/nuisance_refusal_check.json` exits 3 before any LLM call or Docker work, listing the 59 servers' gaps, and leaves no report file; `uv run python -m evals.run_holdout run --report output/holdout_refusal_check.json` exits 3 listing the 30 drawn targets. Neither needs an LLM key.

### Step 8: praisonai repair (seeds, benign argument, fix checks), its log entry

- **Files**: `evals/docker/Dockerfile.praisonai`, `evals/docker/Dockerfile.praisonai-vuln`, `evals/docker/Dockerfile.praisonai-flaw-4.6.34`, `evals/nuisance_fix_checks/cve_2026_47394_praisonai.py`, `evals/nuisance_fix_checks/cve_2026_44336_praisonai.py`, `evals/nuisance_admission.json`, `docs/nuisance-log.md`, `CHANGELOG.md`.
- **Do**:
  1. Fetch both sources at their pins (`gh api repos/MervinPraison/PraisonAI/contents/README.md?ref=a72e156c4d01ef06c64529d302c21381d6485716`, and `docs/features/rules.mdx` of `MervinPraison/PraisonAIDocs` at `bba9a51a6669db7b12004785539c051b9d3e109e`) and take README l.405 to l.417 and rules.mdx l.386 to l.392 verbatim, the rules lines without their `# ` comment markers.
  2. In all three Dockerfiles: drop the `seed.txt` lines; add `ARG AGENTS_SAMPLE=MervinPraison/PraisonAI@a72e156c4d01ef06c64529d302c21381d6485716:README.md#L405-L417` and `ARG RULES_DOCUMENT=MervinPraison/PraisonAIDocs@bba9a51a6669db7b12004785539c051b9d3e109e:docs/features/rules.mdx#L386-L392`; seed `/agents.yaml` by one `RUN printf '%s\n' '<line>' ... > /agents.yaml && chmod a+r /agents.yaml`, one quoted argument per content line (l.413's four spaces kept), and `/tmp/.praison/rules/python.md` the same way (the six lines of l.387 to l.392 without their `# ` markers), readable by the unprivileged user; a header comment saying the two seeds are taken whole from these sources, the rules example without its comment markers. Same lines in the three images.
  3. Fix checks: 47394's docstring benign paragraph names the seeded README sample at `/agents.yaml`; 44336's `_SEEDED_RULE_NAME = "seed.txt"` becomes `_RULE_NAME = "python.md"`, docstring names the seeded document (the rules page's `python.md` example), traversal and witness unchanged.
  4. `nuisance_admission.json`: CVE-2026-44336's benign call arguments become `{"rule_name": "python.md"}`; the server gains the two `seeds` records exactly as in Files. Every other new praisonai field stays `null`, `fix_check` records unchanged.
  5. Run the Verify commands, then write the nuisance log entry (b) as in Files (what was seeded and why it broke the words limit and proved nothing, the two sources with pins and lines, the benign argument, the vulnerable images aligned, the maintainer's repair window and list, the `calibrate --cve` results and the vet line, and the entry (c) lines of any counted tool the vet finds absent from `tools/list`), naming "the tree of commit `<HEAD at run time>`" as the existing entries do. `CHANGELOG.md` `[Unreleased]` `### Fixed`: the praisonai benign calls reading nothing.
- **Test**: no new test; `test_nuisance_fixture_sources.py` now checks the two pins against the patched Dockerfile, `test_nuisance_fix_checks.py` and `test_nuisance_admission_loads.py` stay green.
- **Verify**: the closing commands, all green. Then (Docker):
  - `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-47394` and `--cve CVE-2026-44336` both exit 0, each result matching its recorded `fix_check`, the transcripts showing `praisonai.workflow.show -> ok` with `Research Analyst` on 4.6.40 and `praisonai.rules.show -> ok` with `Use type hints on every function.` on 4.6.34 and 4.6.40.
  - `uv run python -m evals.run_nuisance vet` prints `59 of 59 servers answer their benign calls`, or fewer with each shortfall logged and its cause named, praisonai `ok`, then the not-yet-recorded line for 59 servers. A counted tool absent from `tools/list` on a real fixture does not fail this step: a cause in the launch is repaired by the maintainer and logged (repair window of rule v3), any other cause is logged and handed to the re-admission campaign (taking a tool out of the count belongs to the admission agents). A repair in the launch reruns the vet.
  - `uv run python -m evals.run_holdout calibrate` exits 0, the 30 targets live on vulnerable and dead on patched, unchanged.
