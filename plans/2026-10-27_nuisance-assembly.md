# Nuisance suite assembly: nine admitted servers, their fix-check fixtures, and the calibration path

## Context

The nuisance suite tooling is complete (walk, admission schema, counting predicate, run, acceptance gate, backend registry), but no server is admitted: `evals/nuisance_admission.json` does not exist, `FIX_CHECK_TARGETS` in `evals/nuisance_fixtures.py` is the empty tuple, and there is no repo entry point that re-runs a nuisance fix check. The admission session produced two independent records per server and a maintainer settlement for each. This plan turns those settlements into the committed artifacts the suite needs: the admission file, the patched images the run audits, the committed fix-check fixtures (vulnerable Dockerfile plus exploits) that reproduce each counted flaw, a calibration command that re-runs them, and the test that loads the committed admission.

Scope is nine servers: kanban, aws-api (nb02), arcadedb (nb04), token-optimizer (nb05), claude-in-mobile (nb07), flyto (nb08), ckan (nb03), contextforge (nb06) and doris. (That is kanban, the seven admitted batch servers, the ten of the batch minus the three dropped, and doris.) doris is a holdout twin (its holdout target is CVE-2025-66335, calibrated green); it is assembled like the other backend twins, from the working holdout doris backend, not from a blind re-derivation, and its flaw analysis is taken from its record (see its per-server entry). kanban is built first as the worked pilot: it establishes the fix-check fixture convention, the calibration command and the admission-loading test, so the other eight reuse an established shape.

Three servers are dropped and only logged, never admitted: create-mcp-server-stdio (the injection is unreachable, `z.number()` rejects the payload before the handler), fetch (the declared function of `fetch` is the effect, `declared_function_is_effect=true`), and stata (a proprietary Stata binary the census forbids stubbing).

## Approach

The work splits by artifact kind, following the project's convention that eval data and fixtures are authored directly and committed by hand while repo logic goes through the implementation flow.

Data and fixtures, authored directly: `evals/nuisance_admission.json` (the admitted servers with their settlements), the patched `Dockerfile.<service>` plus its `compose.yml` service for each admitted server, and the vulnerable Dockerfiles plus any stub scripts the fix check builds. These are the equivalent of the holdout draw records and Dockerfiles.

Repo code, through the implementation flow: `FIX_CHECK_TARGETS` and its exploit and benign callables in `evals/nuisance_fixtures.py`, the calibration command that runs them, the unit test that loads `ADMISSION_PATH`, the finalisation of `evals/ckan_backend.py`, and any new backend provisioner a server needs. The counting, images, admission schema and run already exist and do not change except where this plan says so.

The two kinds interleave per server: the admission JSON's `fix_check` block for each counted flaw must match what the committed fix-check fixture reproduces, and the run audits the patched image the fix check confirms clean. So each server is assembled as a unit (JSON entry plus images plus fix-check fixture plus calibration), kanban first.

Every admitted server here is a holdout twin, so its launch, its environment builder and (for backend servers) its backend already exist in `evals/cve_environments.py` and `evals/holdout_fixtures/`. The fix-check fixture reuses a kit builder, which for the command-injection and SSRF servers already exists in `evals/holdout_kit/kit_launch.py` (`command_injection_env`, `ssrf_env`); the arcadedb and contextforge builders exist only on the `cve_environments` side and are ported into the kit as named sub-tasks (see the `FIX_CHECK_TARGETS` section). doris's fix-check backend builder already exists in the kit (`evals/holdout_kit/kit_backends.py`'s `doris_backend_env`, standing the doris cluster) and is reused, not ported. doris additionally runs with the `doris` backend, which is already registered in `nuisance_backends.BACKENDS`. The patched Dockerfile reuses the twin's build recipe at the nuisance patched version. The exact exploit and benign callables for each counted flaw are transcribed from the validated admission fix-check fixtures (the implementer is given their source at implement time; the committed code carries no path to it). The exploit mechanics are stated per server below so the plan is self-contained.

## The repo mechanism

### `evals/nuisance_fixtures.py`: FIX_CHECK_TARGETS and its callables

Populate `FIX_CHECK_TARGETS` with one `FixCheckTarget` per counted flaw of each admitted server, plus the exploit and benign callables they reference. Nine servers' targets with all their callables inlined into `nuisance_fixtures.py` would push it well past the 300-line file limit (CLAUDE.md: "files should rarely exceed 300 lines. When they do, split."). Follow the holdout side's layout, which splits exactly this material: author each server's `FixCheckTarget`(s) and their exploit and benign callables in a per-flaw module under a fixtures package mirroring `evals/holdout_fixtures/` (each holdout fixture file is ~70-155 lines), and keep `nuisance_fixtures.py` the thin aggregator that imports them into `FIX_CHECK_TARGETS`, as `evals/holdout_targets.py` aggregates `evals/holdout_fixtures/`. Every such module keeps the kit's import discipline: it imports only from inside the kit's import closure, that is `evals.holdout_kit` and the clean `evals.cve_*` modules the kit rests on (`cve_places` for `Place`, `cve_planting` for `PlantingHost`, `cve_grammar` for `MechanismClass`), never from `mcp_auditor` nor from the `mcp_auditor`-importing `evals.cve_environments`. `FixCheckTarget`, `FixCheckExploit` and `check_fix` come from `evals.holdout_kit.fix_check`.

A `FixCheckTarget` carries: `flaw` (the CVE id), `mechanism` (the `MechanismClass | None`), `aim` (the `re.Pattern` the proof grammar matches), `witness` (the `Place` the nonce is planted at), `planting_host` (the server's `PlantingHost`), `builder` (a `KitBuilder`), `exploits` (a tuple of `FixCheckExploit`, either surfacing counts), `benign_calls` (a tuple of `FixCheckExploit`, one per counted tool, in the patched version), `vulnerable_service`, `patched_service` and `server_patched_service` (None when the server's patched version equals the flaw's).

The `builder` is a `KitBuilder` (`Callable[[str, PlantingSpec, LaunchShape], AbstractContextManager[kit_launch.Launch]]`), so it must return the kit's own `Launch`. Only two builders a server here needs already exist in the kit (`kit_launch.command_injection_env`, `kit_launch.ssrf_env`). The arcadedb and contextforge builders live in `evals/cve_environments.py` as `arcadedb_mcp_env` and `contextforge_ssrf_env`, which import `mcp_auditor` and return `cve_environments.Launch`: they cannot be imported into the kit. Porting trimmed, `mcp_auditor`-free copies of them into `kit_launch.py` (as the existing four builders already are trimmed copies of their `cve_environments` twins) is a named sub-task of arcadedb and contextforge, per "What stays unchanged". The kit isolation test (`tests/unit/test_holdout_kit_isolation.py`) guards the `mcp_auditor`-free closure.

`check_fix` does **not** build images: it calls `target.builder(image_tag(service), ...)` and assumes the kit image `mcp-auditor-kit-<service>:local` already exists. Building each `evals/docker/Dockerfile.<service>` as that tag is `kit_launch.build_images`, which the `calibrate` command runs before `check_fix` (as the run and gate rebuild through `holdout_run.rebuild_images`). `check_fix` then reproduces the flaw on each version.

The kanban pilot fixes the convention. Its two counted flaws (CVE-2025-53818 on `add_comment`, CVE-2026-0756 on `create_issue`) both inject through a shell `exec` of `gh`. Witness: a `/flag` file read by `cat /flag`, aim `cat\s+/flag`, mechanism `command_execution`, builder `command_injection_env`. Exploit for 53818: `add_comment` with `issue_number = "; cat /flag #"`, the nonce lands in the returned issue data. Exploit for 0756: `create_issue` with `title = 'x"; cat /flag >&2; false #'`, the nonce lands on the rejection message's stderr. Benign calls (one set, working on both the v0.3.0 repo-arg API and the v0.4.x path-arg API): `list_issues`, `create_issue`, `update_issue`, `add_comment` against `octocat/hello-world` at `/work/repo`. Services `kanban-vuln` (v0.3.0) and `kanban` (v0.4.1); `server_patched_service` is None (the server's patched version is the flaws').

A naming note the convention pins: the patched service is the server's run service (`<slug>`), built from `Dockerfile.<slug>`; the vulnerable service is `<slug>-vuln`, built from `Dockerfile.<slug>-vuln`, a fix-check-only fixture. When the server's patched version differs from a flaw's, a third service `<slug>-flaw-<version>` builds that flaw's own patched version for the `server_patched_service` arm.

### The calibration command

Add a `calibrate` subcommand to `evals/run_nuisance.py`, the nuisance twin of `run_holdout calibrate`. It builds the kit images each `FIX_CHECK_TARGET` names (through `kit_launch.build_images`), runs `check_fix` on each (no LLM, Docker only), and prints the resulting `FixCheckResult`. It compares each result to the `fix_check` block the admission records for that flaw and exits non-zero on any mismatch or on a flaw whose witness does not surface on the vulnerable version or surfaces on a patched one, so a drifted fixture is caught. One caveat the comparison has to respect: `fix_check.fix_check_result` hardcodes `source="fix_check"`, so a flaw whose recorded `fix_check.source` is `holdout_calibration` (the aws-api path, decision 5) can never match a re-derived result field for field. For such a flaw the comparison must exclude the `source` field (the record's provenance is the recopied holdout calibration, not a fresh fix-check run), or `calibrate` must skip `holdout_calibration`-sourced flaws outright. With no admission file or an empty `FIX_CHECK_TARGETS` it prints that nothing is drawn and exits 0, mirroring `run` and `gate`. It takes `--cve ID` to calibrate one flaw and `--concurrency` like the other commands.

This is the "real Docker calibration" the assembly needs: it confirms, in the repo, that the committed fixtures reproduce the recorded `fix_check` values before the admission is trusted. It is a maintainer tool, not part of `run`; `run` reads the recorded `fix_check` from the admission JSON through the counting predicate and never re-runs the fix check.

### The admission-loading test

Add a unit test mirroring `tests/unit/test_holdout_census.py`'s `CENSUS_PATH` test: when `ADMISSION_PATH` exists, `load_admission(ADMISSION_PATH, load_census(CENSUS_PATH))` succeeds (raising joined problems otherwise). Today no test loads the committed admission, so "run the unit tests" does not validate it. The test skips cleanly when the file is absent (the pre-admission state), so it is committed with the mechanism and starts validating once the admission file lands.

### `evals/ckan_backend.py` finalisation

The CKAN responder backend and its `Dockerfile.ckan-responder` already exist (untracked) and are wired into `nuisance_backends.BACKENDS` under the `ckan` key with a parity test. Re-read the module against the coding standards, confirm the registry entry's `image`/`network` match `backend_problems`' expectation, and commit it with the rest. Calibrate it under Docker (stand the responder, confirm the patched ckan server's benign call answers without error) before trusting its admission.

### Backend provisioners for the SSRF twins

flyto and contextforge are SSRF twins. The registry has `doris` and `ckan`. **flyto needs no run backend** (decision 1 resolved): its counted benign calls (`string.uppercase`, a seeded recipe) are backend-free, so `backend_need` is none and no provisioner is registered for it; the SSRF sentinel is only a fix-check concern, stood by the kit `ssrf_env` builder. **contextforge needs a registered provisioner**: its benign call reaches a local REST responder, so this plan adds a `contextforge` provisioner (a mirror of `ckan_provisioner`) standing the `contextforge_ssrf_env` sentinel. doris reuses the already-registered `doris` provisioner.

## Per-server data

Each row is the admitted server's shape after the maintainer's settlement. "Counted tools" are the tools the run audits for a false alarm; "dropped flaws" are recorded in the admission but excluded by the counting predicate (class outside the grammar, declared-function-is-effect, or no counted tool). `server_patched_surfaces` is null when the flaw's patched version equals the server's, else the fix check's result on the server's patched version.

### kanban (pilot)

Service `kanban`, patched `0.4.1` source `fix_commit` (npm stops at 0.3.0; the fix is the v0.4.1 git tag, v0.4.0 still interpolates), `runs_over_stdio` true, `runs_under_docker` true, host unprivileged `/tmp` no network, `backend_need` none. Counted flaws: CVE-2025-53818 (`command_execution`, `add_comment`) and CVE-2026-0756 (`command_execution`, `create_issue`), both `server_patched_surfaces` null. Records A and B agree on every field; the one settlement is `backend_need` none (both records marked the `gh` dependency as needing a backend, but the `gh` stub is baked into the image, so the single container provides it). Benign calls per the fix-check fixture above.

### aws-api (nb02)

Service `aws-api-mcp`, patched `1.3.9` source advisory, stdio, docker, host unprivileged `/` no network, `backend_need` none. Counted flaw: CVE-2026-4270 (`read_outside_scope`), counted tool `call_aws` only, `server_patched_surfaces` null. Benign: `call_aws` with `cli_command` `aws ec2 describe-instances help` (offline help, no AWS backend). Settlements: tools of 4270 are `[call_aws]` (record A also listed `suggest_aws_commands`, which does not reach the flaw, removed); `backend_need` none (record B); CVE-2026-16584 dropped (class null, CWE-455 policy bypass outside the grammar; record A's `internal_fetch` on it was an exploit artifact). The fix check uses `source` holdout_calibration (decision 5 resolved): the counted flaw CVE-2026-4270 is the aws holdout twin's own calibrated flaw at the same version (1.3.9), so the `fix_check` block recopies the holdout calibration's witness and booleans and aws carries no committed vulnerable fixture and no `FixCheckTarget` with exploits. `calibrate`'s comparison excludes the `source` field for this flaw (the record's provenance is the recopied holdout calibration, not a fresh run). aws is the one server that takes this path; every other server uses `source` fix_check with a committed vulnerable fixture authored on the holdout builder.

### arcadedb (nb04)

Service `arcadedb`, patched `26.7.1` source advisory (not 26.8.1: 26.8.1 is the max across the out-of-grammar flaws and `_patched_version_problems` would reject it, since the counted flaw's patched version is 26.7.1), stdio, docker, host unprivileged `/home/arcadedb` no network, `backend_need` none (the database is baked into the single image). Counted flaw: CVE-2026-65831 (`read_outside_scope`), counted tool `execute_command` (and `query` if it routes the polyglot js path on 26.7.1, see open decision), `server_patched_surfaces` null (patched equals the flaw's). Launch option: the `config/mcp-config.json` that enables the MCP server and allows `execute_command` so the polyglot js path is reachable (the GraalVM class-loader reflection pivot reads a file outside the database scope). Benign: `query` with a trivial `SELECT 1 AS ok`, plus `execute_command` (a benign call for it is missing from both records and must be added, since it is a counted tool and `_benign_call_problems` requires one). Dropped: CVE-2026-67357, 68578, 75845 (all class null, outside the grammar; 68578 and 75845 are non-root-principal bypasses whose effect is a write or an admin setting with no planted-nonce disclosure channel, `declared_function_is_effect` true per record B). Re-validate the fix check on the 26.7.1 image.

### token-optimizer (nb05)

Service `token-optimizer`, patched `5.1.1` source advisory (decision 4 resolved: the diligence pass verified 5.1.1 is the first fix-carrying release on npm, 5.1.0 being a git tag only; 5.1.1 is the deployable registry release and is taken as the counted flaw's patched version, so `server_patched_surfaces` is null), stdio, docker, host unprivileged `/tmp` no network, `backend_need` none. Counted flaw: CVE-2026-55157 (`command_execution`, `smart_user`), `server_patched_surfaces` null. Benign: `smart_user` with `operation` `get-user-info`, `username` `root`, `useCache` false. Dropped: CVE-2026-55156 (`read_outside_scope`, a dashboard HTTP path with no `tools/call`, record A's tools empty). The exploit injects a shell argument into `smart_user`; the fix (v5.1.0) moves `smart_user` to argv-mode `execFileSafe` plus `assertSafeArg`.

### claude-in-mobile (nb07)

Service `claude-in-mobile`, patched `3.10.3` source advisory, stdio, docker, host unprivileged `/` no network, `backend_need` none (the `adb` stub is baked in). Counted flaw: CVE-2026-81562 (`command_execution`), counted tool `system` (the meta-tool that is the only one `tools/list` returns; record A's `app` and the `system_shell` alias are wrong), action `shell`, `server_patched_surfaces` null, `declared_function_is_effect` false (the declared function of `system` is a catch-all, not command execution). Benign: `system` with action `shell` running `getprop ro.build.version.sdk`. The whole flaw record is settled to record B (the tool, the benign call, the action). The exploit runs a command through `system`'s `shell` action; the witness is the command's output.

### flyto (nb08)

Service `flyto`, patched `2.28.0` source advisory, stdio, docker, host unprivileged `/`, `backend_need` none (decision 1 resolved: the counted benign calls are backend-free, so no run backend is provisioned; the SSRF sentinel is a fix-check-only concern stood by the kit `ssrf_env` builder, and the server host needs no network at run time). Counted tools: `execute_module` (reached by CVE-2026-55787, 67424, 67428, 73530, all `internal_fetch`) and `run_recipe` (reached by CVE-2026-67427, `read_outside_scope`). `server_patched_surfaces`: false on 55787 (2.26.3), 67424/67427/67428 (2.26.7) computed on 2.28.0; null on 73530 (2.28.0, the server's version). Benign: `execute_module` with `module_id` `string.uppercase` (backend-free), `run_recipe` with a seeded `nb08benign` recipe (backend-free). Dropped: CVE-2026-55786 (`command_execution`, `declared_function_is_effect` true), 67425 (class null), 67429 (class null / dfie true). The `internal_fetch` exploits call `execute_module` with an `http.get`-style module whose URL points at the planted sentinel; the witness surfaces in the fetched body.

### ckan (nb03)

Service `ckan`, patched `0.4.112` source advisory, stdio, docker, host unprivileged `/` network true, `backend_need` fixture (the CKAN responder backend, `ckan` provisioner). Counted flaws: CVE-2026-73844 (`internal_fetch`, `ckan_package_search`) and CVE-2026-73845 (`internal_fetch`, `ckan_get_mqa_quality` and `ckan_get_mqa_quality_details`), both `server_patched_surfaces` null (patched 0.4.112 equals the server's). Benign: `ckan_package_search` reaching the responder; `ckan_get_mqa_quality` on `dati.gov.it` (record B; record A targeted the wrong tool and a rejected domain). Dropped: CVE-2026-33060, 53509, 61612 (`internal_fetch` but `declared_function_is_effect` true, their patched versions 0.4.85/0.4.106/0.4.108 predate 0.4.112), 73846 (class null and its positive control failed). Build note from the responder: only `ckan_package_search` mechanically needs the responder (the MQA tools swallow their errors); no `CKAN_ALLOWED_DOMAINS` (enabling it blocks the benign call); TEST-NET-3 subnet plus `--add-host`. Calibrate the responder and the two counted tools under Docker.

### contextforge (nb06)

Service `contextforge`, patched `1.0.7` source advisory, `runs_over_stdio` true (record A rebuilt it as an HTTP gateway and concluded false; the holdout twin exposes it over stdio via `contextforge_ssrf_env`, so stdio is the settled value), docker, host unprivileged `/app` network true, `backend_need` fixture. Counted flaw: CVE-2026-18905 (`internal_fetch`), `server_patched_surfaces` null. The counted tool, its benign call and the exploit are taken from the holdout twin's fixture (record A's tools and benign are empty because it ran the server as an HTTP service, not over stdio). The benign call registers a REST tool pointing at a local responder so it answers without error, which needs a registered provisioner (a mirror of `ckan_provisioner`, standing the `contextforge_ssrf_env` sentinel). Reuse the holdout builder and sentinel; the machinery exists on the holdout side.

### doris

Service `doris`, patched `0.6.1` source advisory, stdio, docker, host unprivileged `/` (network per the `doris` provisioner's bridge), `backend_need` fixture (the `doris` provisioner, already registered in `BACKENDS`). Counted flaw: CVE-2025-66336 (`read_outside_scope`, `declared_function_is_effect` false), counted tool `get_table_comment` (the read-outside-scope carrier the holdout-informed analysis names; whether the other read tools the record lists for the flaw, `get_db_table_list`, `get_table_schema`, `get_table_column_comments`, `get_table_indexes`, `get_db_list`, join it is a tool settlement on the 0.6.1 source, like arcadedb's `query`), `server_patched_surfaces` null (patched 0.6.1 equals the server's). Benign: a read tool reaching the provisioned cluster (`get_table_comment` on a seeded table, plus `get_db_table_list`). Dropped: CVE-2025-66335 (the reaching flaw, `command_execution`, `declared_function_is_effect` true) and CVE-2025-58337 (class null / declared-function-is-effect).

doris is a holdout twin (its holdout target is CVE-2025-66335, calibrated green), so its backend and launch come from the holdout `doris_db_env` and the registered `doris` provisioner, not a blind re-derivation. The counted flaw here (66336) is not the holdout's calibrated flaw (66335), so it is not a holdout_calibration recopy: its fix check is `source` fix_check, authored on that working backend. The blind admission run mis-wired the cluster (record B's positive control did not surface the witness on the vulnerable version, record A found no fix on the patched version and read every flaw as `internal_fetch`), the twin-method artifact the holdout-twins decision warns of, so the blind fix-check is not trusted. The flaw analysis is taken from the record that matches the holdout-informed expectation (66336 `read_outside_scope`, the read tools, `declared_function_is_effect` false); the divergent reading (all flaws `internal_fetch` and never fixed) is the blind re-derivation error, noted not followed. The fix-check builder is the kit's doris backend env, `evals/holdout_kit/kit_backends.py`'s `doris_backend_env`, which already exists in the kit and is reused, not ported (unlike `arcadedb_env` and `contextforge_env`, which are ported from `cve_environments`).

## Assembly order

1. Mechanism and kanban pilot: the `FixCheckTarget` convention, the `calibrate` command, the `ADMISSION_PATH` test, and kanban end to end (vulnerable and patched Dockerfiles, `gh` stub, compose service, admission entry, calibration). This proves the convention.
2. The backend-free twins: aws-api, token-optimizer, claude-in-mobile, arcadedb. Each a patched Dockerfile plus compose service, a fix-check fixture (or holdout_calibration where the version coincides), and an admission entry. arcadedb's fixture additionally needs `arcadedb_mcp_env` ported into `kit_launch.py` as a trimmed, `mcp_auditor`-free copy.
3. ckan: finalise and calibrate the responder backend, then the server's images, fixture and admission entry.
4. contextforge and flyto: register contextforge's provisioner and port `contextforge_ssrf_env` into `kit_launch.py` as a trimmed, `mcp_auditor`-free copy for its fix-check fixture; flyto needs no provisioner (decision 1), only its fix-check fixture on the kit `ssrf_env` builder. Then their images, fixtures and admission entries.
5. doris: reuse the existing doris kit backend builder (`kit_backends.doris_backend_env`), author the CVE-2025-66336 fix-check on the already-registered `doris` backend, then the server's images, fixture and admission entry.
6. Finalise `nuisance_admission.json` with `rule_commit` the v2 rule commit, `grammar_fingerprint` the current `cve_baseline.grammar_fingerprint()`, each server's `agents`/`agreement`/`settlements`, and run `load_admission` green.

## What stays unchanged

`evals/cve_grammar.py` and the grammar fingerprint (touching the grammar resets the acceptance baseline and voids any holdout figure). `evals/nuisance_counting.py`, `evals/nuisance_images.py`, `evals/nuisance_admission.py`'s schema and validation (they are built for this and need no change; if one does, that is a finding, not a silent edit). The acceptance and holdout Dockerfiles, services and images. The nuisance `run` and `gate` commands' behaviour. The holdout kit's `check_fix` and builders (reused, not modified; if a builder a server needs is missing from the kit, adding it is a named sub-task, not an edit to existing ones). No baseline is recorded by this work: the suite stays empty until a run, and the acceptance gate's baselines are untouched (no acceptance server is admitted here).

## Edge cases

A counted flaw whose patched version differs from the server's needs `server_patched_surfaces` set (not null) and a `<slug>-flaw-<version>` fix-check arm; `_patched_version_problems` enforces both directions. A counted tool with no benign call fails `_benign_call_problems` (arcadedb's `execute_command` is the live case). A flaw recorded under another spelling of the server (contextforge's rebuild) needs a `server_package` settlement so `_foreign_flaws` accepts it. A dropped flaw stays in the admission with its real class or a null class; it must not be deleted (the record is the provenance). The CKAN responder and any sentinel must stand on a public-range address so the patched server's SSRF guard passes the benign call. A server whose benign call errors on the patched image (`patched_benign_errored` true, aws's 16584 case) must not be a counted flaw.

## Test scenarios

Unit: the `ADMISSION_PATH` loading test passes against the committed admission (and skips when absent). The existing `nuisance_backends` parity test stays green after the ckan entry and any new provisioner. A test that `FIX_CHECK_TARGETS` covers every counted flaw of every admitted server (each counted `(server, flaw)` has a target), except a flaw whose recorded `fix_check.source` is `holdout_calibration` (aws-api's 4270), which is satisfied by the recopied record without a target, so a counted flaw can never ship without a reproducible fixture or a recopied holdout calibration. A test that each `FixCheckTarget`'s `mechanism` and counted tools match the admission `FlawRecord`'s `effect_class` and `tools` for that flaw (the admission stores no `aim`, so the target's `aim` is not cross-checked against it). Pyright strict and ruff clean on the changed files.

Docker (calibration, no LLM): `run_nuisance calibrate` green on every admitted server, each counted flaw's witness surfacing on the vulnerable version and on neither patched version, every benign call returning without error, and each result matching the admission's recorded `fix_check`. The CKAN responder and the contextforge sentinel stand and are reached.

## Verification

`uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright` (no file argument, the step-closing full run). `uv run python -m evals.run_nuisance calibrate` green under Docker. `uv run python -c "from evals.nuisance_admission import load_admission, ADMISSION_PATH; from evals.holdout_census import load_census; from evals.run_census import CENSUS_PATH; load_admission(ADMISSION_PATH, load_census(CENSUS_PATH))"` succeeds. `docker compose -f evals/docker/compose.yml build <each new service>` succeeds and the fingerprint-label test stays green.

## Living docs

Update, in the same work (CLAUDE.md "Update the living docs ... A feature isn't done until the living docs match it"):

- `CLAUDE.md` Commands list: add the new `run_nuisance calibrate` command, and drop the now-false "no server is admitted yet" tail on the `walk` entry (nine servers are admitted after this work). The `run` entry's conditional "prints that no server is admitted ... while the admission is absent or empty" stays accurate; the `gate` entry's "no acceptance server is admitted yet" stays true (this work admits no acceptance server).
- `CONTRIBUTING.md`: the admission and calibration flow changes, so this is not conditional. Document the new `calibrate` command, and correct the now-false state statements: "The nuisance admission is scaffolded, and no server is admitted" and "The admission session itself, the patched images and the fix check are the maintainer's deferred work" (line ~56). The gate paragraph's "No acceptance server is admitted yet" stays true.
- `README.md`: reconcile any nuisance-suite state wording with the admitted suite (the measurement itself stays future-tense: this work records no baseline and runs nothing).
- `CHANGELOG.md` `[Unreleased]`: the admitted suite and the new `calibrate` command.
- `docs/nuisance-log.md` (it already exists): add an entry for the admitted servers and one for each dropped server with its reason (create-mcp-server-stdio unreachable, fetch declared-function-is-effect, stata proprietary binary).

Do not touch `plans/` or `docs/adr/`.

## Decisions

The numbers are stable so the steps can cite them. Three are settled; two resolve at the step that needs them, on the real source or fixture.

**Resolved:**

1. flyto `backend_need` → **none**. The counted benign calls (`string.uppercase`, the seeded recipe) are backend-free, so no run backend is provisioned; the SSRF sentinel is a fix-check-only concern on the kit `ssrf_env` builder. No flyto provisioner is registered.
4. token-optimizer patched source → **advisory at 5.1.1**. The diligence pass verified 5.1.1 is the first fix-carrying npm release (5.1.0 is a git tag only); 5.1.1 is the counted flaw's patched version, `server_patched_surfaces` null.
5. fix-check source policy → **holdout_calibration only where the counted flaw is the twin's own holdout-calibrated flaw at the same version**. That is aws-api alone (CVE-2026-4270 at 1.3.9). Everywhere else, including kanban (the convention-setting pilot, whose counted flaw 53818 is its holdout flaw but which deliberately demonstrates the fix_check path) and doris (whose counted flaw 66336 is not its holdout flaw 66335), the source is fix_check with a committed vulnerable fixture authored on the holdout builder. `calibrate`'s comparison excludes the `source` field for a holdout_calibration record.

**Open (resolve at the step):**

2. contextforge's benign REST tool and responder shape. The provisioner mirrors `ckan_provisioner` over `contextforge_ssrf_env`; the exact benign tool and responder are derived from the holdout twin's stdio fixture at Step 4, since record A never ran it over stdio.
3. arcadedb's counted tools. `execute_command` is counted; whether `query` also routes the polyglot js path on 26.7.1 decides if `query` joins it or is dropped from the flaw's tools. Resolve on the 26.7.1 source at Step 2 calibration. (The doris counted-tool set, `get_table_comment` alone versus the other read tools, is the same kind of source settlement, resolved at Step 6 calibration.)

## Due diligence record

The diligence pass verified the external version facts this plan cites against live registries and tags on 2026-10-27. Each line below records what that one verification concluded; it is not a standing guarantee. No later pass may treat a line here as a reason to skip its own verification (the record says what was concluded once, not what is true now). A maintainer who edits the corresponding fact by hand should delete its line rather than update it, so this section never asserts something nobody checked.

- SETTLED: `github-kanban-mcp-server` patched `0.4.1` from the `v0.4.1` git tag (tag verified present on github.com/sunwood-ai-labs/github-kanban-mcp-server, alongside v0.4.0 and v0.3.0; source `fix_commit` is correct).
- OPEN (unverified): the sub-claim "npm stops at 0.3.0" for github-kanban-mcp-server. The unscoped npm name returns 404 (package and the 0.3.0/0.4.1 version endpoints all 404), so the package could not be confirmed on npm at all; a scoped name was not checked. Not load-bearing (the patched source is the git tag, verified above).
- SETTLED: `awslabs.aws-api-mcp-server` patched `1.3.9` for CVE-2026-4270 (release present on PyPI; the counted flaw's fix at 1.3.9 matches the calibrated holdout twin's range `>=0.2.14,<1.3.9`). The separate PyPI advisory fixing at 1.3.47 is CVE-2026-16584 (GHSA-29w2-fq35-v728), the flaw this plan drops, not CVE-2026-4270.
- SETTLED: `arcadedata/arcadedb` patched `26.7.1` for CVE-2026-65831 (tag present on github.com/ArcadeData/arcadedb; 26.8.1 also exists, confirming the plan's argument that 26.8.1 is a valid later tag deliberately not chosen; matches the calibrated holdout twin's first-patched pin).
- OPEN (currency): `@ooples/token-optimizer-mcp` patched `5.1.1`. Verified on npm: `5.1.1` is published, `5.1.0` is not (404). The advisory's first-patched is the `v5.1.0` git tag (the calibrated holdout twin builds from it); npm's first release carrying the fix is 5.1.1. Fed decision 4 (since resolved to `advisory` at 5.1.1): `source advisory` at 5.1.1 (deployable npm release) is defensible, but 5.1.1 differs from the flaw's advisory first-patched (5.1.0), which interacts with `_patched_version_problems` and `server_patched_surfaces`. Confirmed at calibration.
- SETTLED: `claude-in-mobile` patched `3.10.3` for CVE-2026-81562 (present on npm; `3.10.2` is absent from npm, consistent with the holdout twin building the vulnerable version from the `v3.10.2` git tag; source `advisory` is correct).
- SETTLED: `flyto-core` patched `2.28.0` as the server version, and `2.26.3`/`2.26.7` for the earlier-fixed flaws (all three releases present on PyPI).
- OPEN (deferred): the per-flaw first-patched mapping for flyto's counted flaws without a holdout twin (CVE-2026-67424/67427/67428 at 2.26.7, CVE-2026-73530 at 2.28.0). The releases exist, but that each is the first-fixed version for its CVE is an advisory-mechanics claim with no calibrated twin to rest on; validated at nuisance calibration against the `server_patched_surfaces` arms.
- SETTLED: `@aborruso/ckan-mcp-server` patched `0.4.112` (version manifest present on npm) for CVE-2026-73844 and CVE-2026-73845.
- SETTLED: `mcp-contextforge-gateway` patched `1.0.7` for CVE-2026-18905 (release present on PyPI, uploaded 2026-08-05; matches the calibrated holdout twin's first-patched pin).
- OPEN (unverified): `doris-mcp-server` patched `0.6.1` for CVE-2025-66336. doris was added to the plan after this diligence pass ran, so its version was not independently web-verified here; `0.6.1` is the pin the calibrated holdout doris twin builds and the value its admission record carries. Verify at Step 6 calibration against PyPI and confirm 0.6.1 is 66336's first fix (the holdout twin's 0.6.1 was pinned for the reaching flaw 66335).
- OPEN (currency): every patched version above is the first-fixed release for its flaw and so deliberately lags the current upstream latest (observed on 2026-10-27: ckan 0.4.131, contextforge 1.1.0, flyto 2.33.0, arcadedb 26.10.2, claude-in-mobile 4.4.1, aws-api 1.5.6). None was changed: pinning the first-fixed version is the nuisance suite's intent, not staleness. Confirm this is deliberate for each.
- OPEN (deferred): the advisory-mechanics per flaw (the exploit path, the witness channel, the affected tool) were not independently web-verified beyond the version facts above; they rest on the admission records and are confirmed in-repo at Docker calibration (`run_nuisance calibrate`), by design.

## Implementation steps

These steps cover only the repo code that goes through the implementation flow. The eval data and
fixtures each step references, `evals/nuisance_admission.json`, the `Dockerfile.<service>` files and
their `compose.yml` services, are authored directly and committed by hand (per the project
convention and the plan's "Approach"); they are not implemented here. The implementer is handed the
validated admission fix-check fixtures (exploit and benign callables) at implement time; the
committed code carries no path back to them. The "Decisions" section settles three decisions (1, 4,
5), applied as stated; the two open ones (2, 3) are resolved by the maintainer at the step that cites
them, not by the implementer.

Every code step stays green on the unit suite alone: the `ADMISSION_PATH` loading test and the
`FIX_CHECK_TARGETS` coverage/parity tests skip while `evals/nuisance_admission.json` is absent, and
no unit test builds or launches a container. The real Docker calibration (`run_nuisance calibrate`),
the `docker compose build` of each new service, and the `load_admission` one-liner are the
maintainer's out-of-band confirmation once the hand-authored artifacts land; they are listed under
each step's Verify as that confirmation, not as a unit gate.

Naming the step planner fixes for the implementer: the per-flaw fix-check fixture modules live in a
new package `evals/nuisance_fix_checks/` (distinct from the aggregator module
`evals/nuisance_fixtures.py`, which cannot share its name), one module per flaw named
`cve_YYYY_NNNNN_<slug>.py`, mirroring `evals/holdout_fixtures/`. Each such module and every builder
ported into `evals/holdout_kit/kit_launch.py` must import only from inside the kit's closure
(`evals.holdout_kit`, `evals.cve_grammar`, `evals.cve_places`, `evals.cve_planting`,
`evals.cve_planting_spec`), never from `mcp_auditor` nor from `evals.cve_environments`; the exploit
and benign callables are `FixCheckExploit`, so they take `(Places, KitClient)`, not the holdout
twin's `(Places, MCPClientPort)` (the call sites are otherwise identical, `KitResponse` mirroring
`ToolResponse`).

### Step 1: Mechanism and kanban pilot

**Files**:
- `tests/unit/test_nuisance_admission_loads.py` (new): the `ADMISSION_PATH` loading test.
- `tests/unit/test_nuisance_fix_checks.py` (new): the `FIX_CHECK_TARGETS` coverage and parity
  tests, plus the `calibrate` comparison unit tests.
- `evals/nuisance_fix_checks/__init__.py` (new) and `evals/nuisance_fix_checks/cve_2025_53818_github_kanban.py`
  (new, carrying both kanban `FixCheckTarget`s, CVE-2025-53818 and CVE-2026-0756; one module is fine
  since they share builder and host).
- `evals/nuisance_fixtures.py` (modify): the thin aggregator, importing the kanban module into
  `FIX_CHECK_TARGETS`, as `evals/holdout_targets.py` aggregates `evals/holdout_fixtures/`.
- `evals/run_nuisance.py` (modify): the `calibrate` subcommand and its comparison helper.
- `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md` (modify): document the new `calibrate` command only
  (the admitted-state wording and `nuisance-log` entries land in Step 7, once the admission exists).

**Do**:
- Write `tests/unit/test_nuisance_admission_loads.py` first: when `ADMISSION_PATH` exists,
  `load_admission(ADMISSION_PATH, load_census(CENSUS_PATH))` returns without raising; when it is
  absent, the test skips cleanly (`pytest.skip`), mirroring `test_holdout_census.py`'s committed-file
  test. It starts validating the moment the admission lands in Step 7.
- Write `tests/unit/test_nuisance_fix_checks.py` first: (a) every counted `(server, flaw)` of every
  admitted server has a matching `FixCheckTarget` in `FIX_CHECK_TARGETS`, except a flaw whose
  `fix_check.source` is `holdout_calibration` (aws-api's 4270), which is satisfied without a target
  (skips when the admission is absent); (b) each target's `mechanism` and counted tools equal the admission `FlawRecord`'s
  `effect_class` and counted tools for that flaw (the admission stores no `aim`, so `aim` is not
  cross-checked); (c) the pure comparison the `calibrate` command uses matches a `FixCheckResult`
  against a `FixCheckRecord` field for field, except that a record whose `source` is
  `holdout_calibration` excludes the `source` field (decision 5); (d) with an empty
  `FIX_CHECK_TARGETS` or no admission file, `calibrate` prints "nothing is drawn" and returns 0.
- Build the kanban module: two `FixCheckTarget`s sharing `builder=command_injection_env`
  (already in `kit_launch.py`, no port needed), `planting_host` unprivileged `/tmp` no network,
  witness a `/flag` file, `aim` `cat\s+/flag`, `mechanism=command_execution`. CVE-2025-53818 exploit:
  `add_comment` with `issue_number="; cat /flag #"`. CVE-2026-0756 exploit: `create_issue` with
  `title='x"; cat /flag >&2; false #'`. One shared `benign_calls` tuple (`list_issues`,
  `create_issue`, `update_issue`, `add_comment` against `octocat/hello-world` at `/work/repo`),
  working on both API shapes. `vulnerable_service="kanban-vuln"`, `patched_service="kanban"`,
  `server_patched_service=None`. Transcribe the exact callables from the validated admission fixture.
- Make `nuisance_fixtures.py` the aggregator importing the kanban targets.
- Add the `calibrate` subcommand to `run_nuisance.py`, the twin of `run_holdout calibrate`: it
  builds the kit images each target names (`kit_launch.build_images` against `evals/docker/`), runs
  `check_fix` on each (Docker, no LLM), prints each `FixCheckResult`, and compares it to the
  admission's recorded `fix_check` through the pure helper tested above, returning non-zero on any
  mismatch or on a witness that fails to surface on the vulnerable version or surfaces on a patched
  one. It takes `--cve ID` and `--concurrency`, and prints "nothing is drawn" / returns 0 with no
  admission or an empty `FIX_CHECK_TARGETS`.
- Living docs: add the `run_nuisance calibrate` line to the `CLAUDE.md` Commands list and document
  the calibration step in `CONTRIBUTING.md` and `CHANGELOG.md [Unreleased]`. Leave every "no server
  is admitted" / "scaffolded" state sentence untouched here (still true until Step 7).

**Test**: the five unit scenarios above (admission load + skip; coverage; mechanism/tools parity;
comparison incl. the `holdout_calibration` source exclusion; empty/no-admission calibrate path). No
Docker in the unit suite.

**Verify**: short loop `uv run pytest tests/unit -n auto --maxprocesses 4`; step-closing
`uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright` (no file
argument). Maintainer confirmation once the kanban Dockerfiles, `gh` stub, compose service and
admission entry are committed: `docker compose -f evals/docker/compose.yml build kanban kanban-vuln`
and `uv run python -m evals.run_nuisance calibrate --cve CVE-2025-53818` green.

### Step 2: Backend-free twins (aws-api, token-optimizer, claude-in-mobile, arcadedb)

**Files**:
- `evals/holdout_kit/kit_launch.py` (modify): port `arcadedb_mcp_env` from `evals/cve_environments.py`
  as a trimmed, `mcp_auditor`-free `arcadedb_env`, the way the four existing kit builders are trimmed
  copies of their `cve_environments` twins.
- `evals/nuisance_fix_checks/cve_2026_55157_token_optimizer.py`, `cve_2026_81562_claude_in_mobile.py`,
  `cve_2026_65831_arcadedb.py` (new). aws-api gets no fix-check module: its counted flaw uses
  `holdout_calibration` (decision 5), so its `fix_check` is a recopied record in the JSON, no
  `FixCheckTarget`.
- `evals/nuisance_fixtures.py` (modify): aggregate the four servers' targets.

**Do**:
- Port `arcadedb_env` into the kit first; the existing kit isolation test
  (`tests/unit/test_holdout_kit_isolation.py`) already guards the `mcp_auditor`-free closure, so run
  it as you go.
- aws-api (CVE-2026-4270, `read_outside_scope`, counted tool `call_aws` only): benign `call_aws`
  with `cli_command="aws ec2 describe-instances help"`. Decision 5 is resolved to
  `holdout_calibration` for aws (its counted flaw 4270 is the holdout twin's own calibrated flaw at
  1.3.9), so this server carries **no** `FixCheckTarget` with exploits and **no** committed vulnerable
  fixture: its `fix_check` block in the admission JSON recopies the holdout calibration's witness and
  booleans, and `calibrate`'s comparison excludes the `source` field for it. The aws module in
  `evals/nuisance_fix_checks/` is therefore either absent or a thin marker, and the coverage test
  treats a `holdout_calibration` flaw as satisfied without a `FixCheckTarget`.
- token-optimizer (CVE-2026-55157, `command_execution`, `smart_user`): `builder=command_injection_env`,
  benign `smart_user` with `operation="get-user-info"`, `username="root"`, `useCache=false`. Decision
  4 is resolved: patched `5.1.1` source `advisory` (the first fix-carrying npm release), so
  `patched_service` builds 5.1.1 and `server_patched_service=None`.
- claude-in-mobile (CVE-2026-81562, `command_execution`, counted tool `system`, action `shell`):
  `builder=command_injection_env`, benign `system` with action `shell` running
  `getprop ro.build.version.sdk`.
- arcadedb (CVE-2026-65831, `read_outside_scope`): `builder=arcadedb_env`, host unprivileged
  `/home/arcadedb` no network, launch option enabling the MCP server and `execute_command`. Counted
  tool `execute_command`, and `query` only if open decision 3 (does `query` route the polyglot js
  path on 26.7.1) resolves to yes. A benign call for `execute_command` is required
  (`_benign_call_problems`): add `execute_command` with a plain SQL `SELECT 1 AS ok` alongside the
  `query` benign. `server_patched_service=None` (patched 26.7.1 equals the flaw's).
- For every server here `server_patched_surfaces` is null, so no `<slug>-flaw-<version>` arm.

**Test**: the coverage and mechanism/tools parity tests from Step 1 gain these servers' rows once the
admission lands (they still skip until then). The kit isolation test stays green after the
`arcadedb_env` port.

**Verify**: short loop, then the step-closing full `uv run pytest -n auto`, `ruff check`,
`ruff format`, `pyright` (no file argument). Maintainer confirmation per server once its hand-authored
Dockerfiles, compose services and admission entry land: `docker compose build <service> <service>-vuln`
and `uv run python -m evals.run_nuisance calibrate --cve <id>` green.

### Step 3: ckan (responder backend finalisation and fix-check fixture)

**Files**:
- `evals/ckan_backend.py` (finalise, already untracked): re-read against the coding standards and
  commit; make no behavioural change unless a standards defect is found (a finding, not a silent
  edit).
- `evals/docker/Dockerfile.ckan-responder` (already untracked): hand-authored, committed by the
  maintainer with this step.
- `evals/nuisance_backends.py` and `tests/unit/test_nuisance_backends.py` (already modified with the
  `ckan` registry entry and its parity/provisioner tests): confirm the entry's `image`/`network`
  match `backend_problems`' expectation and that the tests stay green; commit.
- `evals/nuisance_fix_checks/cve_2026_73844_ckan.py`, `cve_2026_73845_ckan.py` (new): the two counted
  flaws' fix-check fixtures, `builder=ssrf_env` (already in the kit, no port), witness a planted
  sentinel like the contextforge holdout twin.
- `evals/nuisance_fixtures.py` (modify): aggregate the ckan targets.

**Do**:
- Confirm the already-written ckan backend registry entry and its parity test need no change; this
  step's new code is the two ckan fix-check fixtures. CVE-2026-73844: `internal_fetch`,
  `ckan_package_search`. CVE-2026-73845: `internal_fetch`, `ckan_get_mqa_quality` and
  `ckan_get_mqa_quality_details`. Both `server_patched_service=None` (patched 0.4.112 equals the
  server's). The fix-check builder plants its own sentinel (the kit `ssrf_env`); the CKAN responder
  backend is a run-time concern (the benign call reaching a live CKAN API), not a fix-check one.
- The run-time benign calls recorded in the admission (`ckan_package_search` reaching the responder;
  `ckan_get_mqa_quality` on `dati.gov.it`) and the `backend` block naming the `ckan` provisioner are
  hand-authored in the JSON, not here.

**Test**: the existing `nuisance_backends` parity test stays green; the Step 1 coverage/parity tests
gain the two ckan flaws once the admission lands.

**Verify**: short loop, then the step-closing full checks (no file argument). Maintainer confirmation:
`docker compose build ckan ckan-vuln ckan-responder` (as named) and
`uv run python -m evals.run_nuisance calibrate --cve CVE-2026-73844 --cve CVE-2026-73845` green, the
responder standing and reached, the two counted tools' benign calls answering without error.

### Step 4: contextforge (SSRF twin with a run backend)

Resolve open decision 2 (the benign REST tool and responder shape) before this step; the provisioner
and its responder image follow that settlement.

**Files**:
- `evals/holdout_kit/kit_launch.py` (modify): port `contextforge_ssrf_env` as a trimmed,
  `mcp_auditor`-free `contextforge_env`.
- `evals/nuisance_fix_checks/cve_2026_18905_contextforge.py` (new): the counted flaw's fix-check
  fixture, `builder=contextforge_env`, tool/benign/exploit transcribed from the holdout twin's
  fixture (record A ran it as HTTP, so its tools/benign are empty; the stdio twin is the source).
- `evals/contextforge_backend.py` (new): the responder lifecycle, a mirror of `evals/ckan_backend.py`
  standing the `contextforge_ssrf_env` sentinel on a public-range address.
- `evals/docker/Dockerfile.contextforge-responder` (hand-authored by the maintainer, committed with
  this step).
- `evals/nuisance_backends.py` (modify): register `contextforge_provisioner` and its
  `RegisteredBackend`, mirroring `ckan_provisioner`.
- `tests/unit/test_nuisance_backends.py` (modify): the contextforge registry-parity and
  provisioner-wiring tests, mirroring the ckan tests.
- `evals/nuisance_fixtures.py` (modify): aggregate the contextforge target.

**Do**:
- Port `contextforge_env` into the kit; keep the isolation test green.
- Write the `test_nuisance_backends.py` contextforge cases first (registry parity:
  `backend_problems` accepts the fixture; provisioner wiring: `--network`, `--user`, image tag +
  launch tail, ensure/rm reaping), then `contextforge_backend.py` and the `nuisance_backends`
  registry entry to satisfy them. `server_patched_service=None` (patched 1.0.7 equals the server's).
- The `server_package` settlement that unifies contextforge's foreign-spelling flaw record
  (`_foreign_flaws` / `_settled_to_server`) is hand-authored in the JSON, not here.

**Test**: the new contextforge backend parity and provisioner unit tests; the Step 1 coverage/parity
tests gain the contextforge flaw once the admission lands.

**Verify**: short loop, then the step-closing full checks (no file argument). Maintainer confirmation:
`docker compose build contextforge contextforge-vuln contextforge-responder` and
`uv run python -m evals.run_nuisance calibrate --cve CVE-2026-18905` green, the sentinel stood and
reached.

### Step 5: flyto (SSRF twin, multi-flaw)

Decision 1 is resolved: flyto is backend-free (`backend_need` none), so this step adds no provisioner
and no backend lifecycle. The SSRF sentinel is a fix-check-only concern, stood by the kit `ssrf_env`
builder.

**Files**:
- `evals/nuisance_fix_checks/cve_2026_55787_flyto.py` (new): one module carrying the five counted
  flaws' `FixCheckTarget`s, `builder=ssrf_env`.
- `evals/nuisance_fixtures.py` (modify): aggregate the flyto targets. No backend module (decision 1).

**Do**:
- Five `FixCheckTarget`s: CVE-2026-55787, 67424, 67428, 73530 on `execute_module` (`internal_fetch`,
  the `http.get`-style module pointed at the planted sentinel) and CVE-2026-67427 on `run_recipe`
  (`read_outside_scope`). The `internal_fetch` benign is `execute_module` with
  `module_id="string.uppercase"` (backend-free); the `read_outside_scope` benign is `run_recipe` with
  a seeded `nb08benign` recipe (backend-free).
- `server_patched_service` is set (not None) on the flaws whose patched version differs from the
  server's 2.28.0: 55787 (2.26.3), 67424/67427/67428 (2.26.7); each of those needs a
  `flyto-flaw-<version>` fix-check arm (hand-authored Dockerfile + compose service). 73530 is 2.28.0,
  so `server_patched_service=None`. `_patched_version_problems` enforces both directions, so the
  admission `server_patched_surfaces` values (false on the differing-version flaws, null on 73530)
  must match these arms.

**Test**: the Step 1 coverage/parity tests gain the five flyto flaws once the admission lands. No new
backend tests (decision 1: flyto is backend-free).

**Verify**: short loop, then the step-closing full checks (no file argument). Maintainer confirmation:
`docker compose build flyto flyto-vuln flyto-flaw-2.26.3 flyto-flaw-2.26.7` and
`uv run python -m evals.run_nuisance calibrate --cve CVE-2026-55787 ...` green across the five flaws.

### Step 6: doris (holdout-twin backend server)

doris's run backend is the already-registered `doris` provisioner, so this step registers no new provisioner, and its fix-check backend builder (`kit_backends.doris_backend_env`) already exists in the kit, so its only new code is the fix-check fixture. The counted-tool set (`get_table_comment` alone versus the other read tools the record lists) is settled on the 0.6.1 source at this step's calibration, the doris analogue of decision 3.

**Files**:
- No kit builder port: the doris fix-check backend builder already exists as `evals/holdout_kit/kit_backends.py`'s `doris_backend_env` (standing the doris cluster, isolation-clean), reused as the fixture's `builder`. Unlike `arcadedb_env` and `contextforge_env`, which steps 2 and 4 port from `cve_environments`, doris needs no kit change.
- `evals/nuisance_fix_checks/cve_2025_66336_doris.py` (new): the counted flaw's fix-check fixture, builder the doris kit builder, witness a value read outside the database scope by `get_table_comment`.
- `evals/nuisance_fixtures.py` (modify): aggregate the doris target.

**Do**:
- Reuse the existing `kit_backends.doris_backend_env` as the fixture's `builder`; no port, so no kit change (the isolation test already covers it).
- Author the CVE-2025-66336 fix-check on the working doris backend (the environment the holdout twin and the registered `doris` provisioner already drive), not from the blind admission run, whose fix-check mis-wired the cluster (its positive control did not surface the witness on the vulnerable version). The exploit makes `get_table_comment` read the planted witness outside the database scope; the witness surfaces in the returned comment. `server_patched_service=None` (patched 0.6.1 equals the server's).
- The flaw analysis (`read_outside_scope`, the read tools, `declared_function_is_effect` false) and the run-time benign calls plus the `backend` block naming the `doris` provisioner are hand-authored in the JSON, not here.

**Test**: the Step 1 coverage/parity tests gain the doris flaw once the admission lands; the kit isolation test stays green (no kit change, the doris builder already exists).

**Verify**: short loop, then the step-closing full checks (no file argument). Maintainer confirmation: `docker compose build doris doris-vuln` (plus the doris backend images the provisioner pins) and `uv run python -m evals.run_nuisance calibrate --cve CVE-2025-66336` green, the cluster stood and the witness surfacing on the vulnerable version and on neither patched one.

### Step 7: Finalisation and admitted-state living docs

**Files**:
- `evals/nuisance_admission.json` (hand-authored by the maintainer, committed with this step): the
  nine servers with `rule_commit` the v2 rule commit, `grammar_fingerprint` the current
  `cve_baseline.grammar_fingerprint()`, and each server's `agents` / `agreement` / `settlements`.
- `CLAUDE.md`, `CONTRIBUTING.md`, `README.md`, `CHANGELOG.md`, `docs/nuisance-log.md` (modify).

**Do**:
- This step's code work is the living-docs reconciliation; the admission JSON is the maintainer's
  hand-authored artifact, and with it committed the Step 1 `ADMISSION_PATH` and coverage/parity tests
  stop skipping and must pass.
- `CLAUDE.md` / `CONTRIBUTING.md`: drop the now-false "no server is admitted yet" / "scaffolded, no
  server is admitted" / "the maintainer's deferred work" state sentences on the `walk` entry and the
  admission paragraph (nine servers are admitted). Keep the `run` entry's conditional "prints that no
  server is admitted ... while the admission is absent or empty" and the `gate` entry's "no acceptance
  server is admitted yet" (this work admits no acceptance server).
- `README.md`: reconcile the nuisance-suite state wording with the admitted suite, keeping the
  measurement itself future-tense (this work records no baseline and runs nothing).
- `CHANGELOG.md [Unreleased]`: the admitted suite.
- `docs/nuisance-log.md`: one entry for the admitted servers and one per dropped server with its
  reason (create-mcp-server-stdio unreachable, fetch declared-function-is-effect, stata proprietary
  binary).

**Test**: the full unit suite, now including the un-skipped `ADMISSION_PATH` load and the
`FIX_CHECK_TARGETS` coverage/parity tests against the committed admission.

**Verify**: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright`
(no file argument). `uv run python -c "from evals.nuisance_admission import load_admission, ADMISSION_PATH; from evals.holdout_census import load_census; from evals.run_census import CENSUS_PATH; load_admission(ADMISSION_PATH, load_census(CENSUS_PATH))"` succeeds. Maintainer's full Docker
confirmation: `uv run python -m evals.run_nuisance calibrate` green on every admitted server, and the
fingerprint-label test green after every new `docker compose build`.
