# Nuisance re-admission under rule v4, first part: the per-tool declared function and the servers of lots L0 to L3

## Context

The version 4 admission campaign of the nuisance suite is settled outside the repository, and its readings of the rule are in `docs/nuisance-log.md` (entry of 2026-11-08). Its results reach the repository in several pieces of work. This one carries the counter change every later piece relies on and the re-admitted servers of the campaign's first four lots (L0 to L3): 23 servers stay (sf-mcp and doris, which also stay, follow in a later piece), 4 admitted servers leave, and one first admission that never entered is recorded as a drop.

Everything this plan relies on per server is in the vesting manifest: one section per server, giving its outcome, the flaws that set its version, its counted tools with the reason for each one added or removed, the fixture retained file by file (from the record of agent a, of agent b, or mixed), the releases, the seed, the stand-ins and backend, the fix check, the launch, the fields rule v3 and v4 add, the log lines, the agents' models and the points left open with a recommendation. The manifest, the maintainer's decision log, the two agents' records of each server and the fixtures they proposed are held outside the repository, and the maintainer gives their location to the implementer at launch. Where a manifest section and the decision log differ, the decision log wins. Where a section leaves a point open, its recommendation applies unless the decisions below say otherwise.

Nothing here runs an audit. Fix checks run through `run_nuisance calibrate` and benign calls through `run_nuisance vet`, both with Docker and no LLM.

## Decisions

These are the maintainer's, applied as stated.

1. **The counter reads the declared function per tool.** A flaw can reach tools whose declared function is the effect of its class and tools whose declared function is not. The counter reads `ToolRecord.declared_function_is_effect`, which the schema already carries, and falls back to `FlawRecord.declared_function_is_effect` for a tool that records none. `adb_shell`, removed from its flaw's `tools` in data, stays as it is.
2. **A tool reached with no benign call written does not count.** A tool that reaches a flaw but for which neither record writes and plays a benign call is left out of the flaw's `tools` and logged, as `run_job` was. In this part: praisonai's two `validate` tools and adb-mcp's `inspect_ui` and `dump_image`.
3. **The manifest's recommendations on open points apply**, with the exceptions above. In this part they settle, among others: praisonai stays on two tools and its `mcp<2` bound is kept only if a build without it fails, the failing run recorded; mysql's `baked_work` is false and `has_network` false once its backend leaves; markdownify takes agent a's seed and ExifTool 13.55; biome takes agent a's fixture; semgrep keeps agent a's install channel, logged; codehooks sets `backend_need` to `fixture`; ckan empties `host.public_names`; contextforge takes agent a's fixture with agent b's split of the fix-check-only plumbing into its patched image; atlassian keeps agent a's project keys and takes the documented Jira example for the issue body.
4. **desktop-commander's `read_file` and CVE-2026-10690.** `read_file` also carries CVE-2026-10690, which has no class and no version in the census. The implementer reads the census and the advisory: if no release fixes it and its effect overlaps the judge categories `read_file` is counted under, `read_file` leaves the count (the campaign's reading of a flaw never fixed, `docs/nuisance-log.md` 2026-11-08) and the count is 9, logged; otherwise it stays and the count is 10, logged.
5. **The stand-in authority is regenerated with each commit that adds a stand-in host, and the holdout calibration copies are recorded once, at the end of the campaign's assembly.** The committed authority must sign for exactly the hosts that have a committed HTTPS capture (`tests/unit/test_committed_stand_ins.py`), so this part regenerates it with the hosts it adds (change 2 covers the two hosts of this part that fall outside that set, and the commit order). Every regeneration moves the fixture fingerprint of the holdout targets whose hosts declare stand-ins, so this part records no `holdout_fingerprint`: the copied holdout calibrations of its servers keep their copied fields, and their fingerprints are recorded in one pass once the last regeneration of the campaign is done. `run_nuisance run` refuses until then, as it already does.

## Changes

### 1. The counter reads the declared function per tool (`evals/nuisance_counting.py`)

`flaw_counted_tools(flaw)` returns the reachable tools whose effective declared function is not the effect, where a tool's effective value is its own `declared_function_is_effect` when it records one and the flaw's otherwise. `declared_function_tools(server)` returns, over the counted flaws, the reachable tools whose effective value is true, with the same categories. Today it takes every reachable tool of a flaw whose flaw-level value is true. The module docstring says the declared function is read per tool. A flaw whose tools all record false and whose flaw-level value is true counts its tools.

The comment on `ToolRecord.declared_function_is_effect` (`evals/nuisance_admission.py`) and the paragraph of the admission dossier that says the flaw-level field "is the record the count reads until the per-tool one supersedes it" (`evals/nuisance_dossier.py`) say the counter reads the per-tool field and falls back to the flaw's.

Tests, in the counter's existing test file (`tests/unit/test_nuisance_counting.py`) with its given helpers (`tests/unit/support/test_nuisance_counting_given.py`): a flaw with one tool recording true and one recording false counts the second only, and the first is a declared-function tool. A tool recording none follows the flaw's value. A flaw whose value is true but whose tools all record false counts them all. A removed tool is never counted either way. The existing `test_a_tool_recorded_as_its_effect_under_a_flaw_recorded_otherwise_stays_counted` pins today's flaw-level reading: it inverts (the tool is no longer counted, and is a declared-function tool), renamed to say so, and is the first test to go red.

Effect on the committed admission, before any server below changes: the implementer lists the servers whose counted tools move (`counted_tools` before and after on `evals/nuisance_admission.json`) and names them in the log entry. At `d7c32b1` no committed tool records `declared_function_is_effect`, so the list is expected to be empty and the entry says the change moves no count until a re-admission records the per-tool field. One `docs/nuisance-log.md` entry (2026-11-08) records the change and that list.

### 2. Stand-in authority with this part's hosts (`evals/stand_ins/tls/`, the two CVE-2026-5323 Dockerfiles)

Run `evals/stand_ins/tls/generate.sh` with every HTTPS host that has a committed capture once this part's captures are in, the existing ones included, since a run removes the TLS files of a host it is not given. Copy the new `fixture-authority.pem` into `evals/docker/Dockerfile.holdout-2026-5323-a11y` and `-patched` (`tests/unit/test_holdout_targets.py` catches a stale copy) and update their fingerprint labels in `evals/docker/compose.yml`. A capture added later in this part's commits goes in before the regeneration commit, or the regeneration is redone, so that the authority test passes at every commit. `tests/unit/support/test_committed_stand_ins_given.declared_stand_in_hosts` lists the hosts the CVE and holdout targets and apify declare: extend it to the hosts the admitted servers' fixtures serve (their `host.public_names.stand_ins` and the hosts a backend's lifecycle serves), so a nuisance-only capture is a declared one. Read every host from the code, not from a list here.

Two hosts of this part do not fit "one leaf per HTTPS capture", which is what `test_the_committed_authority_signs_for_exactly_the_https_stand_in_hosts`, `test_every_committed_leaf_names_an_https_stand_in_host` and `test_every_committed_capture_loads_with_its_leaf` pin today:

- the retained CKAN lifecycle mounts a fixture leaf for `www.dati.gov.it` on the real CKAN front (with `demo.ckan.org`, which has a capture), and `www.dati.gov.it` has no capture. Its leaf and the authority's permission for it are needed, so the authority test and the leaf-name test (the first two above; the capture-load test is unaffected by a host with no capture) take as their host set the HTTPS capture hosts plus the names a registered backend lifecycle serves under TLS from a fixture leaf, read from the code (the CKAN lifecycle's front names), while `declared_stand_in_hosts` stays the captured set.
- markdownify's new `www.google.com` capture has only `http` routes, yet `public_stand_ins.stand_in` and the stand-in launch (`cve_planting_stand_ins`) read a leaf for every capture, so it needs a leaf too, which the "HTTPS hosts" tests refuse.

An HTTP-only capture (markdownify's `www.google.com`) is new, every committed capture having an https route so far: `generate.sh` is given every captured host plus the TLS names a backend's lifecycle serves (CKAN's `www.dati.gov.it`), and the authority tests compare against that set. The given helper `committed_https_hosts` and the test names that say "https" are renamed after that set, since it is no longer the HTTPS hosts. Only tests and docs change, no loader, launch or stand-in image code, so no further fingerprint moves.

The authority is regenerated in each server commit that adds a stand-in host (markdownify, semgrep, codehooks, ckan, contextforge, apify), so that each commit carries a new capture together with its leaf, its declaring admission entry and the authority's permission, and the stand-in tests pass at every commit. The CVE-2026-5323 PEM copies and labels are redone in each of those commits, and their images are rebuilt and calibrated once, after the last. Decision 5's reason holds: no `holdout_fingerprint` is recorded in this part.

One `docs/holdout-log.md` entry: the authority is regenerated with the nuisance hosts this part adds, which moves the fixture fingerprint of the holdout targets whose hosts declare stand-ins, with no fixture of theirs changed. It also moves the fixture fingerprint of the CVE acceptance target CVE-2025-65513, which declares `example.com`. No CVE acceptance baseline is committed at `d7c32b1` (`evals/baselines/cve/` is absent), so nothing resets. If one has been recorded by then, the regeneration is a fixture change under ADR 016 and the baseline is deleted in its own commit. On the nuisance side, a regeneration moves the fixture fingerprint of every admitted server that reads a fixture leaf (through `host.public_names.stand_ins` or its backend entry's `served`). At `d7c32b1` that is apify alone, which is in this part. The implementer checks that this still holds on the tree being regenerated. If a server outside this part moves, a `docs/nuisance-log.md` line names it with the values before and after, as the 2026-11-08 entry on the stand-in image does. Run `uv run python -m evals.run_holdout calibrate --cve CVE-2026-5323` after rebuilding its images (`docker compose -f evals/docker/compose.yml build holdout-2026-5323-a11y holdout-2026-5323-a11y-patched`): it must stay green.

### 3. The re-admitted servers of lots L0 to L3

For each server the manifest marks as staying and as belonging to this part (maigret, mysql, praisonai, adb-mcp, nmap, android, desktop-commander, taskwarrior, siri-shortcuts, ios-simulator, markdownify, godot-mcp, biome, magento2, serverless, semgrep, node-sandbox, codehooks, ckan, contextforge, n8n, atlassian, apify), one commit that carries its manifest section into the repository:

- **Admission entry** (`evals/nuisance_admission.json`): `flaws` with the tools the section records under each flaw: its counted tools, plus the tools it keeps out of the count with `real_software.answers` false (adb-mcp's `adb_push`, android's `monitor-events`, magento2's two `software_error` tools) or with `declared_function_is_effect` true (node-sandbox's three, codehooks's `deploy_code`, magento2's `db-query`, ckan's `server_url` tools), which the per-tool counter (change 1) leaves out. A tool left out under decision 2 or 4, a tool that also carries an open flaw whose categories overlap (markdownify's three URL tools) and `adb_shell` (decision 1) are not listed. Each tool gets its `real_software` and `declared_function_is_effect`. Then the benign calls with their `expect` and `before`, `relies_on_relaying_stand_in`, `effect_class`, `backend_need` (magento2 and codehooks go to `fixture`), `patched_version` and `patched_source` as the section gives them (n8n's CVE-2026-39974 and CVE-2026-42449 get their advisory versions 2.47.4 and 2.47.14), `host`, `launch`, `service`, `backend`, `stand_ins`, `seeds`, `software_releases`. `agents` keeps the entries it has and gains the two re-admission agents (`role` `admitter`, `scope` `re-admission record A` and `re-admission record B`), each with the model it was launched on and, when the provider answered with another, `fallback_model`, as the section gives them. Several servers had their agent a redone alone (maigret, nmap, android, taskwarrior, ios-simulator, n8n), its first record voided. As `AgentRecord` records one entry per agent launched, the voided agent gets its own entry with `set_aside` giving the cause in plain words: its record was written before its work under an instruction since corrected, or it saw the other agent's final summary before writing its own. `agreement` and `settlements` are replaced by those of the re-admission: one `FieldAgreement` per field the two records give, and one `AdmissionSettlement` per field the maintainer settled, with a reason that states the rule or the reading it applies in plain words (no campaign label, no file outside the repository).
- **Fixture files**: each file the section retains, copied from the proposed fixture to its repository path, with the repairs the section names. A copied Python module (a backend lifecycle, a fix check, `evals/apify_backend.py`) meets the coding standards of `CLAUDE.md` like any code in the repository (function and file length, few arguments, newspaper order, names), refactored where needed with no change to what it launches, before the calibration or `vet` that closes its commit. A Dockerfile under `evals/docker/` gets its fingerprint label updated in `evals/docker/compose.yml` (CONTRIBUTING). A new compose service gets the labels its neighbours carry. A capture keeps its `source`: a capture taken from the real software is `capture`, a route written from the software's documentation is `software_sources`, split into its own file when a capture embeds one. A fix-check image (`-vuln`, `-patched`, `-flaw-*`) is built by its module, not by compose, so it gets no compose service (contextforge's new `Dockerfile.contextforge-patched` included). Every copied Dockerfile must pass `tests/unit/test_cve_compose_labels.py`, whose parser (`cve_images.dockerfile_instructions`) reads every non-comment line, heredoc bodies included. As proposed, several do not: `ADD --checksum=… <URL>` or `COPY --from=<image@digest>` instructions trip `test_no_dockerfile_copies_from_the_build_context` (adb-mcp and its `-vuln`, ios-simulator and its `-vuln`, markdownify, serverless, semgrep and its `-vuln`), and a heredoc line starting with Python's `from … import` reads as an unpinned `FROM` in `test_every_base_image_is_pinned_by_digest` (maigret, ios-simulator and its `-vuln`, atlassian-responder). The heredoc case is repaired in the Dockerfile without changing what it builds (e.g. `import x` then `x.y`), since the parser's lines are also what the fingerprint hashes. Narrow `test_no_dockerfile_copies_from_the_build_context` instead of rewriting those Dockerfiles: the test exists so that no copied source escapes the fingerprint, and a source pinned by a checksum or a digest in the instruction text is hashed with the instruction. The predicate already exists, pure and tested: `evals.fixture_sources.unsourced_copies`, which the nuisance fixture-source test applies to every fingerprinted Dockerfile, refuses a `COPY` or `ADD` from the build context and a remote `ADD` without a checksum in Docker's form, and accepts `ADD --checksum=sha256:<hex> <URL>`. The test asserts it finds nothing instead of refusing every `COPY` and `ADD`. One gap is closed in `unsourced_copies` itself, test-first in `tests/unit/test_fixture_sources.py`: it accepts any `COPY --from=` today, and it refuses a `COPY --from` an image not pinned by digest while accepting `COPY --from=<image>@sha256:<digest>` and a `COPY --from` an earlier stage of the same Dockerfile, each with a test case. Its own commit, before the first server that needs it.
- **Backends**: ckan and n8n replace their responder with the real software (CKAN 2.12.1 in the ckan-docker stack, n8n 2.46.6). Their lifecycle module replaces the committed one, and their entry in `evals/nuisance_backends.py` follows. The entry is a `RegisteredBackend` built directly, no longer through `_responder`. Its `built_services` names every compose service the stack builds (CKAN's five `ckan-*` services and the stand-in service for `data.europa.eu`, n8n's instance service), each a nuisance-profiled compose service (`tests/unit/test_nuisance_compose.py`). Its `served` holds the lifecycle module, those Dockerfiles and the captures, leaves and authority the lifecycle mounts, as apify's entry does today, so the run fingerprint reads them. `backend.image` in the admission is the entry's `image`. `evals/nuisance_provisioners.py` builds every provisioner from its lifecycle and needs no change. mysql, contextforge and apify leave their backend: `backend` goes to `null` and `host.has_network` to false (`_network_problems` refuses a network without a backend). The run serves apify's two hosts and contextforge's `httpbin.org` under their real names through the holder, and mysql's engine runs in its image as its holdout twin's does. Their registry entries go. Remove whatever no admitted server, holdout target or fix check uses any more (responder Dockerfiles, compose services, lifecycle modules, registry entries), after checking every reference with a search. apify's fix check keeps `evals/apify_backend.py` and `Dockerfile.apify-responder` (its module imports them, and the section retains agent b's versions for it). contextforge's module builds its own fixture, so `evals/contextforge_backend.py`, `Dockerfile.contextforge-responder` and its compose service go. `evals/mysql_backend.py` goes (the Doris builder pins its own `mysql:8.0.46`).
- **Fix checks**: a server whose flaw runs its own fix check keeps or replaces its module under `evals/nuisance_fix_checks/` as the section says, and its fix check runs green under `uv run python -m evals.run_nuisance calibrate --cve <ID>` before its commit, its recorded `fix_check` matching what the calibration prints. A copied holdout calibration keeps its copied fields and records no fingerprint (decision 5).
- **Log lines**: each log line the section lists, written in English in the log's style, in one `docs/nuisance-log.md` entry per server dated 2026-11-08: what the re-admission changed and why, each settlement, each departure from the rule's letter the maintainer accepted (a release, a bound, a seed), and each tool left out under decision 2 or 4. adb-mcp's line saying `adb_shell` comes back into CVE-2025-59834 with a declared function that is the effect is not written: decision 1 keeps it out of `tools`.
- **Tests that pin the fixtures that change**, rewritten in the commit that changes the fixture (test-first: the new pin red before the fixture moves):
  - mysql: `tests/unit/test_backend_hostnames.py` (the benign `db_endpoint` at the engine's alias, the run image's moto `AWS_ENDPOINT_URL`) and `tests/unit/test_backend_lifecycle.py` (the MySQL engine and moto stub argv). They go with the backend. The benign `db_endpoint` becomes `127.0.0.1`.
  - contextforge and ckan: `tests/unit/test_nuisance_backends.py` (the baked `GW_BENIGN_URL` and the global responder address of contextforge, ckan's `--add-host` aliases with `NODE_TLS_REJECT_UNAUTHORIZED=0`). The contextforge pins go. The ckan pin follows the new lifecycle: front names at the front's address, `data.europa.eu` at its stand-in, trust through `NODE_EXTRA_CA_CERTS` and the mounted authority, no `NODE_TLS_REJECT_UNAUTHORIZED`.
  - Imports of `CKAN_RESPONDER_IMAGE`, which the new CKAN lifecycle no longer defines: `test_nuisance_calibrate_command.py`, `test_nuisance_gate_sweep.py`, `test_nuisance_backends_built.py` (whose expected built tags become the stack's). These read the registry entry instead.
  - `BACKENDS["apify"]`, gone from the registry: `tests/unit/support/test_responder_fix_checks_given.py` (apify's bridge and responder image, read from `evals/apify_backend.py` instead) and `tests/unit/support/test_nuisance_run_backends_given.py` (`APIFY_TAG`, moved to a backend that stays).
  - `tests/unit/test_apify_backend.py` follows agent b's `evals/apify_backend.py`.
  - The new CKAN and n8n lifecycles get argv tests in the style of `test_nuisance_backends.py`.
- **Check before the commit**: `uv run python -m evals.run_nuisance vet --server <package>` reports the server answering its benign calls, and `load_admission` accepts the file.

### 4. The departures

heim, wireshark, gemini-bridge and claude-in-mobile leave the admission: their entries go from `evals/nuisance_admission.json`, and so do their Dockerfiles, compose services, fix-check modules (gemini-bridge's and claude-in-mobile's, also unregistered from `evals/nuisance_fixtures.py`) and backends when no other admitted server or holdout target uses them (search every reference first, a holdout twin keeps its own files: heim, wireshark and claude-in-mobile have one). healthomics never entered. One `docs/nuisance-log.md` entry records the five, each with its reason as the manifest gives it, in plain words: heim's software is not distributed, wireshark's capability cannot be repaired under the confinement, gemini-bridge's positive control cannot surface its witness without a stand-in that relays the flaw's effect, claude-in-mobile's tools all declare the effect (a dispatcher declares the union of what it dispatches to), healthomics reads a directory an argument names, which is no root the server declares.

### 5. Living docs

In the commits that make each change:

- `CONTRIBUTING.md`: the admitted-server count ("Fifty-nine servers", 55 after this part), the backend keys listed under `--backend`, and the pulled backends of the run paragraph, which no longer include the `mysql` backend's engine and moto stub.
- `CLAUDE.md`: the `generate.sh` line ("one leaf per HTTPS stand-in host"), if the authority now also signs for a backend-served name or an HTTP-only capture host.
- `CHANGELOG.md` `[Unreleased]`: the entry on the v4 fields ("the count still reading the flaw's record") and the one on the raw-count split ("read from the flaw's record") say the count reads the per-tool field, falling back to the flaw's. The admitted-server count of the admission entry becomes 55.
- The docstring of `evals/nuisance_run_containers.py`, which names the `mysql` backend among the pulled ones.

## What stays unchanged

- sf-mcp and doris, whose holdout twins must be recalibrated with a shared file: a later piece of work.
- The servers of lots L4 to L6 and the first admissions, other than the departures above.
- Every `holdout_fingerprint`, and the copied fields of every holdout calibration copy.
- `docs/nuisance-rule.md`, `docs/holdout-rule.md`, every ADR, every holdout fixture other than the authority copy in the two CVE-2026-5323 Dockerfiles.
- `adb_shell`'s exclusion in data.

## Edge cases

- A server whose counted tools change with the counter alone (change 1) but whose section gives the same list: no extra settlement, the log entry of change 1 names it.
- A tool both records count but the section leaves out (decision 2 or 4): left out of `tools`, its omission logged, its agreement recorded as it was.
- A benign call refused by `load_admission` (a duplicate call, an `expect` contained in a prerequisite's arguments): the section's recommendation fixes it. If none does, the implementer stops and reports.
- A fix check the implementer cannot run green on the retained fixture: stop and report the server, never record a `fix_check` that no calibration printed.
- A removal that a holdout target still references: keep the file.

## Verification

```bash
uv run pytest tests/unit -n auto --maxprocesses 6
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
uv run python -m evals.run_nuisance calibrate --cve <ID>   # every flaw whose fix check runs its own module in this part
uv run python -m evals.run_holdout calibrate --cve CVE-2026-5323
uv run python -m evals.run_nuisance vet
```

`vet` at the end reports every admitted server answering its benign calls, and how many fields rule v3 or v4 adds are still unrecorded: only the `holdout_fingerprint` of copies and the fields of servers outside this part. The image builds and pulls these commands make are authorized. The implementer prunes nothing and removes no image, cleanup stays with the maintainer.

## Due diligence record

What the plan's due-diligence pass concluded about the external facts this plan cites or defers, read by the implementation-phase fact check. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes its line rather than updating it.

- SETTLED: `CKAN 2.12.1` (verified against the ckan/ckan GitHub releases, tag `ckan-2.12.1` of 28 Oct 2026, marked latest)
- SETTLED: `n8n 2.46.6` (verified against the n8n-io/n8n GitHub releases, `n8n@2.46.6` of 2026-11-04, marked latest)
- SETTLED: `2.47.4` as the patched version of n8n-mcp for CVE-2026-39974 (verified against OSV, alias GHSA-4ggg-h7ph-26qr, fixed at 2.47.4)
- SETTLED: `2.47.14` as the patched version of n8n-mcp for CVE-2026-42449 (verified against OSV, alias GHSA-56c3-vfp2-5qqj, affected 2.47.4 to 2.47.13)
- SETTLED: ExifTool `13.55` (verified against the exiftool.org version history, 2026-04-07, the most recent production release, later numbers being development releases)
- SETTLED: `ADD --checksum=sha256:<hex> <URL>` (verified against the Dockerfile reference on docs.docker.com, sha256 the only algorithm for HTTP sources)
- SETTLED: `COPY --from=<image>@sha256:<digest>` and `COPY --from=<stage>` (verified against the Dockerfile reference, which documents an image or a build stage as the source, and the uv Docker guide, which pins `COPY --from` by digest; Docker's own reference does not spell out the digest form)
- SETTLED: `mysql:8.0.46` pinned by the Doris builder (verified against Docker Hub, tag 8.0.46, digest matching the one in `evals/doris_backend.py`)
- OPEN (deferred): CVE-2026-10690 on desktop-commander's `read_file`, whether a release fixes it, decision 4 leaves it to the implementer; NVD and OSV list 0.2.37 as affected and OSV names a fix commit but no release.
- OPEN (deferred): every per-server value the plan carries from the external manifest (releases, image digests, seeds, captures, patched versions other than n8n-mcp's two above, the agents' models), not in the plan and not checked by this pass.
- OPEN (unverified): the ckan-docker stack building CKAN 2.12.1 with five `ckan-*` services, the ckan-docker repository page states no default CKAN version, the retained fixture pins it.
- OPEN (deferred): praisonai's `mcp<2` bound, kept or dropped on the outcome of a build without it at implementation.

## Implementation steps

### Conventions for every step

- **Commands.** The short loop is `uv run pytest tests/unit -n auto --maxprocesses 6`, with `uv run pytest <test files> -n 0` while a test being written is red and `--lf` on a failing loop, then the full short loop again. Type-check changed files with `uv run pyright <files>` in the loop. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .` and `uv run pyright` with no file argument, all green.
- **Docker.** The builds and pulls `run_nuisance calibrate`, `run_nuisance vet`, `run_holdout calibrate --cve CVE-2026-5323` and `docker compose ... build` make are authorized. Prune nothing, remove no image and make the Docker disk use grow no more than these commands need: cleanup stays with the maintainer.
- **External material.** Steps 4 to 27 read the vesting manifest, the maintainer's decision log, the two agents' records and the proposed fixtures, held outside the repository at the location the maintainer gives at launch. Where a manifest section and the decision log differ, the decision log wins. Where a section leaves a point open, its recommendation applies unless a decision of this plan says otherwise. Nothing from outside the repository is named in a committed file: no path, no campaign label, no file name of the external material.
- **Server steps (4 to 26) follow change 3 in full.** One commit per server. In order:
  1. Read the server's manifest section and the decision log lines on it, then its current admission entry, run Dockerfile `evals/docker/Dockerfile.<service>`, fix-check module(s) under `evals/nuisance_fix_checks/` and any holdout twin it copies.
  2. Write first the tests whose pins the section changes (red), then move the fixture.
  3. Copy each retained fixture file to its repository path, with the section's repairs. A copied Python module meets the coding standards (function and file length, few arguments, newspaper order, names), refactored with no change to what it launches. A heredoc line reading `from x import y` is rewritten (`import x`, then `x.y`) so `test_every_base_image_is_pinned_by_digest` passes, with no change to what the image builds. A Dockerfile under `evals/docker/` that has a compose service gets its fingerprint label updated in `evals/docker/compose.yml` (`tests/unit/test_cve_compose_labels.py` prints the value), a new compose service carries the labels and `nuisance` profile its neighbours carry, and a fix-check image (`-vuln`, `-patched`, `-flaw-*`) gets no compose service. A capture keeps its `source` (`capture` or `software_sources`, a documentation-written route split into its own file).
  4. Rewrite the server's entry in `evals/nuisance_admission.json` as change 3's first bullet says: the flaws and their tools (counted tools plus the tools kept out with `real_software.answers` false or `declared_function_is_effect` true, never a tool left out under decision 1, 2 or 4 or one carrying an overlapping open flaw), each tool's `real_software` and `declared_function_is_effect`, benign calls with `expect` and `before`, `relies_on_relaying_stand_in`, `effect_class`, `backend_need`, `patched_version`, `patched_source`, `host`, `launch`, `service`, `backend`, `stand_ins`, `seeds`, `software_releases`. `agents` keeps its entries and gains the two re-admission agents (`role` `admitter`, `scope` `re-admission record A` / `re-admission record B`, the launch model, `fallback_model` when the provider answered with another), plus one entry per voided agent with `set_aside` giving the cause in plain words. `agreement` and `settlements` are replaced by the re-admission's, each settlement's reason stating the rule or the reading it applies in plain words.
  5. A copied holdout calibration keeps its copied fields and records no `holdout_fingerprint` (decision 5). A flaw running its own fix check: `uv run python -m evals.run_nuisance calibrate --cve <ID>` green, the recorded `fix_check` matching what it prints. A fix check that cannot run green on the retained fixture: stop and report the server, never record a `fix_check` no calibration printed. A benign call `load_admission` refuses that the section's recommendation does not fix: stop and report.
  6. One `docs/nuisance-log.md` entry dated 2026-11-08 for the server, in English in the log's style: what the re-admission changed and why, each settlement, each accepted departure from the rule's letter (a release, a bound, a seed), each tool left out under decision 2 or 4.
  7. `uv run python -m evals.run_nuisance vet --server <package>` reports the server answering its benign calls, and `tests/unit/test_nuisance_admission_loads.py` passes on the committed file.
- **Stand-in regeneration** (the server steps marked so): add the server's captures, then run `evals/stand_ins/tls/generate.sh` with every host of `evals/stand_ins/*.json` plus every TLS name a registered backend serves from a fixture leaf (the set step 3's helper computes, printed with a one-line `uv run python -c` on that helper), copy the new `evals/stand_ins/tls/fixture-authority.pem` into `evals/docker/Dockerfile.holdout-2026-5323-a11y` and `-patched`, and update both fingerprint labels in `evals/docker/compose.yml`. Then check with `evals.nuisance_fingerprint.nuisance_fixture_fingerprint`, before and after, which admitted servers' fixture fingerprints move: a server outside this part that moves gets a `docs/nuisance-log.md` line with both values. The CVE-2026-5323 images are rebuilt and calibrated once, in step 27.

### Step 1: The counter reads the declared function per tool

- **Files**: `tests/unit/test_nuisance_counting.py`, `tests/unit/support/test_nuisance_counting_given.py`, `evals/nuisance_counting.py`, `evals/nuisance_admission.py`, `evals/nuisance_dossier.py`, `CHANGELOG.md`, `docs/nuisance-log.md`.
- **Do**:
  1. Tests first. Rename and invert `test_a_tool_recorded_as_its_effect_under_a_flaw_recorded_otherwise_stays_counted`: the tool is no longer counted and is a declared-function tool. Run it red first. Add the cases below, extending the given helpers only where a helper abstracts something (a flaw with per-tool values, for instance).
  2. In `evals/nuisance_counting.py`, a tool's effective declared function is its own `ToolRecord.declared_function_is_effect` when not `None`, the flaw's `FlawRecord.declared_function_is_effect` otherwise. `flaw_counted_tools(flaw)` returns the reachable tools (`_reachable_tools`) whose effective value is false. `declared_function_tools(server)` returns, over `counted_flaws(server)`, the reachable tools whose effective value is true, through `_categories_per_tool` as today. The module docstring says the declared function is read per tool, falling back to the flaw's record.
  3. The comment on `ToolRecord.declared_function_is_effect` (`evals/nuisance_admission.py`, line 38) and the dossier paragraph of `evals/nuisance_dossier.py` (lines 206 to 210, "is the record the count reads until the per-tool one supersedes it") say the counter reads the per-tool field and falls back to the flaw's. If a dossier test pins that text, follow it.
  4. `CHANGELOG.md` `[Unreleased]`: the v4-fields entry ("the count still reading the flaw's record") and the raw-count split entry ("read from the flaw's record") say the count reads the per-tool field, falling back to the flaw's.
  5. List the servers whose counted tools move: compute `counted_tools` and `declared_function_tools` for every server of `evals/nuisance_admission.json` before and after the change (a throwaway script in the scratchpad, not committed). Expected: none, no committed tool recording the field.
  6. One `docs/nuisance-log.md` entry dated 2026-11-08: the counter reads the declared function per tool, falling back to the flaw's record. It names the servers whose count moves (expected: none, so the change moves no count until a re-admission records the per-tool field). The counter fingerprint (`evals.nuisance_counter.counter_fingerprint`, which hashes `nuisance_counting.py`) moves, and no nuisance gate baseline is committed (`evals/baselines/nuisance/` absent), so nothing resets.
- **Test**:
  - one tool recording true and one recording false under a flaw recording false: the counted tools are the second only, the declared-function tools the first only.
  - a tool recording `None` follows the flaw's value, true and false.
  - a flaw recording true whose tools all record false: all its tools are counted, none is a declared-function tool.
  - a removed tool recording true or false is never counted and never a declared-function tool.
  - the inverted test above.
- **Verify**: the counting tests red then green, short loop green, then the closing checks.

### Step 2: A copy from an image pinned by digest passes, and the compose test reads `unsourced_copies`

- **Files**: `tests/unit/test_fixture_sources.py`, `evals/fixture_sources.py`, `tests/unit/test_cve_compose_labels.py`.
- **Do**:
  1. Tests first in `tests/unit/test_fixture_sources.py`: `COPY --from=<image>:<tag>@sha256:<64 hex>` passes, `COPY --from=<stage>` passes when an earlier `FROM ... AS <stage>` of the same instructions names it, `COPY --from=<image>:<tag>` (no digest) and `COPY --from=<name>` with no earlier stage of that name are refused. The existing passing case `["COPY --from=build /app /app"]` gets its `FROM ... AS build` line.
  2. `unsourced_copies` tracks the stage names declared by `FROM ... AS <name>` (case-insensitive `AS`) in the joined instructions, and refuses a `COPY --from=<source>` whose source is neither an earlier stage nor an image reference pinned `@sha256:<64 hex>`. The rest is unchanged. Keep functions under 20 lines, extracting a small helper where needed.
  3. `test_no_dockerfile_copies_from_the_build_context` asserts `unsourced_copies(dockerfile_instructions(dockerfile)) == []` instead of refusing every `COPY` and `ADD`, its message unchanged in spirit (the fingerprint would miss the copied source).
- **Test**: the four `COPY --from` cases above, the existing cases of the file unchanged and green, every committed Dockerfile still passing the narrowed test (none copies today).
- **Verify**: the new fixture-source tests red then green, `uv run pytest tests/unit/test_fixture_sources.py tests/unit/test_cve_compose_labels.py -n 0`, short loop, closing checks.

### Step 3: The stand-in tests compare the authority to the captured hosts and the backend-served TLS names

- **Files**: `tests/unit/support/test_committed_stand_ins_given.py`, `tests/unit/test_committed_stand_ins.py`, `tests/unit/support/test_committed_stand_ins_then.py` (only if a then helper's name says "https"), `CLAUDE.md`, `evals/stand_ins/tls/generate.sh` (header comment), `evals/public_stand_ins.py` (docstring, only if it says HTTPS hosts).
- **Do**:
  1. `declared_stand_in_hosts()` returns the hosts the CVE and holdout targets declare, plus the `host.public_names.stand_ins` of every server of the committed admission (loaded as the other committed-admission tests load it, `tests/unit/support/test_nuisance_committed_admission_given.py`), plus the hosts whose capture a registered backend serves (the `evals/stand_ins/*.json` paths among `BACKENDS[*].served` of `evals/nuisance_backends.py`). The `API_HOST` import goes, apify's capture being found through its backend's `served`.
  2. Replace `committed_https_hosts` with a helper named after the new set, say `authority_hosts(directory)`: every host with a capture in `directory`, plus every name a registered backend serves under TLS from a fixture leaf (the leaf paths under `evals/stand_ins/tls/` among `BACKENDS[*].served`, the authority and keys excluded). Rename `test_the_committed_authority_signs_for_exactly_the_https_stand_in_hosts` and `test_every_committed_leaf_names_an_https_stand_in_host` after it (for instance `..._signs_for_exactly_the_stand_in_hosts`, `..._names_a_stand_in_host`), and the IP-literal test's helper call with them. `test_every_committed_capture_loads_with_its_leaf` is unchanged.
  3. Check that `generate.sh` is not among any fingerprinted file (search `evals/` for what hashes `stand_ins/tls`): if it is not, its header says it makes one leaf per host given, every captured stand-in host and every name a backend serves from a fixture leaf, given at once. If it is, leave it.
  4. `CLAUDE.md`, the `generate.sh` line: "one leaf per stand-in host" and "give it every stand-in host at once (every captured host, an HTTP-only one included, and every name a backend serves from a fixture leaf)". The `evals/public_stand_ins.py` docstring follows if it says HTTPS hosts.
- **Test**: the renamed tests pass on the committed files, with the same host set as before (every committed capture has an https route today, and apify's served leaf is `api.apify.com`, a captured host). No new test case: the change re-reads the set from the code.
- **Verify**: `uv run pytest tests/unit/test_committed_stand_ins.py -n 0`, short loop, closing checks. No fingerprint moves (only tests and docs change).

### Step 4: maigret (`npm:mcp-maigret`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.maigret`, `evals/docker/compose.yml`, `docs/nuisance-log.md`, plus any file the section retains.
- **Do**: the server-step conventions. CVE-2026-2130 is a copied holdout calibration. The retained Dockerfile has a heredoc `from ... import` line to rewrite. Agent a was redone alone: its voided first run gets its own `agents` entry with `set_aside`.
- **Test**: no test pins this server.
- **Verify**: `uv run python -m evals.run_nuisance vet --server npm:mcp-maigret`, short loop, closing checks.

### Step 5: mysql (`PyPI:awslabs-mysql-mcp-server`), its backend leaves

- **Files**: `tests/unit/test_backend_hostnames.py`, `tests/unit/test_backend_lifecycle.py`, `evals/nuisance_admission.json`, `evals/docker/Dockerfile.mysql`, `evals/docker/compose.yml`, `evals/nuisance_backends.py`, `evals/mysql_backend.py` (removed), `evals/nuisance_run_containers.py` (docstring), `CONTRIBUTING.md`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions. The engine runs in the server's image as its holdout twin's does: `backend` goes to `null`, `host.has_network` to false, `baked_work` false, the benign `db_endpoint` becomes `127.0.0.1`. CVE-2026-85788 stays a copied holdout calibration. Remove the `"mysql"` registry entry, its imports and `evals/mysql_backend.py` after searching every reference (`tests/unit/test_cve_launches.py`, `tests/unit/support/test_nuisance_benign_call_given.py` and `tests/integration/test_nuisance_doris_backend.py` mention mysql: keep what concerns Doris's own `mysql:8.0.46`). The mysql pins of `test_backend_hostnames.py` (the benign `db_endpoint` at the engine alias, the run image's moto `AWS_ENDPOINT_URL`) and of `test_backend_lifecycle.py` (MySQL engine and moto stub argv) go with the backend, the files kept if other backends' tests remain in them. Docs: `CONTRIBUTING.md` drops `mysql` from the `--backend` list and "the `mysql` backend's engine and moto stub" from the pulled backends of the run paragraph, and the `evals/nuisance_run_containers.py` docstring drops the `mysql` backend from the pulled ones.
- **Test**: the remaining backend-hostname and lifecycle tests pass, the committed admission loads (`_network_problems` accepts no network without a backend).
- **Verify**: `uv run python -m evals.run_nuisance vet --server PyPI:awslabs-mysql-mcp-server`, short loop, closing checks.

### Step 6: praisonai (`PyPI:praisonai`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.praisonai`, `-vuln`, `-flaw-4.6.34` (as retained), `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2026_47394_praisonai.py`, `cve_2026_44336_praisonai.py`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions. Two counted tools. The two `validate` tools are left out of `tools` (decision 2), logged. The `mcp<2` bound stays only if a build without it fails: build the run image without it first, and if it fails keep the bound and record the failing run (the error and the command) in the log entry; otherwise drop it and log that the documented install starts.
- **Test**: no unit test pins this server beyond the walk test, which must stay green.
- **Verify**: `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-47394` and `--cve CVE-2026-44336` (or the flaws the section keeps) green and matching, `vet --server PyPI:praisonai`, short loop, closing checks.

### Step 7: adb-mcp (`npm:adb-mcp`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.adb-mcp`, `Dockerfile.adb-mcp-vuln`, `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2025_59834_adb_mcp.py`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions. `adb_push` stays in `tools` with `real_software.answers` false. `inspect_ui` and `dump_image` are left out (decision 2), logged. `adb_shell` stays out of `tools` (decision 1), and the section's log line saying it comes back is not written. Both Dockerfiles use `ADD --checksum` / `COPY --from=<image@digest>`, which pass since step 2.
- **Test**: the compose-label tests pass on both Dockerfiles.
- **Verify**: `calibrate --cve CVE-2025-59834` green and matching, `vet --server npm:adb-mcp`, short loop, closing checks.

### Step 8: nmap (`npm:mcp-nmap-server`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.nmap`, `evals/docker/compose.yml`, `docs/nuisance-log.md`, plus any file the section retains.
- **Do**: the server-step conventions. CVE-2026-3484 is a copied holdout calibration. Agent a was redone alone: its voided run gets its `set_aside` entry.
- **Test**: none pins this server.
- **Verify**: `vet --server npm:mcp-nmap-server`, short loop, closing checks.

### Step 9: android (`https://github.com/jiantao88/android-mcp-server`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.android`, `evals/docker/compose.yml`, `docs/nuisance-log.md`, plus any file the section retains.
- **Do**: the server-step conventions. CVE-2026-19978 is a copied holdout calibration. `monitor-events` stays in `tools` with `real_software.answers` false. Agent a was redone alone: its voided run gets its `set_aside` entry.
- **Test**: none pins this server.
- **Verify**: `vet --server https://github.com/jiantao88/android-mcp-server`, short loop, closing checks.

### Step 10: desktop-commander (`npm:@wonderwhy-er/desktop-commander`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.desktop-commander`, `evals/docker/compose.yml`, `docs/nuisance-log.md`, plus any file the section retains.
- **Do**: the server-step conventions. CVE-2025-11489 is a copied holdout calibration. Decision 4: read CVE-2026-10690 in `evals/holdout_census.json` and its advisory (NVD, OSV, the GitHub advisory and the project's releases). If no release fixes it and its effect overlaps the judge categories `read_file` is counted under (`cve_grammar.VALID_CATEGORIES` of the counted class), `read_file` leaves `tools` and the count is 9. Otherwise it stays and the count is 10. Either way the log entry states the reading, the sources consulted and the count.
- **Test**: none pins this server.
- **Verify**: `vet --server npm:@wonderwhy-er/desktop-commander`, short loop, closing checks.

### Step 11: taskwarrior (`npm:mcp-server-taskwarrior`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.taskwarrior`, `evals/docker/compose.yml`, `docs/nuisance-log.md`, plus any file the section retains.
- **Do**: the server-step conventions. CVE-2026-5833 is a copied holdout calibration. Agent a was redone alone: its voided run gets its `set_aside` entry.
- **Test**: none pins this server.
- **Verify**: `vet --server npm:mcp-server-taskwarrior`, short loop, closing checks.

### Step 12: siri-shortcuts (`npm:mcp-server-siri-shortcuts`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.siri-shortcuts`, `-vuln`, `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2026_0758_siri_shortcuts.py`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions.
- **Test**: none pins this server.
- **Verify**: `calibrate --cve CVE-2026-0758` green and matching, `vet --server npm:mcp-server-siri-shortcuts`, short loop, closing checks.

### Step 13: ios-simulator (`npm:ios-simulator-mcp`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.ios-simulator`, `-vuln`, `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2025_52573_ios_simulator.py`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions. Both Dockerfiles have a heredoc `from ... import` line to rewrite and use `ADD --checksum` / `COPY --from=<image@digest>` (passing since step 2). Agent a was redone alone: its voided run gets its `set_aside` entry.
- **Test**: the compose-label tests pass on both Dockerfiles.
- **Verify**: `calibrate --cve CVE-2025-52573` green and matching, `vet --server npm:ios-simulator-mcp`, short loop, closing checks.

### Step 14: markdownify (`npm:mcp-markdownify-server`), first stand-in regeneration

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.markdownify`, `evals/docker/compose.yml`, `evals/stand_ins/www.google.com.json` (new, HTTP-only), `evals/stand_ins/tls/` (regenerated), `evals/docker/Dockerfile.holdout-2026-5323-a11y`, `-patched`, `docs/nuisance-log.md`, `docs/holdout-log.md`.
- **Do**: the server-step conventions and the stand-in regeneration. Agent a's seed and ExifTool 13.55. The three URL tools, which also carry an open flaw whose categories overlap, are not listed in `tools`, logged. The Dockerfile uses `ADD --checksum` / `COPY --from=<image@digest>` (passing since step 2). `www.google.com` is declared as the section declares it (`host.public_names.stand_ins`), so the step-3 tests see it declared, and gets a leaf though its capture has only `http` routes. Write the one `docs/holdout-log.md` entry of change 2 here: the authority is regenerated with the nuisance hosts this part adds, moving the fixture fingerprint of the holdout targets whose hosts declare stand-ins with no fixture of theirs changed, and that of the CVE acceptance target CVE-2025-65513 (`example.com`). Check `evals/baselines/cve/` is still absent: if a baseline exists, stop and report (the regeneration would be a fixture change under ADR 016 needing its own reset commit).
- **Test**: `tests/unit/test_committed_stand_ins.py`, `tests/unit/test_public_stand_ins.py` and `tests/unit/test_holdout_targets.py` (the stale-PEM check) pass.
- **Verify**: the flaws the section gives a fix-check module of their own calibrate green (`calibrate --cve <ID>`), `vet --server npm:mcp-markdownify-server`, short loop, closing checks.

### Step 15: godot-mcp (`npm:@coding-solo/godot-mcp`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.godot-mcp`, `evals/docker/compose.yml`, `docs/nuisance-log.md`, plus any file the section retains.
- **Do**: the server-step conventions. CVE-2026-25546 is a copied holdout calibration.
- **Test**: none pins this server.
- **Verify**: `vet --server npm:@coding-solo/godot-mcp`, short loop, closing checks.

### Step 16: biome (`https://github.com/RyuzakiShinji/biome-mcp-server`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.biome`, `evals/docker/compose.yml`, `docs/nuisance-log.md`, plus any file the section retains.
- **Do**: the server-step conventions, with agent a's fixture. CVE-2026-3680 is a copied holdout calibration.
- **Test**: none pins this server.
- **Verify**: `vet --server https://github.com/RyuzakiShinji/biome-mcp-server`, short loop, closing checks.

### Step 17: magento2 (`npm:@elgentos/magento2-dev-mcp`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.magento2`, `evals/docker/compose.yml`, `docs/nuisance-log.md`, plus any file the section retains.
- **Do**: the server-step conventions. CVE-2026-5603 is a copied holdout calibration. Its two `software_error` tools stay in `tools` with `real_software.answers` false, `db-query` with `declared_function_is_effect` true. `backend_need` goes to `fixture`.
- **Test**: none pins this server.
- **Verify**: `vet --server npm:@elgentos/magento2-dev-mcp`, short loop, closing checks.

### Step 18: serverless (`npm:serverless`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.serverless`, `-vuln`, `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2025_69256_serverless.py`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions. The run Dockerfile uses `ADD --checksum` / `COPY --from=<image@digest>` (passing since step 2).
- **Test**: the compose-label tests pass.
- **Verify**: `calibrate --cve CVE-2025-69256` green and matching, `vet --server npm:serverless`, short loop, closing checks.

### Step 19: semgrep (`npm:mcp-server-semgrep`), stand-in regeneration

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.semgrep`, `-vuln`, `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2026_7446_semgrep.py`, its capture(s) under `evals/stand_ins/`, `evals/stand_ins/tls/`, the two CVE-2026-5323 Dockerfiles, `docs/nuisance-log.md`.
- **Do**: the server-step conventions and the stand-in regeneration. Agent a's install channel, logged. Both Dockerfiles use `ADD --checksum` / `COPY --from=<image@digest>` (passing since step 2). The stand-in host goes in `host.public_names.stand_ins`.
- **Test**: the stand-in tests, the holdout stale-PEM test and the compose-label tests pass.
- **Verify**: `calibrate --cve CVE-2026-7446` green and matching, `vet --server npm:mcp-server-semgrep`, short loop, closing checks.

### Step 20: node-sandbox (`npm:node-code-sandbox-mcp`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.node-sandbox`, `-vuln`, `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2025_53372_node_sandbox.py`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions. Its three tools whose declared function is the effect stay in `tools` with `declared_function_is_effect` true, so step 1's counter leaves them out.
- **Test**: none pins this server.
- **Verify**: `calibrate --cve CVE-2025-53372` green and matching, `vet --server npm:node-code-sandbox-mcp`, short loop, closing checks.

### Step 21: codehooks (`https://github.com/RestDB/codehooks-mcp-server`), stand-in regeneration

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.codehooks`, `-vuln`, `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2025_53100_codehooks.py`, its capture(s) under `evals/stand_ins/`, `evals/stand_ins/tls/`, the two CVE-2026-5323 Dockerfiles, `docs/nuisance-log.md`.
- **Do**: the server-step conventions and the stand-in regeneration. `deploy_code` stays in `tools` with `declared_function_is_effect` true. `backend_need` goes to `fixture`. The stand-in host goes in `host.public_names.stand_ins`.
- **Test**: the stand-in tests and the holdout stale-PEM test pass.
- **Verify**: `calibrate --cve CVE-2025-53100` green and matching, `vet --server https://github.com/RestDB/codehooks-mcp-server`, short loop, closing checks.

### Step 22: ckan (`npm:@aborruso/ckan-mcp-server`), the real CKAN backend, stand-in regeneration

- **Files**: tests first: `tests/unit/test_nuisance_backends.py`, `tests/unit/test_nuisance_calibrate_command.py` and its given, `tests/unit/test_nuisance_gate_sweep.py`, `tests/unit/test_nuisance_backends_built.py`, and any of `tests/unit/test_nuisance_vet.py`, `tests/unit/test_nuisance_run_backends.py` and its given, `tests/unit/support/test_nuisance_admission_edits_given.py` that imports from `evals/ckan_backend.py`. Then `evals/ckan_backend.py` (replaced by the retained lifecycle), `evals/nuisance_backends.py`, the CKAN stack Dockerfiles under `evals/docker/`, `evals/docker/compose.yml`, `evals/docker/Dockerfile.ckan`, `-vuln`, `evals/nuisance_fix_checks/cve_2026_73844_ckan.py`, `cve_2026_73845_ckan.py`, the `data.europa.eu` capture, `evals/stand_ins/tls/` (with the `www.dati.gov.it` leaf), the two CVE-2026-5323 Dockerfiles, `evals/nuisance_admission.json`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions and the stand-in regeneration.
  1. Tests first: the ckan pin of `test_nuisance_backends.py` follows the new lifecycle (front names at the front's address, `data.europa.eu` at its stand-in, trust through `NODE_EXTRA_CA_CERTS` and the mounted authority, no `NODE_TLS_REJECT_UNAUTHORIZED`). The imports of `CKAN_RESPONDER_IMAGE` read `BACKENDS["ckan"]` instead, and the expected built tags of `test_nuisance_backends_built.py` become the stack's. Argv tests for the new lifecycle in the style of `test_nuisance_backends.py`.
  2. The retained lifecycle (CKAN 2.12.1 in the ckan-docker stack) replaces `evals/ckan_backend.py`, refactored to the coding standards. The `"ckan"` entry of `BACKENDS` is a `RegisteredBackend` built directly: `built_services` names CKAN's five `ckan-*` compose services and the stand-in service for `data.europa.eu`, each nuisance-profiled (`tests/unit/test_nuisance_compose.py`), and `served` holds the lifecycle module, `closed_network`, those Dockerfiles and the captures, leaves (`www.dati.gov.it`, `demo.ckan.org`, `data.europa.eu`) and authority the lifecycle mounts, as apify's entry does. `backend.image` in the admission is the entry's `image`.
  3. `host.public_names` is emptied. The `server_url` tools stay in `tools` with `declared_function_is_effect` true.
  4. Remove `Dockerfile.ckan-responder` and its compose service once a search shows no admitted server, holdout target or fix check uses them (the holdout CKAN twin keeps its own files). `evals/responder_backend.py` stays while another responder uses it.
  5. The regeneration takes `www.dati.gov.it` as a backend-served TLS name with no capture, which step 3's `authority_hosts` reads from the entry's `served`.
- **Test**: the new and rewritten backend tests above, the stand-in tests (authority set now including `www.dati.gov.it` and `data.europa.eu`), the holdout stale-PEM test, the nuisance-compose test.
- **Verify**: the backend tests red then green, `calibrate --cve CVE-2026-73844` and `--cve CVE-2026-73845` (or the flaws the section keeps) green and matching, `vet --server npm:@aborruso/ckan-mcp-server`, short loop, closing checks.

### Step 23: contextforge gateway (`PyPI:mcp-contextforge-gateway`), its backend leaves, stand-in regeneration

- **Files**: `tests/unit/test_nuisance_backends.py`, `evals/nuisance_admission.json`, `evals/docker/Dockerfile.contextforge`, `-vuln`, `Dockerfile.contextforge-patched` (new fix-check image, no compose service), `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2026_18905_contextforge.py`, `evals/nuisance_backends.py`, `evals/contextforge_backend.py` and `Dockerfile.contextforge-responder` (removed), the `httpbin.org` capture, `evals/stand_ins/tls/`, the two CVE-2026-5323 Dockerfiles, `CONTRIBUTING.md`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions and the stand-in regeneration. Agent a's fixture with agent b's split of the fix-check-only plumbing into `Dockerfile.contextforge-patched`. `backend` goes to `null`, `host.has_network` to false, and `httpbin.org` is served under its real name through the holder (`host.public_names.stand_ins`). The fix-check module builds its own fixture. Remove the `"contextforge"` registry entry and its imports, `evals/contextforge_backend.py`, `Dockerfile.contextforge-responder` and its compose service after a reference search (the ContextForge sandbox server, `contextforge-sandbox`, is a different server and keeps its files). The contextforge pins of `test_nuisance_backends.py` (baked `GW_BENIGN_URL`, global responder address) go. Check `tests/unit/test_nuisance_dossier.py` and `tests/unit/support/test_nuisance_fix_checks_given.py`, which mention contextforge, and follow them if they read the removed backend. `CONTRIBUTING.md` drops `contextforge` from the `--backend` list.
- **Test**: the remaining backend tests, the stand-in tests, the holdout stale-PEM test.
- **Verify**: `calibrate --cve CVE-2026-18905` green and matching, `vet --server PyPI:mcp-contextforge-gateway`, short loop, closing checks.

### Step 24: n8n (`npm:n8n-mcp`), the real n8n backend

- **Files**: tests first: `tests/unit/test_nuisance_backends.py` (new n8n lifecycle argv tests), `tests/unit/test_n8n_fix_check_builder.py` if it reads the responder. Then `evals/n8n_backend.py` (replaced by the retained lifecycle), `evals/nuisance_backends.py`, the n8n instance Dockerfile and compose service, `evals/docker/Dockerfile.n8n`, `-vuln`, `-flaw-2.50.1` (as retained), `evals/nuisance_fix_checks/ghsa_8g7g_hmwm_6rv2_n8n.py`, `cve_2026_44694_n8n.py`, `evals/nuisance_admission.json`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions. The retained lifecycle (n8n 2.46.6) replaces `evals/n8n_backend.py`, refactored to the coding standards, and the `"n8n"` entry is a `RegisteredBackend` built directly, `built_services` naming the instance's nuisance-profiled compose service and `served` the lifecycle module, `closed_network` and its Dockerfiles. `backend.image` is the entry's `image`. `evals/n8n_instance_backend.py` is the holdout's and stays. CVE-2026-39974 and CVE-2026-42449 get `patched_version` 2.47.4 and 2.47.14 from their advisories. Remove `Dockerfile.n8n-responder` and its compose service after a reference search. Agent a was redone alone: its voided run gets its `set_aside` entry.
- **Test**: the new lifecycle argv tests, the n8n fix-check builder test, the nuisance-compose test.
- **Verify**: `calibrate --cve GHSA-8g7g-hmwm-6rv2` and `--cve CVE-2026-44694` (or the flaws the section keeps) green and matching, `vet --server npm:n8n-mcp`, short loop, closing checks.

### Step 25: atlassian (`PyPI:mcp-atlassian`)

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.atlassian`, `-vuln`, `Dockerfile.atlassian-responder`, `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2026_77252_atlassian.py`, `evals/atlassian_backend.py` (if the section retains a version), `tests/unit/test_atlassian_backend.py` (if it follows), `docs/nuisance-log.md`.
- **Do**: the server-step conventions. Agent a's project keys and the documented Jira example for the issue body. `Dockerfile.atlassian-responder` has a heredoc `from ... import` line to rewrite. The `atlassian` backend stays.
- **Test**: the atlassian backend and fix-check resolver tests pass.
- **Verify**: `calibrate --cve CVE-2026-77252` green and matching, `vet --server PyPI:mcp-atlassian`, short loop, closing checks.

### Step 26: apify (`npm:@apify/actors-mcp-server`), its backend leaves, stand-in regeneration

- **Files**: tests first: `tests/unit/test_apify_backend.py`, `tests/unit/support/test_responder_fix_checks_given.py`, `tests/unit/support/test_nuisance_run_backends_given.py`, and any of `tests/unit/test_nuisance_run_backends.py`, `tests/unit/test_nuisance_run_containers.py`, `tests/unit/test_fix_check_resolver.py` that reads `BACKENDS["apify"]`. Then `evals/apify_backend.py` and `evals/docker/Dockerfile.apify-responder` (agent b's versions), `evals/nuisance_backends.py`, `evals/docker/Dockerfile.apify`, `-vuln`, `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2026_46341_apify.py`, apify's second capture, `evals/stand_ins/tls/`, the two CVE-2026-5323 Dockerfiles, `evals/nuisance_admission.json`, `CONTRIBUTING.md`, `docs/nuisance-log.md`.
- **Do**: the server-step conventions and the stand-in regeneration. `backend` goes to `null`, `host.has_network` to false, and the run serves apify's two hosts under their real names through the holder (`host.public_names.stand_ins`). The `"apify"` registry entry and its imports go, while `evals/apify_backend.py` and `Dockerfile.apify-responder` stay for the fix check, at agent b's versions. Tests: `test_apify_backend.py` follows agent b's module, `test_responder_fix_checks_given.py` reads apify's bridge and responder image from `evals/apify_backend.py`, `test_nuisance_run_backends_given.py` moves `APIFY_TAG` to a backend that stays. The step-3 helpers now find apify's hosts through the admission's `public_names`. `CONTRIBUTING.md` drops `apify` from the `--backend` list. Keep the `apify-responder` compose service while anything builds the responder image through compose (check how the fix check and `evals/responder_backend.py` build it), and remove it only when nothing does.
- **Test**: the rewritten apify and responder tests, the stand-in tests, the holdout stale-PEM test.
- **Verify**: the rewritten tests red then green, `calibrate --cve CVE-2026-46341` green and matching, `vet --server npm:@apify/actors-mcp-server`, short loop, closing checks.

### Step 27: The departures and the closing verification

- **Files**: `evals/nuisance_admission.json`, `evals/docker/Dockerfile.heim`, `Dockerfile.wireshark`, `Dockerfile.gemini-bridge`, `-vuln`, `Dockerfile.claude-in-mobile`, `-vuln` (removed), `evals/docker/compose.yml`, `evals/nuisance_fix_checks/cve_2026_54785_gemini_bridge.py`, `cve_2026_81562_claude_in_mobile.py` (removed), `evals/nuisance_fixtures.py`, `CONTRIBUTING.md`, `CHANGELOG.md`, `docs/nuisance-log.md`.
- **Do**:
  1. Remove the entries of `npm:@nor2/heim-mcp`, `https://github.com/A-G-U-P-T-A/wireshark-mcp`, `PyPI:gemini-bridge` and `npm:claude-in-mobile` from `evals/nuisance_admission.json`, their run and fix-check Dockerfiles, compose services and fix-check modules (unregistered from `evals/nuisance_fixtures.py`), each after a reference search. The holdout twins of heim, wireshark and claude-in-mobile (`Dockerfile.holdout-2026-5602-heim`, `-7785-wireshark`, `-81562-claude-in-mobile` and their `-patched`) keep their files, and a removal a holdout target still references is kept.
  2. One `docs/nuisance-log.md` entry dated 2026-11-08 records the five with their reasons in plain words, as change 4 states them (healthomics never entered).
  3. `CONTRIBUTING.md` "Fifty-nine servers" becomes "Fifty-five servers". `CHANGELOG.md` `[Unreleased]`: the admission entry's "fifty-nine servers" becomes "fifty-five".
  4. Closing verification: `docker compose -f evals/docker/compose.yml build holdout-2026-5323-a11y holdout-2026-5323-a11y-patched`, then `uv run python -m evals.run_holdout calibrate --cve CVE-2026-5323` green. Then `uv run python -m evals.run_nuisance vet`: every admitted server answers its benign calls, and the unrecorded count lists only the `holdout_fingerprint` of the copies and the fields of servers outside this part (sf-mcp, doris and the servers a later piece of work re-admits). Report any other gap.
- **Test**: the committed admission loads, and the tests over `evals/nuisance_fixtures.py` and the compose-label tests pass with the files gone.
- **Verify**: short loop, `vet` and the CVE-2026-5323 calibration as above, then the closing checks.
