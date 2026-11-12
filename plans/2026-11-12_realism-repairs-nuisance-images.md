# Realism repairs, second part: the nuisance images of ios-simulator, houtini, memory-keeper, git-mcp, mcp-package-docs, ArcadeDB, MySQL, PostgreSQL and Gravitino

## Context

The first part (`plans/2026-11-12_realism-repairs-holdout-images.md`) corrects records, logs the departures the maintainer keeps and repairs holdout images. This second part repairs nuisance fixtures whose seeds, launch settings or stand-in outputs break a limit of version 6 of the nuisance suite rule, within the bounds its log entry of 2026-11-12 sets (`docs/nuisance-suite-log.md`, which refers to the entry for version 13 in `docs/detection-suite-log.md`). The bounds, the proof rule, the record and log conventions and the Docker disk clause of the first part apply here unchanged, and are not restated beyond what this part needs.

The review's report and the maintainer's rulings are held outside the repository, and the maintainer gives their location to the implementer at launch. Nothing from outside the repository is named in a committed file: no path, no file name, no correction label, no campaign label.

The aim is realism at a cost a project of this size, kept by one person, can carry: each repair does what the bounds and its source call for, and no more. A repair whose cost grows far beyond what it changes for the auditor is stopped and reported, not pursued.

This part starts once the first part is committed: both edit `evals/nuisance_admission.json`, `evals/census.json`, `evals/docker/compose.yml` and the two suite logs.

No step runs an audit or an LLM eval. No holdout run, nuisance run or gate run has taken place, and `evals/baselines/detection/` and `evals/baselines/nuisance/` are absent, so nothing resets.

## What this part moves, and what it does not

- No step touches a holdout image, a file under `evals/stand_ins/`, or a module of `ENVIRONMENT_PATHS` (`evals/cve/detection/baseline.py`). So no detection fixture fingerprint moves and no `holdout_fingerprint` is recorded again. The closing pass confirms it: `current_copy_fingerprints` (`tests/unit/support/test_nuisance_committed_admission_given.py`) still returns the committed values, among them those of CVE-2026-85788 and CVE-2026-85787.
- The nuisance fixture fingerprint (`evals/cve/nuisance/fingerprint.py`) moves for each server whose run Dockerfile, launch, backend files, counted tools or benign calls change. It is recorded nowhere, so nothing is copied.
- Fix-check images are built by name from `evals/docker/Dockerfile.<service>` and are not compose services: only the compose labels of the run images and backend part images whose Dockerfile changes move (`tests/unit/test_cve_compose_labels.py` prints the value), `gravitino-db` among them. A fix-check image of the form "the run image plus what the reproduction needs" is named `<service>-patched` and carries no ARG beyond the run image's, as `tests/unit/test_nuisance_fix_checks.py` requires (precedent `Dockerfile.dbt-patched`). It repeats the run Dockerfile's instructions from the same digest-pinned `FROM` and adds its own at the end, never `FROM` the local run tag, which `test_every_base_image_is_pinned_by_digest` refuses. Every `FROM` of a new build stage is pinned by digest too.
- A seed's `pin` occurs in a fingerprinted instruction (`evals/cve/fixture_sources.py`, `unfingerprinted_pins`), a remote `ADD` carries a checksum, and a stand-in output's `request` text occurs in the file that serves it (`unheld_requests`).
- A benign call shared by several counted flaws stays identical across them (`evals/cve/nuisance/admission_records.py`).

## The maintainer's readings for this part

- The engine settings that only the reproduction of a flaw needs leave the run image and stay in the fix-check images only. For MySQL and PostgreSQL the fix check is the holdout calibration copy, whose images keep those settings, so no fix-check image is added. ArcadeDB is read differently: its write permissions are an option the run keeps because the fix needs it set (`docs/nuisance-suite-rule.md`, the launch at its defaults "unless a fix needs it set"). At the defaults `execute_command` refuses a script before evaluating it, so the patched code path the counted tool carries would never run during an audit. The run image keeps `allowInsert`, `allowUpdate` and `allowDelete`, and only `allowSchemaChange` and `allowAdmin`, which nothing needs, go back to their default, as the first part sets the holdout images.
- MySQL's account follows the server's README at 1.0.23 (least privilege, `GRANT SELECT` on one database), and PostgreSQL's role follows the server's README at 1.1.7 (no superuser, a read-only role). The account names, passwords, cluster identifier and endpoint the shared Secrets Manager and RDS stand-ins serve stay as they are.
- Gravitino's sample is the Gravitino Playground at its `branch-1.2`, the branch that targets the pinned Gravitino line, seeded in the part the backend holds (metalake, PostgreSQL catalog, HR schema). PostgreSQL stays at its current release unless the Playground's `init.sql` fails to load on it.
- The git samples take the names and identity of Pro Git, git's own documentation, before any written value, and no real person's address.
- The point lookup of ios-simulator answers the capture for its captured point only, and idb's documented `null` for any other point (documentation before source code).
- `stop_recording` of ios-simulator keeps its current answer, logged as a limit: the real outcome needs a recording process the stand-in would have to keep alive, which no source describes, and installing `pkill` alone would only turn one error into another.
- Two settings of the git-mcp image that the review did not cover (`GIT_SIGN_COMMITS=false`, `MCP_LOG_LEVEL=error`, where the documented defaults are `true` and `info`) stay out of this part, and the git-mcp log entry says so: they are left for a later part, which reads them against the server's documentation (signing at its default would make every commit of a benign call fail without a key).

## Changes

Each item is its own commit, with its proof, its record corrections and its nuisance log entry, in the order below (lightest first, Gravitino last).

### 1. ios-simulator and siri-shortcuts: records, and the point lookup

Servers `npm:ios-simulator-mcp` (CVE-2025-52573) and `npm:mcp-server-siri-shortcuts` (CVE-2026-0758), both with their own fix check.

- Records only, no image change: no tool of the pinned releases sends `simctl launch` or `shortcuts list --folders`, so nothing of those outputs reaches the auditor. `record_video` (not counted) always returns its own text after three seconds, whatever the stand-in answers. The companion methods the tools call (`connect`, `accessibility_info`, `hid`) are already served. The log records these, and the `stop_recording` limit above.
- The point lookup: today every point request gets the capture taken at `(201, 90)` (`Dockerfile.ios-simulator`, the `describe-point` handling, and the same block of `Dockerfile.ios-simulator-vuln`). The stand-in serves the capture only when the request's point is `x == 201` and `y == 90`, fixed values at fixed positions of the message, and answers every other point with `json="null"`, from idb's documentation at `v1.7.7`, the release the image installs (`website/docs/idb/ui.mdx`, "or `null` when nothing is at the point"), which comes before idb's source code, where the same case throws. The benign call of `ui_describe_point` moves to `(201, 90)`, expect `AXGroup` unchanged, in the admission, its `benign_calls` settlement and `_benign_describe_point` of `evals/cve/nuisance/fix_checks/cve_2025_52573_ios_simulator.py`. The exploit keeps its point. The capture's citation is corrected (the demos page it cites is regenerated from a file the repository does not hold, so no version pins it), and the `null` output is recorded as `software_sources` with its citation and a request string held in the file.
- Proof: `uv run python -m evals.run_nuisance fix-check --flaw CVE-2025-52573`, `uv run python -m evals.run_nuisance vet --server npm:ios-simulator-mcp`.

### 2. houtini: the project is the git sample

Server `npm:@houtini/lm` (CVE-2026-82112, own fix check, counted tool `code_task_files`).

- `/srv/app` in `Dockerfile.houtini` and `Dockerfile.houtini-vuln` is today a written project (`greet.js`, a written identity and commit, a written origin). It becomes the sample of Pro Git, `https://github.com/schacon/simplegit-progit` cloned whole and reset to `ca82a6dff817ec66f44342007202690a93763949`, the pin `Dockerfile.auto-commit` already uses. No commit is made at build, so the identity goes. `chmod -R a+rX` stays. The block comes after the model layers, so the cached model is not rebuilt.
- The benign call (`/srv/app/.git/config`) holds on a clone and does not change. The witness and the exploit do not touch `/srv/app`.
- Records: the seed becomes `published_sample` with the pin and the Pro Git citation, the path `/srv/app` stays as the launch option sets it, the `seeds` settlement and the Dockerfile comments are restated.
- Proof: `fix-check --flaw CVE-2026-82112`, `vet --server npm:@houtini/lm`.

### 3. memory-keeper: the export is generated by the server

Server `npm:mcp-memory-keeper` (CVE-2026-54561, own fix check, counted tool `context_import`).

- Today `Dockerfile.memory-keeper` and `-vuln` bake a written export at `/tmp/mcp-data/memory-keeper/exports/project-context.json`. The project publishes no sample (`examples/` at `v0.13.0` holds a profile configuration and a guide).
- At build, the installed server runs once over stdio, driven by a small client on the server's own `@modelcontextprotocol/sdk` dependency, waiting for each reply. It plays the Usage block of its README at `v0.13.0` (which ships in the pinned npm package): `context_session_start` and the saves that block gives, then `context_export`. The export is renamed from its random name (`memory-keeper-export-<8 hex>.json`) to `backup.json`, the name the same README's import example gives, and `context.db` (with any `-wal` and `-shm`) is deleted, so the image holds one export and no store, as it does today. `HOME` or `DATA_DIR` is set for that instruction only, and `/tmp/mcp-data` stays owned by 65534 as today (`chown -R`), since the server creates its store there at run time. The client is written inline in the `RUN` (heredoc), since `unsourced_copies` (`evals/cve/fixture_sources.py`) refuses a local `COPY`.
- `-vuln` (0.12.2 exports to `os.tmpdir()`) carries the same file: the 0.13.0 export is copied from a build stage (`COPY --from`, which `fixture_sources.py` accepts), so the two arms carry the same generation (each with its own session id and dates, which no proof reads).
- The benign call's `filePath` becomes `backup.json`, in the admission and in `evals/cve/nuisance/fix_checks/cve_2026_54561_memory_keeper.py`. The witness and the exploits do not change.
- Records: the export `generated` (citation `context_export` at 0.13.0, pin `mcp-memory-keeper@0.13.0`), the saved values and the file name `project_document` (citation the README at `v0.13.0` with its lines), the `seeds` and `benign_calls` settlements and the Dockerfile comments restated.
- Proof: `fix-check --flaw CVE-2026-54561`, `vet --server npm:mcp-memory-keeper`.

### 4. git-mcp: the trees are clones of the git sample

Server `npm:@cyanheads/git-mcp-server` (CVE-2025-53107 and CVE-2026-85626, own fix checks, 23 counted tools).

- Today `Dockerfile.git-mcp` and the three fix-check images `-flaw-2.1.4`, `-flaw-2.1.5`, `-flaw-2.15.1` build written repositories (`README.md`, `note.txt`, branches `feature` and `upstream`, tag `v1`, a written commit for cherry-pick, a written identity), and the admission says no sample exists, which is false.
- Each tree becomes the simplegit sample cloned whole and reset to `ca82a6d…` on its branch `master`. The bare remote is `git clone --bare` of the sample (Pro Git 4.2), and the remote clone is cloned from it, so git writes origin and the upstream. Names come from Pro Git (`progit/progit2` at `a013e3230a1207cfa5ae94d28ba7d2021063c337`): branch `iss53` for the main and checkout trees, `hotfix` for the merge tree, `experiment` for the rebase tree (created on `master` and checked out, with no commit of its own, so the benign rebase onto `master` finds it up to date, as today), lightweight tag `v1.4-lw`. The main tree carries no working-tree edit and no untracked file any more, so `git_add`, `git_diff` and `git_clean` run on a clean tree and `vet` shows whether their expects still hold. The cherry-pick tree resets `master` one commit back (`085bb3b…`) so the benign call replays the sample's own `ca82a6d`, still reachable through `origin/master`; the reset position is recorded as written. The identity is Pro Git's `John Doe <johndoe@example.com>`, at `--system`, since `git_commit` and `git_cherry_pick` create commits at run time. `init.defaultBranch` and `core.fileMode` are dropped, and kept with their reason only if `vet` fails without them.
- The benign calls that change, in the admission and in `_BENIGN_53107` of `evals/cve/nuisance/fix_checks/cve_2025_53107_git_mcp.py` (legacy forms of 2.1.x included): `git_add` `README`, `git_checkout` `iss53`, `git_cherry_pick` the commit `ca82a6d…`, `git_merge` `hotfix`, `git_rebase` onto `master`, `git_pull` and `git_push` on `master`. The three calls shared with CVE-2026-85626 do not change. Expects do not change.
- The exploits aim at the layout and at fresh `/tmp` paths, and the witness is planted by the kit outside the trees: none changes. Their literal `main` stays (frozen, and the injected path fails before any ref is read).
- `tests/unit/support/retired_word_exemptions.py` allows the line `'"target": "feature"'` of the fix-check module: it follows the rename to `'"target": "iss53"'`, or `tests/unit/test_glossary.py` fails.
- Records: seeds rewritten (`published_sample` the sample with its pin and Pro Git citation, `generated` the clones, branches, tag and bare remote, `project_document` the names and identity with their Pro Git file and line, `written` the tree paths and the reset position), the `seeds` and `benign_calls` settlements and the Dockerfile comments restated.
- Proof: `fix-check --flaw CVE-2025-53107`, `fix-check --flaw CVE-2026-85626`, `vet --server npm:@cyanheads/git-mcp-server`.

### 5. mcp-package-docs: the Swift project only in the fix check

Server `npm:mcp-package-docs` (CVE-2025-54073, own fix check).

- `Dockerfile.mcp-package-docs` bakes `/opt/swift-project/Package.swift` (`Package(name: "fixture")`) into the run image, while only the fix check reads it. The run image drops it and its comment. A new `Dockerfile.mcp-package-docs-patched`, the run image with that file added as its last instruction, serves the fix check's patched arm (`patched_service="mcp-package-docs-patched"` in `evals/cve/nuisance/fix_checks/cve_2025_54073_mcp_package_docs.py`, whose docstring follows). `-vuln` keeps its copy.
- The file keeps the name `fixture`: the frozen exploit names `https://example.com/fixture` and `/opt/swift-project`, and the server takes the local path only when `Package.swift` names the package. A renamed file would change the exploit, which the bounds forbid. The witness and the benign calls do not change.
- Records: `seeds` stays empty (true of the run), the log records the move.
- Proof: `fix-check --flaw CVE-2025-54073`, `vet --server npm:mcp-package-docs`.

### 6. ArcadeDB: only the permissions the fix needs

Server `Maven:com.arcadedb:arcadedb-server`. Its one counted flaw is CVE-2026-65831 (own fix check), with the counted tools `execute_command` and `query`. The other flaws of the server count no tool and have no fix-check module.

- `Dockerfile.arcadedb` writes `config/mcp-config.json` with every permission class allowed. ArcadeDB's defaults at 26.7.1 (`MCPConfiguration.java`) allow reads only, and stdio mode enables the MCP server whatever the file says (`MCPStdioServer.java`). A polyglot script maps to create, update and delete (26.6.1's `PolyglotQueryEngine`), so `execute_command` reaches the engine only with those three permissions, which the fix needs set for its patched path to run. The file keeps `enabled`, `allowReads`, `allowInsert`, `allowUpdate`, `allowDelete` and `allowedUsers` as today, and `allowSchemaChange` and `allowAdmin` go to their default, `false`. The benign calls `vet` plays (those of the counted tools `execute_command` and `query`) are SQL `SELECT`s.
- `Dockerfile.arcadedb-vuln` takes the same file, so its header comment ("otherwise identical to the run image") stays true. No fix-check image is added, and the fix check's `patched_service` stays `arcadedb`.
- Records: the `config/mcp-config.json` seed and the `launch_option` of CVE-2026-65831 carry the five flags that remain (`allowSchemaChange` and `allowAdmin` removed), with the reason above, and the `seeds` settlement is restated. The `fix_check` records of CVE-2026-67357, CVE-2026-68578 and CVE-2026-75845 (no module, no counted tool, no re-run) stay as recorded, and the log says they were taken on the former run image with every permission class allowed.
- Proof: `fix-check --flaw CVE-2026-65831` (vulnerable arm surfaces, patched arm does not, benign clean, as recorded), `vet --server Maven:com.arcadedb:arcadedb-server`.

### 7. MySQL and PostgreSQL: the run images at their defaults

Servers `PyPI:awslabs-mysql-mcp-server` (CVE-2026-85788) and `PyPI:awslabs-postgres-mcp-server` (CVE-2026-85787, CVE-2026-87911), whose fix checks are holdout calibration copies. Their proof is `vet` alone, and their holdout images (`Dockerfile.holdout-2026-85788-mysql*`, `Dockerfile.holdout-2026-85787-postgres*`) are not touched: they keep the settings the reproduction needs.

MySQL (`Dockerfile.mysql`):

- The engine runs on the image's own `/etc/my.cnf`: the `/etc/mcp/my.cnf` defaults file and `--defaults-file` go, which removes `secure_file_priv=`, `local_infile=1`, `bind-address`, `mysqlx=0` and `port` (and the same file's `skip-name-resolve` and `host_cache_size=0`, which the image's own file also sets), and `/etc/mcp` leaves the `chown`. `--initialize-insecure` stays (MySQL's documented initialization, which the official image's entrypoint uses).
- The account keeps the name `postgres` and the password `EXAMPLE-PASSWORD` the stand-ins serve. Its grant follows the server's README at 1.0.23 ("Recommended configuration": `GRANT SELECT ON your_database.* TO ...`), each replacement recorded. The `ALL` and `FILE` grants go.
- The database is the `employees` sample, the first of MySQL's example databases (dev.mysql.com, "Example Databases"), from `datacharmer/test_db` at `e324b56193ca506ab7cc1ab143a9153d8c4535d7`, fetched with one `ADD --checksum=sha256:...` per file (about 172 MB) and loaded at build with `mysql --commands < employees.sql` (a client from 9.5 on disables `SOURCE` by default). It loads at build, outside the memory bound. The image grows by an estimated 0.5 to 0.8 GB, which the implementer measures and reports. If the sample does not load on this MySQL release, the step stops and reports it.
- At run time mysqld runs as 65534 against the default `secure-file-priv` directory (`/var/lib/mysql-files`, `0750`, owned by the image's `mysql` user). If mysqld refuses to start on it, or on a log path the package's configuration sets and 65534 cannot write, that path joins the existing `chown`, a container repair that changes no setting.
- The benign call and its prerequisite move from `database` `app` to `employees`.
- Records: the account seed is split (the account `published_sample` with the stand-in's pin, the grant `project_document` from the README with its replacements), the `app` seed gives way to `published_sample` employees with its pin and citation, the `seeds` and `benign_calls` settlements and the Dockerfile header are restated (it says the image matches its holdout target's, which stops being true).

PostgreSQL (`Dockerfile.postgres`):

- `CREATE EXTENSION dblink` goes, with its seed (dblink stays installed as a contrib module, not created). `listen_addresses` and `unix_socket_directories` go back to their defaults (`localhost`, which the RDS stand-in's endpoint still names, and `/var/run/postgresql`, which 65534 can write).
- The role follows the server's README at 1.1.7 ("Do not connect as a superuser"): a read-only role named `postgres` (the name the stand-ins fix), with the README's grants and `default_transaction_read_only`, while initdb's bootstrap superuser takes initdb's default name, the operating-system user running it (`nobody`, since initdb runs as 65534). Authentication stays initdb's default, `trust`, as today: the README asks only that the server not connect as a superuser. If this role proves fragile at `vet`, the step falls back to the superuser `postgres` and logs it.
- PostgreSQL publishes no sample database (its tutorial's `basics.source` ends by dropping its tables), recorded with that reason.
- The benign call (`SELECT version()` on database `postgres`) does not change.
- Records: the three engine seeds are rewritten (the bootstrap superuser `nobody` under `trust` authentication, `generated`, named as such, the read-only role `postgres` `project_document` from the README at 1.1.7 with its grants, the dblink seed removed), the absent sample recorded with its reason, and the Dockerfile comments restated. The server has no `seeds` settlement today, so none is restated.

The holdout card of CVE-2026-85788 (`evals/census.json`, `draw.cards`, under `seeded_outside_layout`) records the settings its images set and the card omits (`mysqlx=0`, `bind-address=127.0.0.1`, `--initialize-insecure`), and the reason of its walk step (`draw.walk`, outcome `drawn`), which still names MySQL 8.0 and moto, is corrected. A record correction: no fingerprint moves, no check runs, and the entry goes in the detection log.

Proof: `vet --server PyPI:awslabs-mysql-mcp-server`, `vet --server PyPI:awslabs-postgres-mcp-server`.

### 8. sf-mcp: no build-day files in the run image

Server `https://github.com/akutishevsky/sf-mcp-server`, whose counted flaw's fix check is the holdout calibration copy of CVE-2026-26029, so its proof is `vet`.

- The first part removed from the holdout images of CVE-2026-26029 the files the CLI writes on the day of the build: the oclif version cache `/tmp/.cache/sf/version` and the dated log `/tmp/.sf/*.log`. On a rebuild they made the benign call fail on the patched version. The nuisance run image `Dockerfile.sf-mcp` removes the log but keeps the version cache, so a rebuild without its layer cache would break its benign call the same way. The login instruction also removes `/tmp/.cache/sf/version`, as the holdout images do.
- No value, seed or benign call changes. The holdout copy does not move (the holdout fingerprint does not hash the nuisance Dockerfile).
- Proof: `docker compose -f evals/docker/compose.yml --profile nuisance build --no-cache sf-mcp`, the one cold build this part needs (the image is about 0.6 GB), then `vet --server https://github.com/akutishevsky/sf-mcp-server`.

### 9. Gravitino: freeze the exploits, then seed from the Playground

Server `https://github.com/apache/gravitino` (CVE-2026-41041, own fix check, 27 counted tools).

- First commit, with no behaviour change: the fix check's exploits are built today from the benign calls (`EXPLOITS = tuple(_call(tool, {**benign, field: _TRAVERSAL}) ...)` in `evals/cve/nuisance/fix_checks/cve_2026_41041_gravitino.py`). They are written out as the 27 literal calls they produce today, so the reseed cannot move them. The module already holds 380 lines, past the 300 of `CLAUDE.md`, so the literal calls go in a sibling module of `evals/cve/nuisance/fix_checks/`, `gravitino_exploits.py`, which the fixture module imports (precedent `excel_witness_workbook.py`, `n8n_redirect_stand_in.py`), under the kit's import closure the package docstring states. `fix-check --flaw CVE-2026-41041` proves the commit changes nothing.
- Second commit, the reseed. The seed in `evals/cve/backends/gravitino.py` (metalake `analytics`, written schemas, columns, properties and file contents) and `Dockerfile.gravitino-db` (user, password and database written) are replaced by what the Playground (`apache/gravitino-playground` at `branch-1.2`, commit `11b37bc618763c2f172f6ae997871a067666389f`) gives and the backend can hold: metalake `metalake_demo`, catalog `catalog_postgres` with the Playground's properties, and its `init/postgres/init.sql` (the HR schema) loaded into gravitino-db through `/docker-entrypoint-initdb.d`, with the Playground's PostgreSQL user and service name (the db alias becomes `postgresql`). Fileset, model, tag and policy follow the examples of the Gravitino documentation at v1.2.1. The Kafka topic, the statistic and the fileset's file content take the examples of the documentation at v1.2.1 where it gives one (its messaging and statistics pages first), and stay written and recorded only where it gives none. The parts of the Playground the backend cannot hold (Hive, Trino, Spark, Iceberg, MySQL) are recorded as left out, with that reason.
- The launch moves to `--metalake metalake_demo`, and `METALAKE`, `GRAVITINO_SERVER_LAUNCH`, the backend's PostgreSQL probe and the fix check's `_PROBES` follow. The 26 benign calls that name seeded objects and their expects are rewritten from what 1.2.1 returns on the new seed, in the admission and in the fix check's patched-arm benign calls. `get_job_template_by_name` does not change.
- The witness does not move: the fix check seeds its own metalake `hidden` and catalog `secretcat`, which the traversal reaches whatever the metalake's name, and only `get_list_of_schemas` surfaces it. The frozen exploits keep the old names and are fix-check-only content.
- `tests/unit/test_backend_hostnames.py` pins `analytics`, the part aliases `{"gravitino", "postgres", "kafka"}` and the `warehouse` catalog's `jdbc-url`: it follows the new values. `tests/unit/test_gravitino_fix_check_builder.py` pins `--metalake analytics` and follows too. The fix check's module docstring, which names `analytics` three times, is restated.
- Records: the launch and its `launch` settlement, the seven seeds (`published_sample` with pin and citation for the Playground parts, `project_document` for the documentation examples, `written` for the rest), `software_releases` (the reason of the Gravitino entry is reworded, since it names a flaw's patched version as the reason for the release), the benign calls, and a log entry that redoes the ratification of 2026-11-11. The server has no `seeds` settlement today (its settlements are `tools` and `launch`), so none is restated.
- Proof: `vet --server https://github.com/apache/gravitino`, then `fix-check --flaw CVE-2026-41041` (in that order, see step 10).

## What stays unchanged

- Every exploit, witness place, counted tool and version, and every benign call this part does not name.
- Every holdout image, every stand-in capture, every module of `ENVIRONMENT_PATHS`, the rules, the census flaws, the walk, the draw, the places file, the grammar, the counter, the auditor (`src/mcp_auditor/`).
- The two git-mcp settings outside the review, and every server this part does not name.

## Edge cases

- A proof that fails: the item reverts to its state before the repair, and the log records the break it keeps. Nothing leaves the nuisance holdout layer for that reason.
- A proof that fails for a cause older than the repair (a rebuild that brings out a break the layer cache hid, as the first part met on sf-mcp): the step stops and reports the cause before reverting, since reverting would not make the proof pass, and the maintainer decides whether its repair joins the step.
- A real program that replaces a written one (git in place of written trees, the server generating its export) may read a file the fixture plants for the fix check: before the proof, the implementer checks what the program reads at start and in each benign call, and stops if it reaches the witness.
- A benign call that fails on a server at its defaults (an ArcadeDB or MySQL counted tool refused under the default permissions): the step stops and reports it, since the counted tools are frozen and dropping one is the admission agents' work.
- A source that contradicts what this plan describes: the source wins, and the step records it.
- A build that is far heavier than estimated (the MySQL sample, the Gravitino stand-up): the step measures and reports it before going on.

## Verification

- Per step: the proofs above. In the loop, the short loop of `CLAUDE.md` on the changed test files and the integration files that import a changed module. The pass that closes each step runs `uv run pytest -n auto`, `uv run ruff check .` and `uv run pyright` with no file argument.
- Closing the plan: the same three at the final tree, `current_copy_fingerprints` unchanged, and `uv run python -m evals.run_nuisance vet` on every server this part touched.
- Docker disk: as the first part, with the MySQL image's growth reported. No build beyond those the proofs need, no new tag, every container, network or image created by hand removed, no prune of an image the implementer did not create, any `docker system df` growth above about 1 GB reported. Cleaning up existing images is left to the maintainer.

## Due diligence record

What the plan's due-diligence pass concluded about the external facts this plan cites or defers, read by the implementation-phase fact check. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `ca82a6dff817ec66f44342007202690a93763949` of `https://github.com/schacon/simplegit-progit`, parent `085bb3bcb608e1e8451d4b2432f8ecbe6306e7e7` (verified against the GitHub commits API)
- SETTLED: `progit/progit2` at `a013e3230a1207cfa5ae94d28ba7d2021063c337` gives `John Doe` / `johndoe@example.com` (first-time-setup.asc), branches `iss53` and `hotfix` (basic-branching-and-merging.asc), `experiment` rebased onto `master` (rebasing.asc), lightweight tag `v1.4-lw` (tagging.asc), and `git clone --bare` in "Getting Git on a Server" (4.2) (verified against the files at that commit)
- SETTLED: idb `website/docs/idb/ui.mdx` says describe-point emits "`null` when nothing is at the point", at `v1.7.8` and at `v1.7.7` alike (verified against both tags)
- SETTLED: mcp-memory-keeper `v0.13.0`: the README's Usage block calls `context_session_start`, `context_save`, `context_export`, and its import example names `backup.json`; the export is named `memory-keeper-export-${targetSessionId.substring(0, 8)}.json` in the exports directory; `examples/` holds `config.json` and `project-directory-setup.md`; `v0.12.2` exports to `os.tmpdir()` (verified against the repository at both tags)
- SETTLED: ArcadeDB `26.7.1` `MCPConfiguration.java` defaults to `allowReads` true and the other five permission flags false, and saves `config/mcp-config.json` when absent; `MCPStdioServer.java` calls `config.setEnabled(true)` (verified against the source at that tag)
- SETTLED: `awslabs.mysql-mcp-server` `1.0.23` README, "Recommended configuration": `GRANT SELECT ON your_database.* TO 'mcp_readonly'@'%';` (verified against PyPI)
- SETTLED: `awslabs.postgres-mcp-server` `1.1.7` README: "Do not connect as a superuser", the `GRANT CONNECT` / `USAGE` / `SELECT` grants and `default_transaction_read_only = on` (verified against PyPI)
- SETTLED: `datacharmer/test_db` at `e324b56193ca506ab7cc1ab143a9153d8c4535d7` exists, `employees.sql` plus its `load_*.dump` files and `show_elapsed.sql` total 172,290,184 bytes; the employee data is first in MySQL's "Example Databases" (verified against the GitHub API and dev.mysql.com)
- SETTLED: the MySQL 9.5 client's `--commands` defaults to `FALSE`, which disables `source` (verified against the 9.5 reference manual)
- SETTLED: PostgreSQL's `src/tutorial/basics.source` ends with `DROP TABLE weather, cities;` (verified against postgres master)
- SETTLED: `apache/gravitino-playground` `branch-1.2` head is `11b37bc618763c2f172f6ae997871a067666389f`; `init/postgres/init.sql` creates database `db` and schema `HR`; `init/common/init_metalake_catalog.sh` creates `metalake_demo` and `catalog_postgres` with `jdbc:postgresql://postgresql/db`, user and password `postgres`, `jdbc-database` `db`; the compose service is `postgresql` (verified against the repository at that commit)
- SETTLED: Gravitino tag `v1.2.1` exists (verified against the GitHub refs API)
- OPEN (currency): Gravitino `v1.2.1`, while `v1.3.1` is the latest release; the pin is the server's patched version and is not touched
- OPEN (unverified): the MySQL 9.5 client as the first to disable `source` by default; the manual shows the default, not the version that changed it
- OPEN (unverified): the `/etc/my.cnf` the `mysql:26.10.0` image ships (its `secure-file-priv` directory and any `log-error` path); docker-library's Dockerfile does not set them, the package's file does
- OPEN (unverified): idb's source code throwing on an empty point; not checked
- OPEN (deferred): the per-file `sha256` checksums of the employees files, computed at implementation
- OPEN (deferred): the 26 Gravitino benign calls and expects, the fileset, model, tag and policy examples of the documentation at v1.2.1, and the written Kafka topic, statistic and file content, produced at implementation
- OPEN (deferred): the corrected citation of the ios-simulator capture and the request string of the `null` output, written at implementation

## Implementation steps

Every step is one commit and follows the plan's order (item 9 is two steps, since it is two commits). Common to every step, and not repeated below:

- The records go in `evals/nuisance_admission.json` (seeds, settlements, benign calls, launch), the entry in `docs/nuisance-suite-log.md` (in the detection log too where a step says so), the Dockerfile comments are restated to match, and every compose service whose Dockerfile changes gets the label value `tests/unit/test_cve_compose_labels.py` prints (`evals/docker/compose.yml`). A new `<service>-patched` fix-check Dockerfile is not a compose service.
- Tests that guard the records and images, run in the loop after each record or Dockerfile edit: `tests/unit/test_nuisance_admission_loads.py`, `tests/unit/test_nuisance_admission_records.py`, `tests/unit/test_nuisance_fixture_sources.py`, `tests/unit/test_nuisance_fix_checks.py`, `tests/unit/test_nuisance_compose.py`, `tests/unit/test_cve_compose_labels.py` (`uv run pytest <files> -n 0`), then the short loop `uv run pytest tests/unit -n auto --maxprocesses 6`, `uv run pyright <changed .py files>`, `uv run ruff check .`.
- A seed record of kind `published_sample` carries a `citation` and a `pin`, `project_document` a `citation` (`evals/cve/nuisance/admission_records.py`), and the `pin` occurs in a fingerprinted instruction of the Dockerfile (`unfingerprinted_pins`). A remote `ADD` carries `--checksum`. Every new `FROM` is pinned by digest.
- The step's proof commands (Docker) run before the closing checks. A proof that fails reverts the item and logs the break it keeps (plan, Edge cases). A source that contradicts the plan wins and is recorded.
- Closing checks of every step: `uv run pytest -n auto`, `uv run ruff check .`, `uv run pyright`, all green, with no file argument.
- Docker disk: only the builds the proofs need, no new tag beyond the ones the step creates, every container, network or image created by hand removed, any `docker system df` growth above about 1 GB reported, no prune of an image the implementer did not create.
- Nothing from outside the repository is named in a committed file.

### Step 1: ios-simulator and siri-shortcuts, records and the point lookup

- **Files**: `evals/docker/Dockerfile.ios-simulator`, `evals/docker/Dockerfile.ios-simulator-vuln`, `evals/cve/nuisance/fix_checks/cve_2025_52573_ios_simulator.py`, `evals/nuisance_admission.json`, `evals/docker/compose.yml`, `docs/nuisance-suite-log.md`.
- **Do**:
  1. In the `describe-point` handling of both Dockerfiles (same block), inside the existing branch for a plain request with a point in format `LEGACY` (every other request keeps its `UNIMPLEMENTED` answer), serve the capture taken at `(201, 90)` only when the request's point is `x == 201` and `y == 90` (fixed values at fixed positions of the message), and answer every other point with `json="null"`, per idb's `website/docs/idb/ui.mdx` at `v1.7.7`.
  2. Move the benign call of `ui_describe_point` to `(201, 90)`, expect `AXGroup` unchanged: `_benign_describe_point` in the fix-check module, the admission's benign call and its `benign_calls` settlement. The exploit keeps its point.
  3. Records: correct the capture's citation (the demos page is regenerated from a file the repository does not hold, so no version pins it), and record the `null` output as `software_sources` with its citation and a `request` string that occurs in the Dockerfile serving it (`unheld_requests`).
  4. Log entry: no tool of the pinned releases sends `simctl launch` or `shortcuts list --folders`; `record_video` (not counted) returns its own text after three seconds whatever the stand-in answers; `connect`, `accessibility_info` and `hid` are already served; and the `stop_recording` limit kept (no source describes the recording process the stand-in would have to keep alive, `pkill` alone would turn one error into another). siri-shortcuts gets no image change.
- **Test**: the guard tests above pass (the `null` output's request is held, the benign call is identical wherever it is shared, the label matches).
- **Verify**: `uv run python -m evals.run_nuisance fix-check --flaw CVE-2025-52573` exits 0 (witness on the vulnerable arm, none on the patched arm, benign `AXGroup` holds), `uv run python -m evals.run_nuisance vet --server npm:ios-simulator-mcp` prints `ok`, then the closing checks.

### Step 2: houtini, the project is the git sample

- **Files**: `evals/docker/Dockerfile.houtini`, `evals/docker/Dockerfile.houtini-vuln`, `evals/nuisance_admission.json`, `evals/docker/compose.yml`, `docs/nuisance-suite-log.md`.
- **Do**: in both Dockerfiles, replace the written `/srv/app` project (`greet.js`, identity, commit, origin) with `git clone` of `https://github.com/schacon/simplegit-progit` whole, reset to `ca82a6dff817ec66f44342007202690a93763949` (the pin `Dockerfile.auto-commit` uses). No commit at build, no identity. Keep `chmod -R a+rX`. Keep the block after the model layers so the cached model is not rebuilt. Records: the seed becomes `published_sample` with that pin and the Pro Git citation, path `/srv/app` unchanged, the `seeds` settlement restated. Benign call (`/srv/app/.git/config`), witness and exploit unchanged.
- **Test**: the guard tests above pass (the pin is in a fingerprinted instruction).
- **Verify**: `uv run python -m evals.run_nuisance fix-check --flaw CVE-2026-82112` exits 0, `uv run python -m evals.run_nuisance vet --server npm:@houtini/lm` prints `ok`, then the closing checks.

### Step 3: memory-keeper, the export is generated by the server

- **Files**: `evals/docker/Dockerfile.memory-keeper`, `evals/docker/Dockerfile.memory-keeper-vuln`, `evals/cve/nuisance/fix_checks/cve_2026_54561_memory_keeper.py`, `evals/nuisance_admission.json`, `evals/docker/compose.yml`, `docs/nuisance-suite-log.md`. The small build-time client is a heredoc inside the `RUN`, not a separate file: a local `COPY` is refused (`unsourced_copies`, `evals/cve/fixture_sources.py`).
- **Do**:
  1. `Dockerfile.memory-keeper`: drop the written export. At build, run the installed 0.13.0 server once over stdio with a small client on the server's own `@modelcontextprotocol/sdk` dependency, waiting for each reply, playing the README's Usage block at `v0.13.0` (`context_session_start`, the saves the block gives, then `context_export`). Rename `memory-keeper-export-<8 hex>.json` to `backup.json` in the exports directory (`/tmp/mcp-data/memory-keeper/exports/`), delete `context.db` and any `-wal`/`-shm`, set `HOME` or `DATA_DIR` for that instruction only, and keep `chown -R 65534:65534 /tmp/mcp-data` (the server writes its store there at run time).
  2. `Dockerfile.memory-keeper-vuln`: add a digest-pinned build stage that installs 0.13.0 and generates the same export, and `COPY --from` it to the same path, so both arms carry the same generation.
  3. The benign call's `filePath` becomes `backup.json` in the admission and in the fix-check module. Witness and exploits unchanged.
  4. Records: the export `generated` (citation `context_export` at 0.13.0, pin `mcp-memory-keeper@0.13.0`), the saved values and the file name `project_document` (README at `v0.13.0` with its lines), the `seeds` and `benign_calls` settlements restated.
- **Test**: the guard tests above pass (the `COPY --from` is accepted, the pin is fingerprinted).
- **Verify**: `uv run python -m evals.run_nuisance fix-check --flaw CVE-2026-54561` exits 0, `uv run python -m evals.run_nuisance vet --server npm:mcp-memory-keeper` prints `ok`, then the closing checks.

### Step 4: git-mcp, the trees are clones of the git sample

- **Files**: `tests/unit/support/retired_word_exemptions.py`, `evals/docker/Dockerfile.git-mcp`, `evals/docker/Dockerfile.git-mcp-flaw-2.1.4`, `evals/docker/Dockerfile.git-mcp-flaw-2.1.5`, `evals/docker/Dockerfile.git-mcp-flaw-2.15.1`, `evals/cve/nuisance/fix_checks/cve_2025_53107_git_mcp.py`, `evals/nuisance_admission.json`, `evals/docker/compose.yml`, `docs/nuisance-suite-log.md`.
- **Do**:
  1. First, in `retired_word_exemptions.py`, replace the allowed line `'"target": "feature"'` with `'"target": "iss53"'`, and run `tests/unit/test_glossary.py` to see it red until the module is renamed.
  2. In the four Dockerfiles, each tree becomes the simplegit sample cloned whole and reset to `ca82a6dff817ec66f44342007202690a93763949` on `master`. The bare remote is `git clone --bare` of the sample, the remote clone is cloned from it (git writes origin and upstream). Branch `iss53` in the main and checkout trees, `hotfix` in the merge tree, `experiment` rebased onto `master` in the rebase tree, lightweight tag `v1.4-lw`. The main tree has no working-tree edit and no untracked file. The cherry-pick tree resets `master` to `085bb3bcb608e1e8451d4b2432f8ecbe6306e7e7` so the benign call replays `ca82a6d…`, still reachable through `origin/master`. Identity `John Doe <johndoe@example.com>` at `--system`. Drop `init.defaultBranch` and `core.fileMode`, and restore either with its reason only if `vet` fails without it.
  3. In `_BENIGN_53107` (legacy 2.1.x forms included) and the admission: `git_add` `README`, `git_checkout` `iss53`, `git_cherry_pick` `ca82a6dff817ec66f44342007202690a93763949`, `git_merge` `hotfix`, `git_rebase` onto `master`, `git_pull` and `git_push` on `master`. The three calls shared with CVE-2026-85626 and every expect stay. Exploits (their literal `main` included) and witness stay.
  4. Records: `published_sample` the sample (pin, Pro Git citation), `generated` the clones, branches, tag and bare remote, `project_document` the names and identity (`progit/progit2` at `a013e3230a1207cfa5ae94d28ba7d2021063c337`, file and line each), `written` the tree paths and the reset position. Replace the admission's claim that no sample exists. Restate the `seeds` and `benign_calls` settlements.
- **Test**: `tests/unit/test_glossary.py` green after the rename, plus the guard tests above (shared benign calls stay identical across the two flaws).
- **Verify**: `uv run python -m evals.run_nuisance fix-check --flaw CVE-2025-53107` and `--flaw CVE-2026-85626` exit 0, `uv run python -m evals.run_nuisance vet --server npm:@cyanheads/git-mcp-server` prints `ok` (in particular `git_add`, `git_diff` and `git_clean` hold on the clean tree, else stop and report, with no written edit added to the tree to make an expect hold), then the closing checks.

### Step 5: mcp-package-docs, the Swift project only in the fix check

- **Files**: `evals/docker/Dockerfile.mcp-package-docs`, new `evals/docker/Dockerfile.mcp-package-docs-patched`, `evals/cve/nuisance/fix_checks/cve_2025_54073_mcp_package_docs.py`, `evals/docker/compose.yml`, `docs/nuisance-suite-log.md`.
- **Do**: drop `/opt/swift-project/Package.swift` and its comment from the run image. Write `Dockerfile.mcp-package-docs-patched` as the run Dockerfile's instructions from the same digest-pinned `FROM`, with no ARG beyond the run image's, plus the `Package.swift` file (`Package(name: "fixture")`, name kept since the frozen exploit names it) as its last instruction (precedent `Dockerfile.dbt-patched`). Set `patched_service="mcp-package-docs-patched"` in the fix-check module and restate its docstring. `-vuln` keeps its copy. `seeds` stays empty. Log the move.
- **Test**: `tests/unit/test_nuisance_fix_checks.py` (the `-patched` form, no extra ARG) and the guard tests above.
- **Verify**: `uv run python -m evals.run_nuisance fix-check --flaw CVE-2025-54073` exits 0, `uv run python -m evals.run_nuisance vet --server npm:mcp-package-docs` prints `ok`, then the closing checks.

### Step 6: ArcadeDB, only the permissions the fix needs

- **Files**: `evals/docker/Dockerfile.arcadedb`, `evals/docker/Dockerfile.arcadedb-vuln`, `evals/nuisance_admission.json`, `evals/docker/compose.yml`, `docs/nuisance-suite-log.md`.
- **Do**: in the `config/mcp-config.json` instruction of `Dockerfile.arcadedb` and `Dockerfile.arcadedb-vuln`, set `allowSchemaChange` and `allowAdmin` to `false` (their 26.7.1 default) and keep the other flags. Records: the seed and the `launch_option` of CVE-2026-65831 name the remaining flags with the reason of item 6, the `seeds` settlement restated. Leave the `fix_check` records of CVE-2026-67357, CVE-2026-68578 and CVE-2026-75845 as recorded, and log that they were taken with every permission class allowed. If the fix check or a benign call of `execute_command` or `query` fails, revert and log (plan, Edge cases).
- **Test**: the guard tests above.
- **Verify**: `uv run python -m evals.run_nuisance fix-check --flaw CVE-2026-65831` exits 0 (vulnerable arm surfaces, patched arm does not, benign clean), `uv run python -m evals.run_nuisance vet --server Maven:com.arcadedb:arcadedb-server` prints `ok`, then the closing checks.

### Step 7: MySQL and PostgreSQL, the run images at their defaults

- **Files**: `evals/docker/Dockerfile.mysql`, `evals/docker/Dockerfile.postgres`, `evals/nuisance_admission.json`, `evals/census.json`, `evals/docker/compose.yml`, `docs/nuisance-suite-log.md`, `docs/detection-suite-log.md`.
- **Do**:
  1. MySQL: drop `/etc/mcp/my.cnf` and `--defaults-file` (so `secure_file_priv=`, `local_infile=1`, `bind-address`, `mysqlx=0`, `port` go), keep `--initialize-insecure`. Account `postgres` / `EXAMPLE-PASSWORD` kept, grant per the README at 1.0.23 (`GRANT SELECT ON employees.*`), `ALL` and `FILE` grants removed. `ADD --checksum=sha256:<computed>` each file of `datacharmer/test_db` at `e324b56193ca506ab7cc1ab143a9153d8c4535d7` that `employees.sql` loads, and load at build with `mysql --commands < employees.sql`. If mysqld refuses to start as 65534 on `/var/lib/mysql-files` or a log path of the package's `/etc/my.cnf`, add that path to the existing `chown`. If the sample does not load on this release, stop and report. Measure and report the image growth (estimated 0.5 to 0.8 GB). Move the benign call and its prerequisite from `database` `app` to `employees`. Records: account `published_sample` with the stand-in's pin, grant `project_document` from the README with its replacements, the `app` seed replaced by `published_sample` employees with pin and citation, `seeds` and `benign_calls` settlements and the Dockerfile header restated (it no longer matches its holdout target's image).
  2. PostgreSQL: drop `CREATE EXTENSION dblink` and its seed, restore `listen_addresses` and `unix_socket_directories` defaults. initdb runs as 65534 with its default superuser name (`nobody`) and `trust` authentication. Create a read-only role `postgres` with the README's (1.1.7) `GRANT CONNECT` / `USAGE` / `SELECT` grants and `default_transaction_read_only = on`. If it proves fragile at `vet`, fall back to the superuser `postgres` and log it. Benign call unchanged. Records: bootstrap superuser `generated`, role `project_document` (README at 1.1.7 with grants), dblink seed removed, the absent sample recorded with its reason (`basics.source` ends by dropping its tables), Dockerfile comments restated.
  3. `evals/census.json`: in the CVE-2026-85788 card (`draw.cards`, `seeded_outside_layout`) record `mysqlx=0`, `bind-address=127.0.0.1` and `--initialize-insecure`, and correct the reason of its `draw.walk` step (outcome `drawn`) that still names MySQL 8.0 and moto. Entry in `docs/detection-suite-log.md`. Holdout images untouched.
- **Test**: the guard tests above, plus `tests/unit/test_census.py` and `tests/unit/test_detection_holdout_card_readiness.py` after the census edit, and `current_copy_fingerprints` (`tests/unit/support/test_nuisance_committed_admission_given.py`) still returning the committed values for CVE-2026-85788 and CVE-2026-85787 (its tests green, no `holdout_fingerprint` change).
- **Verify**: `uv run python -m evals.run_nuisance vet --server PyPI:awslabs-mysql-mcp-server` and `vet --server PyPI:awslabs-postgres-mcp-server` print `ok`, image growth reported, then the closing checks.

### Step 8: sf-mcp, no build-day files in the run image

- **Files**: `evals/docker/Dockerfile.sf-mcp`, `evals/docker/compose.yml`, `docs/nuisance-suite-log.md`.
- **Do**: add `/tmp/.cache/sf/version` to the `rm -rf` that ends the login instruction, as `Dockerfile.holdout-2026-26029-sf-mcp` does. Log entry: the file, why it goes (written on the build day, it breaks the benign call on a rebuild), and that no value changes.
- **Test**: the guard tests above.
- **Verify**: `docker compose -f evals/docker/compose.yml --profile nuisance build --no-cache sf-mcp`, then `uv run python -m evals.run_nuisance vet --server https://github.com/akutishevsky/sf-mcp-server` prints `ok`, then the closing checks.

### Step 9: Gravitino, freeze the exploits

- **Files**: new `evals/cve/nuisance/fix_checks/gravitino_exploits.py`, `evals/cve/nuisance/fix_checks/cve_2026_41041_gravitino.py`.
- **Do**: compute the 27 pairs `(tool, {**benign, field: _TRAVERSAL})` that `_TOOLS` gives today (`EXPLOITS` is a tuple of closures, so the pairs are compared, not the closures) and write them out as literal `FixCheckExploit` calls in `gravitino_exploits.py`, which takes `FixCheckExploit` from `evals.cve.kit.fix_check` and defines its own `_call`, since the fixture module imports it (precedent `excel_witness_workbook.py`, `n8n_redirect_stand_in.py`), importing only what the kit's import closure in the package docstring allows. The fixture module imports `EXPLOITS` from it and drops the derivation. No behaviour change: before writing, dump the current `EXPLOITS` to a scratch file and compare it to the new tuple.
- **Test**: the tuple equals the one dumped before the change (checked by hand in the loop, not committed), `tests/unit/test_gravitino_fix_check_builder.py`, `tests/unit/test_nuisance_fix_checks.py`, `tests/unit/test_nuisance_re_admission_dossier.py` (the dossier ships the new module) green.
- **Verify**: `uv run python -m evals.run_nuisance fix-check --flaw CVE-2026-41041` exits 0 as recorded, then the closing checks.

### Step 10: Gravitino, seed from the Playground

- **Files**: `tests/unit/test_backend_hostnames.py` (and its `tests/unit/support/test_backend_hostnames_given.py` if it holds the pinned values), `tests/unit/test_gravitino_fix_check_builder.py`, `evals/cve/backends/gravitino.py`, `evals/docker/Dockerfile.gravitino-db`, `evals/cve/nuisance/fix_checks/cve_2026_41041_gravitino.py`, `evals/nuisance_admission.json`, `evals/docker/compose.yml`, `docs/nuisance-suite-log.md`.
- **Do**:
  1. Tests first: in `test_backend_hostnames.py` replace `analytics` with `metalake_demo`, the part aliases `{"gravitino", "postgres", "kafka"}` with `{"gravitino", "postgresql", "kafka"}`, and the catalog's `jdbc-url` with the Playground's (`catalog_postgres`, `jdbc:postgresql://postgresql/db`), and the Kafka catalog's `bootstrap.servers` if its catalog follows a documentation example. In `test_gravitino_fix_check_builder.py` replace `--metalake analytics` with `--metalake metalake_demo`. Run them red.
  2. `Dockerfile.gravitino-db`: the Playground's PostgreSQL user, password and database, and `init/postgres/init.sql` of `apache/gravitino-playground` at `11b37bc618763c2f172f6ae997871a067666389f` (remote `ADD` with checksum and `--chmod=0644`, since a remote `ADD` lands `0600` and owned by root while the image's entrypoint runs as `postgres`) under `/docker-entrypoint-initdb.d`. PostgreSQL release unchanged unless `init.sql` fails to load on it (then record).
  3. `evals/cve/backends/gravitino.py`: metalake `metalake_demo`, catalog `catalog_postgres` with the Playground's properties, db alias `postgresql`, `METALAKE`, `GRAVITINO_SERVER_LAUNCH` and the PostgreSQL probe updated. Fileset, model, tag and policy from the Gravitino documentation examples at v1.2.1. The Kafka topic, statistic and fileset file content stay written. Split the module if it grows past about 300 lines.
  4. Fix-check module: `_PROBES` follows, the patched-arm benign calls follow, the docstring (three mentions of `analytics`) restated. Witness (`hidden`, `secretcat`) and frozen exploits unchanged.
  5. The 26 benign calls naming seeded objects and their expects rewritten from what 1.2.1 returns on the new seed, in the admission and the fix check (`get_job_template_by_name` unchanged). Launch `--metalake metalake_demo` and its `launch` settlement.
  6. Records: the seven seeds (`published_sample` with pin and citation for the Playground parts, `project_document` for the documentation examples, `written` for the rest), the Playground parts left out (Hive, Trino, Spark, Iceberg, MySQL) with their reason, the `software_releases` Gravitino reason reworded, and a log entry that redoes the ratification of 2026-11-11. If the stand-up is far heavier than expected, measure and report before going on.
- **Test**: the two pinned test files green with the new values, the guard tests above.
- **Verify**: `uv run python -m evals.run_nuisance vet --server https://github.com/apache/gravitino` prints `ok`, then `uv run python -m evals.run_nuisance fix-check --flaw CVE-2026-41041` exits 0. `vet` first: `fix-check` rebuilds only the fixture's own services and builds a Gravitino part only when its tag is absent (`_ensure_part_images`), so run first it would stand the old `gravitino-db` image, while `vet` rebuilds the built backend images. Then the plan's closing: the closing checks at the final tree, `current_copy_fingerprints` unchanged, and `uv run python -m evals.run_nuisance vet --server` on each of the ten servers this part touched (ios-simulator, houtini, memory-keeper, git-mcp, mcp-package-docs, ArcadeDB, MySQL, PostgreSQL, sf-mcp, Gravitino).
