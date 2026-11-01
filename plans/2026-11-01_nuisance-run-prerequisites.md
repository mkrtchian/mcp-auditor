# Nuisance run prerequisites

## Context

The nuisance suite admits 59 servers (`evals/nuisance_admission.json`) and its walk now covers the whole draw order. No nuisance run has taken place, and one could not start today:

1. `nuisance_run.run_nuisance` rebuilds the audited servers' images with `docker compose -f evals/docker/compose.yml build <services>` (`run_images.rebuild_images`) and launches each server from `mcp-auditor-nuisance-<service>:local` (`nuisance_images.image_tag`). None of the 59 services is in `evals/docker/compose.yml`, so the first build fails.
2. 14 admitted servers have no run Dockerfile `evals/docker/Dockerfile.<service>`: `android`, `aws-api-mcp`, `biome`, `desktop-commander`, `godot-mcp`, `heim`, `magento2`, `maigret`, `markdownify`, `mysql`, `nmap`, `sf-mcp`, `taskwarrior`, `wireshark`. Each is a holdout twin whose counted flaw recopies the holdout calibration (`fix_check.source = holdout_calibration`), so no nuisance Dockerfile was ever written for it, and `nuisance_images.nuisance_fixture_fingerprint` raises on it. For 13 of them the server-level `patched_version` is the version its holdout patched Dockerfile `Dockerfile.holdout-<id>-<slug>-patched` pins (godot `21c785d` and heim `c321d8a` as abbreviations of the admission's full SHAs), which the holdout calibration already confirmed. Wireshark is the exception: the admission records the tag `v0.2.2` (commit `3901192a`), the holdout patched Dockerfile pins its ancestor `6e56043c`, two commits behind with identical server code (`plans/2026-10-27_nuisance-assembly-batch2.md`, open decision 2, left deferred to the run Dockerfile). Decided by the maintainer: the wireshark run Dockerfile pins the tag's commit `3901192a`, the version the admission and the rule name. The copy of the holdout patched Dockerfile changes on that one pin, noted in its header comment, and the recopied fix check rests on the server code identity of the two commits, already checked.
3. The rule (`docs/nuisance-rule.md`, Run conditions, Images) says that before each nuisance run "every image is built again from its committed Dockerfile, the backend's included when the fixture builds it, with the build cache". The responder backends build their image only when the tag is absent (`responder_backend.Responder._ensure_image`), and so does any other backend the fixture builds, so a responder whose Dockerfile changed after its first build stays stale, and a responder container left running from a calibration keeps serving the old image.
4. The run path of the 13 backend provisioners (`evals/nuisance_provisioners.py`) and of the single-container launch (`nuisance_audit.nuisance_environment`) has run only in unit tests with fakes. The fix checks reached the servers through their own modules. Nothing shows that the 59 servers start and answer their benign calls on the exact launch a run uses.

This plan makes a run startable and proves the wiring without an LLM.

## Decisions (taken with the maintainer)

- A new command, `uv run python -m evals.run_nuisance vet`, rebuilds the run's images, brings up the backends through the run's provisioners and makes each audited server's benign calls through the run's own launch path, with no LLM. It prints a verdict per server and exits 0 when every server answers. All 59 green (the audited population, see below) is this plan's acceptance criterion, and the command serves before every later run to find a broken image without paying for an audit.
- 13 of the 14 run Dockerfiles are copies of the twins' holdout patched Dockerfiles, under the nuisance naming `Dockerfile.<service>`, one per service, so the fingerprint follows the nuisance file and a later holdout edit does not move the nuisance suite silently. The 14th, `mysql`, is server-only, not a copy: the holdout image bakes mysqld and moto in and its entrypoint exports `AWS_ENDPOINT_URL=http://127.0.0.1:5000`, while the nuisance `mysql` backend provisions the engine and the moto stub as separate containers and expects the server image to point at `MOTO_ENDPOINT` (`evals/mysql_backend.py` docstring, `plans/2026-10-28_nuisance-assembly-batch3.md`).
- When `vet` shows that a server does not start or answer on the launch its admission records (an empty `launch`, a `host.working_directory`, a network stance), the fix is a maintainer step done by hand by the assistant inside this plan: the mechanics are taken from the holdout builder of a twin (the launch, the working directory, the seeded start-up files, never the analysis), edited in `nuisance_admission.json`, and logged. No run or gate has taken place, so no baseline is reset. A server whose image does not build, or whose failure is not a launch mechanic, stops the step and is reported to the maintainer.
- The backend images the fixture builds are rebuilt before each run and before each `vet`, through compose, like the server images (point 3 above). This is the rule's text, not a choice.

## Approach

Three layers, in order:

1. **Data and images.** 14 run Dockerfiles, 13 copied from the holdout patched ones and a server-only `mysql`, then one compose service per admitted server (`build.context: .`, `build.dockerfile: Dockerfile.<service>`, `image: mcp-auditor-nuisance-<service>:local`, `build.labels` with the Dockerfile fingerprint). Then one compose service per backend image the fixture builds (the responders and the Neo4j backend), each under the tag its backend module already uses.
2. **Backend rebuild and container hygiene in the run.** The run rebuilds the built backend images with the server images, removes the running containers of the built backend images before the rebuild (the refusal stays on server containers), and its end-of-run removal covers the built backend images too. Pulled backend images (Doris, its MySQL client, the MySQL and moto images of the `mysql` backend) are pinned by digest and pulled, not built, so they are left as they are.
3. **The `vet` command**, built on the same pieces as the run: `run_population`, the rebuild, `nuisance_vetting.vet_all` and `nuisance_vetting.benign_call`.

Then the maintainer runs `vet` under Docker, fixes the launch mechanics of any red server, and the plan closes when all 59 are green.

## Files

### `evals/docker/Dockerfile.<service>` (14 new files)

For 13 services, a copy of the twin's `Dockerfile.holdout-<id>-<slug>-patched`, instructions unchanged, with a header comment naming the holdout file it copies and the patched version it pins. Map, from the holdout fixtures in `evals/holdout_fixtures/` (the patched service is `holdout-<id>-<slug>-patched`, a top-level `PATCHED` constant in some fixtures only):

| nuisance service | holdout fixture |
|---|---|
| `android` | `cve_2026_19978_android.py` |
| `aws-api-mcp` | `cve_2026_4270_aws_api_mcp.py` |
| `biome` | `cve_2026_3680_biome.py` |
| `desktop-commander` | `cve_2025_11489_desktop_commander.py` |
| `godot-mcp` | `cve_2026_25546_godot_mcp.py` |
| `heim` | `cve_2026_5602_heim.py` |
| `magento2` | `cve_2026_5603_magento2.py` |
| `maigret` | `cve_2026_2130_maigret.py` |
| `markdownify` | `cve_2025_58358_markdownify.py` |
| `mysql` | `cve_2026_85788_mysql.py` |
| `nmap` | `cve_2026_3484_nmap.py` |
| `sf-mcp` | `cve_2026_26029_sf_mcp.py` |
| `taskwarrior` | `cve_2026_5833_taskwarrior.py` |
| `wireshark` | `cve_2026_7785_wireshark.py` |

`mysql` (the table's holdout row gives the version only): a server-only image, `awslabs.mysql-mcp-server==1.0.23` and `mcp<2` on `python:3.12-slim` pinned by digest (decided by the maintainer at diligence: the server talks only to the moto stub over HTTP and needs no MySQL in its image, and a base of its own keeps it apart from the backend's `mysql:8.0.46` digest; `awslabs.mysql-mcp-server` 1.0.23 requires Python >=3.10; the digest is read on the pulled image with `docker image inspect --format '{{index .RepoDigests 0}}'`, as for every pinned base), no mysqld, no moto, no seeding, `ENV` carrying `AWS_ENDPOINT_URL` set to `MOTO_ENDPOINT` (`http://mcp-auditor-cve-mysql-moto:5000`), dummy `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (`testing`, the values the holdout entrypoint and the backend's seed use), `AWS_DEFAULT_REGION=us-east-1`, `AWS_SHARED_CREDENTIALS_FILE=/dev/null`, `AWS_CONFIG_FILE=/dev/null`, `ENTRYPOINT ["python3", "-m", "awslabs.mysql_mcp_server.server"]`. Its header comment names the holdout file it derives from and why it differs.

Before copying, the implementer checks that the version the holdout patched Dockerfile pins equals the admission's server-level `patched_version` for each of the 14 (an abbreviated SHA in the Dockerfile matches when it is a prefix of the admission's full SHA, as for godot and heim), and stops and reports on a mismatch rather than editing either side. Wireshark is a known mismatch, settled in Context, point 2: its copy pins `3901192a`. A holdout patched Dockerfile that seeds something only the holdout needs (a planted place, a layout path) is copied as is if the server starts with it, since the nuisance run plants nothing in it anyway, and the difference is noted in the header comment.

### `evals/docker/compose.yml`

One service per admitted server (59), grouped under a comment marking the nuisance namespace, in the shape of the existing services:

```yaml
  calc:
    build:
      context: .
      dockerfile: Dockerfile.calc
      labels:
        org.mcp-auditor.dockerfile-fingerprint: "<dockerfile_fingerprint('calc')>"
    image: mcp-auditor-nuisance-calc:local
```

And one service per built backend image, named so that `cve_targets.image_tag(service)` gives the tag the backend module uses (`ckan-responder` for `mcp-auditor-cve-ckan-responder:local`, and so on for `contextforge`, `n8n`, `atlassian`, `apify`, `jenkins`, `gitlab`, `googleapis`, `facebook-ads`, `figma`, and `neo4j-backend`). The implementer lists the built backend images from the backend modules' image constants and their `Dockerfile` constants, skips any already present in `compose.yml` (a holdout target may already build one), and adds the rest. The labels are computed with `cve_images.dockerfile_fingerprint`, never by hand.

Every new service, server or backend, carries `profiles: ["nuisance"]` (decided by the maintainer at diligence), so a bare `docker compose -f evals/docker/compose.yml build`, the documented prerequisite of the CVE benchmark, builds what it builds today and a broken nuisance Dockerfile cannot fail it. The run and `vet` name their services on the command line (`run_images.rebuild_images`), and Compose enables the profile of a service named on the command line, so they need no `--profile` flag. The implementer confirms that behavior on the installed Compose before relying on it (`docker compose --dry-run -f evals/docker/compose.yml build calc` builds the profiled service, a bare `docker compose ... config --services` does not list it; checked at review on Compose v5.6.1 with a scratch compose file: `build <profiled service>` builds it, while `config --services <profiled service>` does **not** list it, so `config` is no test of the behavior), and adds `--profile nuisance` to `rebuild_images`'s nuisance callers if it does not hold. The header comment of `compose.yml` gains a paragraph on the nuisance block, its profile, and how to build it by hand (`--profile nuisance`).

### `evals/nuisance_backends.py`

`RegisteredBackend` gains `built_service: str | None`, the compose service that builds its image, `None` for a pulled image (`doris`, `mysql`). A helper `built_backend_services(servers) -> list[str]` returns the deduplicated services of the audited servers' backends. A unit test pins that every backend whose image tag is in the `mcp-auditor-cve-` namespace with a local tag has a `built_service`, and that `cve_targets.image_tag(built_service)` equals the entry's `RegisteredBackend.image`. A helper `built_backend_tags(servers) -> list[str]`, `cve_targets.image_tag` over `built_backend_services`, gives the run and `vet` (its two callers) the backend tags to refuse and sweep.

### `evals/nuisance_run.py`

- `_services` is unchanged. The rebuild call becomes `deps.rebuild([*services, *built_backend_services(population.audited)])`.
- Built backend containers are **removed, not refused**, at the start (decided by the maintainer at diligence): before the rebuild, the run removes the running containers of the built backend tags of the audited servers, so a responder left running by a calibration is replaced by one started from the fresh image when its provisioner next ensures it, with no hand `docker rm` after each calibration. A responder is a stateless stand-in this repository owns, unlike a server container, which may be an audit in progress, so the refusal stays on the server tags only. A run and a calibration must not overlap on one machine, stated in the docs. The end-of-run removal covers the server tags and the built backend tags. Not `_backend_images` (kept for provenance only): it also holds the pulled `DORIS_IMAGE` and `MYSQL_IMAGE`, whose containers are persistent by design (the Doris cluster, the MySQL engine) and cannot serve a stale build, and `docker ps --filter ancestor=<mysql digest>` would also match every container of an image built `FROM` that digest. Removing them at each run's end would cost a Doris cold start per run for nothing.
- `nuisance_run.py` is at 296 lines: if these lines take it past 300, the change splits it (the container hygiene, `_refuse_running_containers` and the tag list, is the natural seam) rather than letting it grow.
- The backend removal runs before the rebuild: after the rebuild, `ancestor=<tag>` resolves to the new image and would no longer match a container started from the previous build.

### `evals/nuisance_vet_command.py` (new) and `evals/run_nuisance.py`

`vet` subcommand: `--census`, `--walk-record`, `--admission` (defaults as for `run`), `--server PKG` (repeatable, restricts to these audited servers), `--concurrency` (default `NUISANCE_CONCURRENCY`), `--tool-call-timeout` (default from `evals/holdout_conditions.json`, the run's own timeout, falling back to `cve_environments.TOOL_CALL_TIMEOUT` when the conditions leave it `None`, as `nuisance_run.default_deps` does). A `--server` naming no audited server (unknown, acceptance or excluded) prints it and exits `UNKNOWN_SERVER_EXIT` (2), as `calibrate --cve` does.

```python
async def vet_servers(
    servers: Sequence[AdmittedServer], deps: VetDeps
) -> VetResult: ...
```

`VetDeps` groups the rebuild, the running-container lookup and removal, and the bounded benign call, injected like `NuisanceDeps`, so the orchestration is unit-tested with fakes. Order, as in the run: refuse when a container of the vetted server images is running, remove the running containers of the built backend images, rebuild, refuse again on the server images, `vet_all`, remove the containers of the server and built backend images, return the not-run list and the surviving list. The command prints one line per server (`ok` or the reason `vet_all` records), then `<k> of <n> servers answer their benign calls`, and exits 0 when all answer, 1 when one fails, 3 (`REFUSED_EXIT`) on a refusal or malformed input, 4 (`CRASHED_EXIT`) on a crash, mirroring `calibrate`. `run_nuisance.main` catches only `Refused` and `ProviderFatal`, so an uncaught exception (the `RuntimeError` of a failed `rebuild_images`, a failed `docker ps`) would exit 1 and read as "a server fails": the vet handler catches it, prints it, and returns `CRASHED_EXIT`. `benign_call` already turns a launch or call failure into a reason, so only the orchestration can crash. It needs Docker and no LLM key, refuses nothing about tracing or a dirty tree (it writes no result), and does not write a report file. The population is `run_population(...).audited`, so an acceptance server or an excluded one is not vetted, as a run would not audit it. `nuisance_vet_command.py` holds `add_vet_arguments(parser)` (setting the handler with `set_defaults(command=...)`, the key `run_nuisance.main` dispatches on), the handler, `VetDeps` with its default builder and `vet_servers`. `run_nuisance._parser` only registers the subparser, as it does for `calibrate` (`add_calibrate_arguments`) and `gate` (`add_gate_arguments`), so `run_nuisance.py` (236 lines) stays under 300.

### `evals/nuisance_admission.json` (maintainer step only)

Edits of `launch` and `host` only, on the servers `vet` shows red for a launch mechanic, each with a `docs/nuisance-log.md` entry. No other field moves.

### Tests

- `tests/unit/test_cve_compose_labels.py`: already labels every compose service, so the 59 new services and the backend services are covered without change. New: every admitted server's `service` is a compose service whose `image` is `nuisance_images.image_tag(service)`, and every `RegisteredBackend.built_service` is a compose service whose `image` is the backend's tag. Placed in `tests/unit/test_nuisance_images.py` or a new `tests/unit/test_nuisance_compose.py` (real data, like `test_nuisance_admission_loads.py`).
- `tests/unit/test_nuisance_backends_built.py` (new, beside `test_nuisance_backends_responders.py`: `test_nuisance_backends.py` is at 284 lines and would cross 300): the real-data pin on `built_service` above, and `built_backend_services` on fixture servers (two servers on one backend give one service, a pulled backend gives none).
- `tests/unit/test_nuisance_run_backends.py` (new, on `tests.unit.support.test_nuisance_run_given` as `test_nuisance_run_interrupted.py` is: `test_nuisance_run.py` is already at 455 lines, past the 300-line limit, so it takes no more tests): the rebuild receives the backend service, a running built-backend container is removed before the rebuild and does not refuse the run, a running server container still refuses, the end-of-run removal covers built-backend tags, and a pulled backend's image (Doris) is neither refused nor swept.
- `tests/unit/test_nuisance_vet.py` (+ given/then where they abstract something): all answering gives exit 0 and the count line; one failing gives exit 1 and its reason; a running server container refuses before the rebuild; a running responder container is removed and the vet goes on; a failing rebuild gives exit 4; `--server` restricts; `--server` naming an unknown or acceptance server gives exit 2; an acceptance server is not vetted.
- `tests/unit/test_run_nuisance.py`: the `vet` subcommand parses and wires its defaults (existing CLI pattern, with the fixture census, walk record and admission).
- `tests/unit/test_nuisance_fixture_fingerprint_*` or the existing fingerprint test: `nuisance_fixture_fingerprint` computes for every admitted server on the real data (it raised on the 14 before).

## What stays unchanged

- The holdout: its fixtures, its patched Dockerfiles (copied, not edited), its run and its kit. The holdout's own backend rebuild behavior is out of scope.
- `docs/nuisance-rule.md`: the rule already requires all of this.
- The counter, the statistic, the report, the gate, the walk and the walk record.
- `nuisance_admission.json`, except `launch` and `host` of servers `vet` shows red for a launch mechanic.
- The fix-check modules and `run_nuisance calibrate`.
- The pulled backend images (Doris, MySQL client, the `mysql` backend's images): pinned by digest, not built.

## Edge cases

- A built backend image already a compose service for a holdout target: reused, not duplicated.
- Two servers on one backend: one rebuild, one running responder shared by both, as the provisioners already serialise the stand-up.
- A server red on `vet` whose image builds and starts but whose benign call errors because the call itself is wrong (argument, tool name): a data defect of the admission, not a launch mechanic, so stop and report.
- A twin whose holdout patched Dockerfile pins a version other than the admission's: stop and report, no edit.
- `vet` interrupted: containers of the vetted images may be left running. The next `vet` or run refuses until they are removed, as a run already does. The message names `docker rm -f` with the labels, as the run's does.
- One image that does not build fails the whole `docker compose build` of the vetted services, so `vet` exits 4 without vetting any server: the compose output tail names the service, and `--server` vets the others meanwhile.
- `vet`'s reasons are the run's own (`TYPES_ONLY`, server stderr to `/dev/null`), so a red server says what failed, not why: diagnosing it is a `docker run -i` of the image by hand, outside the command.
- Disk: 59 server images plus the backends. The maintainer step checks `df -h /` before the first full `vet` and may vet in groups with `--server`.

## Test scenarios

1. Compose coverage, real data: every admitted service and every `built_service` is a compose service with the right tag and a fingerprint label equal to `dockerfile_fingerprint`.
2. Fingerprint, real data: `nuisance_fixture_fingerprint` returns for all 59 servers.
3. `built_backend_services`: dedupes, skips pulled backends, skips servers with no backend.
4. Run orchestration with fakes: the rebuild list holds the backend service; a running built-backend container is removed before the rebuild and does not refuse the run, while a running server container still refuses; the end-of-run removal is called with built-backend tags; a pulled backend image is in neither.
5. `vet_servers` with fakes, asserted on outcomes as the run's container tests are (`test_nuisance_run.py`), never on the call sequence: a container running at start refuses with nothing rebuilt, a container seen only after the rebuild refuses and is left running, the containers left at the end are removed, exit codes 0, 1, 2 (unknown `--server`), 3, 4 (failed rebuild), the count line, `--server`, an acceptance server left out.
6. Every new Dockerfile passes `test_no_dockerfile_copies_from_the_build_context` and `test_every_base_image_is_pinned_by_digest` (existing parametrized tests, nothing to add).

## Steps outline (refined by the breakdown pass)

1. The 14 run Dockerfiles (13 copies, the server-only `mysql`) and the 59 server compose services, with the real-data compose and fingerprint tests.
2. Built backend services in compose, `RegisteredBackend.built_service`, the run's backend rebuild and container hygiene.
3. The `vet` command.
4. Maintainer step, done by hand by the assistant: `df -h /`, then `uv run python -m evals.run_nuisance vet` under Docker (in groups if disk demands), fix the launch mechanics of red servers in `nuisance_admission.json` with log entries, until 59 green. Report anything that is not a launch mechanic. Present the admission diff for review before commit. If the classifier cuts reading a holdout builder, switch to Opus 4.8.
5. Living docs: `CLAUDE.md` Commands (the `vet` line, and the `run` line's note that built backend images rebuild and their running containers are replaced, and that a run and a calibration must not overlap; the `docker compose` build line's note that nuisance services sit under the `nuisance` profile), `CONTRIBUTING.md` (the nuisance paragraph: run prerequisites in place, `vet` before a run), `CHANGELOG.md` `[Unreleased]`, `docs/nuisance-log.md` (the launch edits, and one entry stating that all 59 answered their benign calls on the run's launch path at a named commit).

Commits: one per step, each after the maintainer's go on the diff, the admission edits in their own commit.

## Verification

```bash
uv run pytest tests/unit -n auto --maxprocesses 4
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
docker compose -f evals/docker/compose.yml config --quiet        # compose parses
uv run python -m evals.run_nuisance vet                           # Docker, no LLM: 59 of 59
```

## Due diligence record

What the due-diligence pass concluded, on 2026-11-01, about the external facts this plan cites or defers, read by the implementation-phase fact check. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `git checkout 3901192a47a34d74ecd127c65dcbab9f95acdc84` (wireshark run Dockerfile): the tag `v0.2.2` of `https://github.com/A-G-U-P-T-A/wireshark-mcp.git` points at this commit, and `6e56043c..3901192a` holds two commits (a Pages workflow, docs, `.gitignore`, `README.md`, a docs build script) touching no server code (verified with `git ls-remote` and `git diff --stat` on the live repository).
- SETTLED: `"awslabs.mysql-mcp-server==1.0.23"` exists on PyPI (uploaded 2026-07-02, `requires_python >=3.10`) (verified against `https://pypi.org/pypi/awslabs.mysql-mcp-server/1.0.23/json`).
- SETTLED: `mysql:8.0@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b` is the digest the holdout mysql Dockerfiles already pin and the same digest as the admission's backend image `mysql:8.0.46@sha256:7dcd...`, present locally (verified against `evals/docker/Dockerfile.holdout-2026-85788-mysql-patched`, `evals/nuisance_admission.json` and `docker images --digests`, not against Docker Hub).
- SETTLED: the patched versions the 13 copied holdout Dockerfiles pin equal the admission's `patched_version` (godot `21c785d` and heim `c321d8a` as prefixes, taskwarrior through `ARG COMMIT`) (verified locally against `evals/docker/Dockerfile.holdout-*-patched` and `evals/nuisance_admission.json`, for the git-pinned ones; the package-pinned ones, aws-api-mcp `1.3.9`, maigret `1.0.13`, desktop-commander `0.2.33`, markdownify `a31204de058b`, read equal).
- SETTLED: `MOTO_ENDPOINT` is `http://mcp-auditor-cve-mysql-moto:5000` (verified against `evals/mysql_backend.py`).
- OPEN (deferred): the `launch` and `host` edits to `nuisance_admission.json` for servers `vet` shows red, values produced only by the maintainer step from the twins' holdout builders.
- OPEN (deferred): the `org.mcp-auditor.dockerfile-fingerprint` labels of the new compose services, computed at implementation with `cve_images.dockerfile_fingerprint`.

## Implementation steps

The plan's outline steps 4 and 5 are refolded: the living docs ship with the code that changes them (steps 2 and 3, per `CLAUDE.md` Workflow), and the `docs/nuisance-log.md` entries ship with the maintainer step that produces them (step 4). Step 4 is a maintainer step, done by hand by the assistant, not dispatched to an implementer.

Commands used throughout: the short loop `uv run pytest tests/unit -n auto --maxprocesses 4`, `uv run pyright <changed files>` in the loop. Every step closes with `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .` and `uv run pyright` with no file argument.

### Step 1: Run Dockerfiles and the 59 server compose services

**Files**
- `tests/unit/test_nuisance_compose.py` (new, real data)
- `tests/unit/test_nuisance_images.py` (one real-data fingerprint test added, or in the new file if `test_nuisance_images.py` would pass 300 lines)
- `evals/docker/Dockerfile.{android,aws-api-mcp,biome,desktop-commander,godot-mcp,heim,magento2,maigret,markdownify,mysql,nmap,sf-mcp,taskwarrior,wireshark}` (14 new)
- `evals/docker/compose.yml` (59 server services, header paragraph)

**Do**
1. Tests first:
   - `test_nuisance_compose.py`: load `evals/nuisance_admission.json` as `test_nuisance_admission_loads.py` does, load `compose.yml` as `test_cve_compose_labels.py` does. Test: every admitted server's `service` is a compose service whose `image` is `nuisance_images.image_tag(service)`, and whose `profiles` is `["nuisance"]`. The fingerprint label of each is already checked by the existing parametrized `test_each_compose_service_is_labeled_with_its_dockerfile_fingerprint`, no duplicate.
   - Real-data fingerprint: `nuisance_fixture_fingerprint` returns (does not raise) for every admitted server.
   - Run them: both red (no services, 14 Dockerfiles missing).
2. Before copying, for each of the 13 copied services, read the twin's holdout fixture in `evals/holdout_fixtures/` (table in Files) to find its patched service `holdout-<id>-<slug>-patched`, and check that the version its `Dockerfile.holdout-<id>-<slug>-patched` pins equals the admission's server-level `patched_version` (an abbreviated SHA matches as a prefix of the full one, taskwarrior through `ARG COMMIT`). On a mismatch other than wireshark's: stop and report, edit neither side.
3. Copy the 13 holdout patched Dockerfiles to `Dockerfile.<service>`, instructions unchanged, with a header comment naming the holdout file and the patched version. Wireshark: the one change is the checkout pin to `3901192a47a34d74ecd127c65dcbab9f95acdc84` (tag `v0.2.2`), the header noting it and the server-code identity with `6e56043c`. A holdout-only seed (planted place, layout path) stays as is, noted in the header.
4. Write `Dockerfile.mysql` as the plan's Files section specifies (server-only, `python:3.12-slim@sha256:...` digest read with `docker pull python:3.12-slim` then `docker image inspect --format '{{index .RepoDigests 0}}'`, `pip install "awslabs.mysql-mcp-server==1.0.23" "mcp<2"`, the `ENV` block with `AWS_ENDPOINT_URL=http://mcp-auditor-cve-mysql-moto:5000` and the dummy credentials, the `ENTRYPOINT`), header naming `Dockerfile.holdout-2026-85788-mysql-patched` and why it differs. No `COPY` from the build context.
5. Append to `compose.yml`, after the existing services, a commented nuisance block: one service per admitted server (59), shape as in the plan (`build.context: .`, `build.dockerfile: Dockerfile.<service>`, `build.labels` fingerprint, `image: mcp-auditor-nuisance-<service>:local`, `profiles: ["nuisance"]`). Compute every label with `cve_images.dockerfile_fingerprint(service)` from a throwaway script in the scratchpad, never by hand. Add the header paragraph: the nuisance block, its profile, building it by hand with `docker compose -f evals/docker/compose.yml --profile nuisance build`.
6. Confirm the profile behavior on the installed Compose: `docker compose -f evals/docker/compose.yml config --services` does not list `calc`, and `docker compose --dry-run -f evals/docker/compose.yml build calc` builds the profiled service (`config --services calc` is no test: it does not list a profiled service even when named). If naming a service does not enable its profile, note it for step 2, which then adds `--profile nuisance` to the nuisance callers of `rebuild_images`.

**Test**
- Every admitted service is a compose service with tag `mcp-auditor-nuisance-<service>:local` and profile `nuisance`.
- `nuisance_fixture_fingerprint` returns for all 59 servers.
- Existing parametrized tests pass on the 14 new Dockerfiles: fingerprint label, `test_no_dockerfile_copies_from_the_build_context`, `test_every_base_image_is_pinned_by_digest`.

**Verify**
- `uv run pytest tests/unit/test_nuisance_compose.py tests/unit/test_nuisance_images.py tests/unit/test_cve_compose_labels.py` green.
- `docker compose -f evals/docker/compose.yml config --quiet` exits 0.
- Closing checks green.

### Step 2: Built backend services, `built_service`, and the run's backend rebuild and container hygiene

**Files**
- `tests/unit/test_nuisance_backends_built.py` (new)
- `tests/unit/test_nuisance_run_backends.py` (new, on `tests.unit.support.test_nuisance_run_given`, as `test_nuisance_run_interrupted.py`)
- `tests/unit/test_nuisance_compose.py` (one test added)
- `evals/docker/compose.yml` (backend services)
- `evals/nuisance_backends.py`
- `evals/nuisance_run.py` (and, if it crosses 300 lines, a new `evals/nuisance_run_containers.py` holding the container hygiene)
- `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`

**Do**
1. Tests first:
   - `test_nuisance_backends_built.py`: real-data pin, every `BACKENDS` entry (the registry dict in `nuisance_backends.py`) whose image is a local `mcp-auditor-cve-` tag has a `built_service`, and `cve_targets.image_tag(built_service) == entry.image`; pulled ones (`doris`, `mysql`) have `None`. `built_backend_services` on fixture servers: two servers on one backend give one service, a pulled backend gives none, a server with no backend gives none. `built_backend_tags` maps through `cve_targets.image_tag`.
   - `test_nuisance_compose.py`: every non-`None` `built_service` is a compose service whose `image` is the backend's tag.
   - `test_nuisance_run_backends.py`, asserting on outcomes through the fakes of `test_nuisance_run_given`: the rebuild receives the backend service; a built-backend container running at start is removed and the run goes on (no refusal); a server container running at start still refuses; the end-of-run removal covers built-backend tags; a pulled backend's image (Doris) is neither refused nor swept. `test_nuisance_run_given.py` is already at 324 lines and `deps_auditing` fakes the rebuild as `lambda services: None`: put any new given (a server with a backend, a recording rebuild, a running container on a tag) in a new `tests/unit/support/test_nuisance_run_backends_given.py` building on it (e.g. `dataclasses.replace(deps_auditing(...), rebuild=...)`), not in the over-limit file. `RunningContainers` (from `test_holdout_run_given`) already models running containers per tag.
2. `compose.yml`: list the built backend images from the backend modules' image constants and their Dockerfile constants (ckan, contextforge, n8n, atlassian, apify, jenkins, gitlab, googleapis, facebook-ads, figma responders, and `neo4j-backend`), skip any already a compose service, add the rest in the nuisance block with `profiles: ["nuisance"]`, service named so that `cve_targets.image_tag(service)` is the module's tag, `dockerfile` the module's Dockerfile, label from `cve_images.dockerfile_fingerprint`.
3. `nuisance_backends.py`: `RegisteredBackend.built_service: str | None`, set on every entry. `built_backend_services(servers) -> list[str]` (deduplicated, order-stable) and `built_backend_tags(servers) -> list[str]`.
4. `nuisance_run.py`: in the same order as `vet` (Files section), after the first refusal on the server tags has passed and before the rebuild, remove the running containers of `built_backend_tags(population.audited)` (through `deps.running_containers` and `deps.remove_containers`), so a refused run touches nothing. Call `remove_containers` only when the listing is non-empty: `remove_containers([])` runs a bare `docker rm -f`. A failed listing here is not swallowed (unlike `sweep_containers` at the end, no run result is at stake yet). Rebuild `[*services, *built_backend_services(population.audited)]` (plus `--profile nuisance` in the rebuild path only if step 1 found it necessary). The refusal stays on the server tags. The end-of-run sweep covers server tags and built-backend tags. `_backend_images` is left as is (provenance). If the file passes 300 lines, move the container hygiene (`_refuse_running_containers`, the backend removal, the tag lists) into `evals/nuisance_run_containers.py`, a seam step 3 reuses.
5. Living docs: `CLAUDE.md` Commands, the `run` line notes that the built backend images are rebuilt with the server images and their running containers replaced, and that a run and a calibration must not overlap on one machine; the `docker compose ... build` line notes that the nuisance services sit under the `nuisance` profile (`--profile nuisance` to build them by hand). `CONTRIBUTING.md`, the nuisance `run` paragraph: its "(a backend image, such as the persistent Doris cluster, is never checked)" becomes false for the built backend images, so it says that the built backend images (the responders, Neo4j) are rebuilt with the server images and their running containers removed at the start and the end, the pulled ones (Doris, the `mysql` backend's) left alone, and that a run and a calibration must not overlap; and the Dockerfile paragraph (line 14) notes the `nuisance` profile. `CHANGELOG.md` `[Unreleased]`: the run rebuilds the built backend images and replaces their running containers.

**Test**
- `built_service` pin on real data, the three `built_backend_services` cases, `built_backend_tags`.
- Compose coverage of every `built_service`.
- The five run orchestration outcomes above.

**Verify**
- `uv run pytest tests/unit/test_nuisance_backends_built.py tests/unit/test_nuisance_run_backends.py tests/unit/test_nuisance_run.py tests/unit/test_nuisance_run_interrupted.py tests/unit/test_nuisance_compose.py tests/unit/test_cve_compose_labels.py` green.
- `docker compose -f evals/docker/compose.yml config --quiet` exits 0.
- Closing checks green.

### Step 3: The `vet` command

**Files**
- `tests/unit/test_nuisance_vet.py` (new), with `tests/unit/support/test_nuisance_vet_given.py` and `..._then.py` only where they abstract something
- `tests/unit/test_run_nuisance.py` (vet parse test; if it would pass 300 lines, a new `tests/unit/test_run_nuisance_vet.py` on `test_run_nuisance_given`)
- `evals/nuisance_vet_command.py` (new)
- `evals/run_nuisance.py` (registers the subparser only)
- `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`

**Do**
1. Tests first, `vet_servers` and the handler with fake `VetDeps`, asserted on outcomes as the run's container tests are, never on call order: all answering gives exit 0 and `<n> of <n> servers answer their benign calls`; one failing gives exit 1 and its reason line; a server container running at start refuses (exit 3) with nothing rebuilt; a server container seen only after the rebuild refuses and is left running; a running responder container is removed and the vet goes on; the containers left at the end (server and built-backend tags) are removed; a failing rebuild (`RuntimeError`) gives exit 4 and prints the error; `--server` restricts to the named servers; `--server` naming an unknown, acceptance or excluded server prints it and exits `UNKNOWN_SERVER_EXIT` (2); an acceptance server is not vetted without `--server`. CLI test: `vet` parses with the fixture census, walk record and admission, and wires `--concurrency` (default `NUISANCE_CONCURRENCY`) and `--tool-call-timeout` (default the conditions' timeout, else `cve_environments.TOOL_CALL_TIMEOUT`).
2. `nuisance_vet_command.py`: `VetDeps` (rebuild, running-container lookup, removal, bounded benign call), its default builder (`rebuild_images`, `running_containers`, `remove_containers`, `nuisance_vetting.benign_call` with the timeout, bounded by concurrency through `nuisance_vetting.vet_all`), `async def vet_servers(servers: Sequence[AdmittedServer], deps: VetDeps) -> VetResult` in the run's order (refuse on server tags, remove built-backend containers, rebuild servers plus `built_backend_services`, refuse again, `vet_all`, sweep server and built-backend tags in a `finally`), `add_vet_arguments(parser)` with `set_defaults(command=...)` (`run_nuisance.main` calls `args.command(args)`), the handler: input loaded under `malformed_input_refused()`, an absent or empty admission printing that no server is admitted and exiting 0 as `run` does, population `run_population(...).audited`, `--server` filter, printing one line per server (`ok` or the reason) and the count line, exit 0/1/2/3/4; as `nuisance_gate_command.gate` does, it re-raises `Refused` (which `main` prints and maps to `REFUSED_EXIT`, malformed input included) and turns any other exception into a printed traceback and `CRASHED_EXIT` (4). `VetResult` is the `(not_run, surviving)` pair `vet_all` returns, a named dataclass if the handler reads it by field. No tracing or dirty-tree refusal, no report file, no LLM key. Reuse the container-hygiene seam of step 2.
3. `run_nuisance.py`: register the `vet` subparser through `add_vet_arguments`, as for `calibrate` and `gate`.
4. Living docs: `CLAUDE.md` Commands, the `vet` line (what it does, Docker, no LLM, `--server`, exit codes); `CONTRIBUTING.md` nuisance paragraph, run prerequisites in place and `vet` before a run; `CHANGELOG.md` `[Unreleased]`, the `vet` command.

**Test**
- The ten `vet_servers`/handler outcomes and the CLI parse test above.

**Verify**
- `uv run pytest tests/unit/test_nuisance_vet.py tests/unit/test_run_nuisance.py` green.
- `uv run python -m evals.run_nuisance vet --help` prints the options.
- Closing checks green.

### Step 4: Maintainer step, vet all 59 under Docker (hand-done by the assistant, not dispatched)

**Files**
- `evals/nuisance_admission.json` (`launch` and `host` of red servers only, own commit)
- `docs/nuisance-log.md`

**Do**
1. `df -h /`, then `uv run python -m evals.run_nuisance vet` (in groups with `--server` if disk demands).
2. For a server red on a launch mechanic: take the mechanic from the twin's holdout builder (launch, working directory, seeded start-up files, never the analysis), edit `launch`/`host` in the admission, log each edit in `docs/nuisance-log.md`, re-vet. A server whose image does not build, or whose benign call fails on its own argument or tool name, stops the step and is reported. If the classifier cuts reading a holdout builder, switch to Opus 4.8.
3. When 59 of 59 answer: a `docs/nuisance-log.md` entry stating it at the named commit. Present the admission diff for review before commit.

**Verify**
- `uv run python -m evals.run_nuisance vet` prints `59 of 59 servers answer their benign calls` and exits 0.
- Closing checks green (the admission edits move fingerprints only, no test pins them).
