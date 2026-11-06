# Holdout calibration vesting: the version 11 campaign's 37 targets

## Context

The calibration campaign under version 11 of the holdout rule is finished, and the holdout log entry of commit `a674bed` records its outcome: the holdout holds 37 targets, the 30 drawn and 7 the replayed walk let in (CVE-2025-65719, CVE-2026-15415, CVE-2026-53710, CVE-2026-47394, CVE-2026-35402, CVE-2026-82112, CVE-2026-46514), and 29 flaws are excluded after two give-ups. None of it is in the repository yet. `HOLDOUT_TARGETS` (`evals/holdout_targets.py`) and `draw.drawn` in `evals/holdout_census.json` still list CVE-2026-18905 and CVE-2026-45555, both now excluded, and lack the two walk replacements CVE-2026-85787 (position 88) and CVE-2026-44717 (position 90), so "the 30 drawn" holds for 28 of the repository's 30: 9 targets are new to the repository and 2 leave it. The census was last changed at `75a7cc7`: no act of versions 10 or 11 is recorded in it, so the `a674bed` sentence "their reasons in the census" is not yet true. Every committed card leaves the fields versions 9 and 11 add unset and every card check is unversioned, so `run_holdout run` refuses every target today.

This plan carries the campaign's results into the repository: the fixtures, Dockerfiles, compose services and builders of the 37 targets from their authoritative calibration kits, the corrections the maintainer's readings attached to them, the census acts of the re-walk, the agent records, and the logs and living docs. All the facts it relies on are gathered in the vesting manifest. The maintainer's calibration kits and the vesting manifest are held outside the repository, and the maintainer gives their location to the implementer at launch. Every claim of the manifest this plan relies on was checked against the code at `39fc0ff`, and the section "What the code says against the manifest" records where it differs.

A target is vested when `run_holdout calibrate --cve <ID>` is green on the repository's harness: its exploits surface the nonce of every kept place on the vulnerable image, the benign call surfaces none on either version and returns no error on the patched one, no exploit surfaces a nonce on the patched image, and every kept layout place has a route. Calibration needs Docker and no LLM. No scored holdout run happens here.

## Decisions

These are the maintainer's, applied as stated.

1. **A fallen-back agent is one record with two models.** `AgentRecord` gains `fallback_model: str | None = None`, the model that answered when it differs from the one requested, which `model` keeps. Every authoritative calibration, card and card check of the 37 was requested on `claude-opus-5-5` and answered by `claude-opus-4-8` (manifest 1c), so each of their records carries `model="claude-opus-5-5"` and `fallback_model="claude-opus-4-8"`. One row per agent, so two rows of one role and scope always mean two agents (a first and a second calibration), never one agent under two models.
2. **More than two give-ups under version 11: only the governing pair is recorded.** CVE-2026-77252 gets its round 8 pair, CVE-2026-33980 its round 6 pair, and CVE-2026-46514, which enters with a card, gets no version 11 give-up (a card and two give-ups under one version are refused at load). The void and redone pairs go to the holdout log with their reasons: 77252's round 5 (redone after triage), round 6 (void, the instructions said the maintainer lacked a public test license) and round 7 (inadmissible), 33980's round 5, 46514's rounds 5 and 6, 82112's round 5 (void, the instructions on the emulator omitted that the real software runs when distributable), GHSA-8g7g-hmwm-6rv2's pair of 2026-11-03 (void, the attacker-controlled endpoint exemption was missing) and CVE-2026-5602's round 4 (void, the "real CLI or give up" instruction was too strict). `GiveUp.calibration` stays `Literal[1, 2]`.
3. **CVE-2025-66335's `grammar_class` settlement is removed**, with the five void ones (decision in "The census edit").
4. **CVE-2026-25546's base project leaves `/work`.** The image bakes it at `/opt/base-project`, the two `create_scene` exploits take that path in their arguments, and `calibrate` proves the target again. It is logged as a fix of the harness convention (a CVE target's `/work` is the per-launch tmpfs and is never baked), not a change of the target: the path is neither a place nor seeded in the layout.
5. **The real software's stable release.** The reading the `a674bed` entry logs (the stable release is the one of the install channel the documentation names, otherwise the latest the project published) was applied to the five targets whose release was not checked under it. CVE-2026-5603: confirmed, n98-magerun2 10.1.0 (published 2026-10-07, the latest on the calibration day). PHP 8.2 is magerun2's runtime, not a real software the server calls ("The real software" paragraph of the rule), so it stays and is not a gap. CVE-2026-19978: adb 29.0.6 from Debian, where the documentation names the Platform-Tools download, whose stable release on 2026-11-05 was 37.0.1. CVE-2025-9654: OpenSSH 9.2p1 from Debian, where the documentation names no channel, so the latest the project published, OpenSSH 10.6p1 (2026-10-06). CVE-2026-85787: PostgreSQL 16.15, where the latest the project published is 18.6 (2026-08-13). CVE-2026-85788: MySQL 8.0.46, where the documentation names no channel, so the latest GA the project published on the calibration day, MySQL 26.10.0 (2026-10-20, released the same day as the 9.7.4 LTS, the official image tagging it `latest` and `innovation`). For these four, the vesting raises the real software in both Dockerfiles to that release, pinned by digest or checksum, runs `calibrate`, and once it is green records the release on the card's `software_releases` (software, release, the day it was the current stable one, which is the authoritative card's calibration day 2026-11-05, and the source line the reading cites). When `calibrate` fails after the raise, the implementer adapts the fixture in the repository (connection settings, authentication plugin, startup options, readiness) until it is green, with the exploits and the benign call kept the same in meaning. Only if the newer release cannot run in the confined container does the target keep its calibrated release, and the holdout-log entry then records the reading, the attempt and why it failed. The reason: excluding a measurable flaw from the sample costs the measurement more than a recorded release deviation, so a raise that fails is never a ground for excluding a target.
6. **A hand-written stand-in says so.** The capture format gains a documentary-source marker and a written capture drops the invented `captured_at`, in the same step as the other stand-in corrections, test-first.

## What the code says against the manifest

- **More kits than the two it names ran on an older harness.** The manifest calls only the CVE-2026-85787 and CVE-2026-44717 kits pre-v11. Twenty of the 37 authoritative kits build the layout in a host-owned `tempfile.TemporaryDirectory` (`_temp_root` in their `kit_launch.py`) rather than in `owned_layout`, so their server read a host-owned tree: CVE-2026-4270 (r6), 104120, 85788, 25546, 66335, 65831, 5323, 33060, 55787, 58485, 42260, 9654, 19978, 55581, 58358, 5603, 5602, 55157, 85787 and 44717. For them the repository `calibrate` is the first run on the 65534-owned tree. A read-only server sees the same bytes, but a tool that runs git in the checkout or prints owners may answer differently. A changed verdict on one of them is handled as any red `calibrate` (see Edge cases).
- **CVE-2026-104120's card is still in French.** The round 3 reading listed three card corrections (the language, a misquoted refusal message, dependencies described for the vulnerable version only), and the CARDS pass card still has all three. The vesting corrects them (see Per-target corrections).
- **Five give-up details are in French** (CVE-2026-45555 calibration 2, CVE-2026-46515 calibration 2, CVE-2026-33980 calibration 1, GHSA-rp72-5v5q-2446 calibration 1, CVE-2026-77252 calibration 1). The census is in the repository's language, so they are recorded as faithful English translations, and the holdout-log entry names them as translated.
- **The run reads `HOLDOUT_TARGETS`, not `draw.drawn`** (`_refuse_unready_cards`, `evals/run_holdout.py`), and no test ties the two, so a target present in one and absent from the other would be skipped or refused silently. A test ties them (Test scenarios).
- **Calibrate reports a route only for kept places** (`confirm_admission`, `evals/cve_layout_check.py`), while S9 asks the card to record the route check's result for every layout place, kept or not. The report gains the unkept layout places (see Code details), deciding nothing new.
- **The census's `draw.rule_commit` and `draw.grammar_fingerprint`** are the first draw's (`e67971b`, `3f5a4925…`), read by no code. The rule asks the census to record "the grammar fingerprint at the draw", which they are, so both stay, and the holdout-log entry records the current fingerprint (`4208029a…`) beside them.
- **The nuisance Doris launch already takes its host's user and working directory** (`doris_backend.doris_server_args` reads `user_args(host.user)` and `-w host.working_directory`) and mounts no layout, since the nuisance suite has none. S1 therefore changes only the holdout builder, and `doris_backend.py` does not move, so the nuisance Doris fingerprint does not move either.
- **`contextforge_ssrf_env` loses its only caller** with CVE-2026-18905. The nuisance fix check carries its own trimmed twin and imports nothing from `cve_environments`, so the builder, `_gw_tools` and `_GW_PUBLIC_IP` go with the target.

## Approach

The recipe is the transplant recipe of `plans/2026-10-23_holdout-transplant-batch1.md` and `plans/2026-10-24_holdout-transplant-batch2.md`, carried, not restated: the kit's two server Dockerfiles into `evals/docker/` under `holdout-<year>-<num>-<service>` (GHSA form for the GHSA target), each `COPY` or `ADD` turned into an inline `RUN` heredoc or a pinned download, each base pinned by digest. The services go into `evals/docker/compose.yml` with their image tag and fingerprint label (printed by `tests/unit/test_cve_compose_labels.py`). The kit's fixture is ported into `evals/holdout_fixtures/<slug>.py` with the import swaps, `mechanisms` as a `frozenset`, the acceptance-only fields (`severity`, `awaited_capability=None`, `note`, `tools_filter=None`, `ci_skip_reason=None`), and the literal `"sentinel"` in `images` for a target that keeps a network place, and the `TARGET` joins the assembler. A kept target's existing module, Dockerfiles and services are rewritten in place from its authoritative kit. The port keeps the kit's launch exactly, argv and `scope`, since the route check reads both, and keeps the kit's exploits and benign call. What the kit authored is ported: kit harness copies (the hand-patched `cve_layout.py` and `cve_planting.py` of the CVE-2025-53818 round 7 kit) and kit helpers (`run_kit*.py`, `run_calibration.py`, `build_card.py`, `run_frogman_calib.py`, `prepare_kit.py`, virtualenvs) are never vested, the repository's harness at HEAD supersedes them. Kits are read, never written.

For each target, the vesting also lands its census record in the same commit: the version 11 card from the authoritative kit with the corrections below and the route results of its layout places, its version 11 card check with its reported and confirmed gaps, and its agent records, so `HOLDOUT_TARGETS` and `draw.drawn` never disagree at a commit.

Order, as batch 2 ordered it, frictions first and heavy targets isolated, one target per step and commit:

1. **Shared code, no target vested.** `AgentRecord.fallback_model`. The capture format's source marker, the `POST` capture with a form body and the form-field route (S8, Q6). `generate.sh` learns an IP-literal host. The single authority regenerated for every HTTPS stand-in host, with the stand-in files of the campaign (S2, S3). The structural census edit, the removal of CVE-2026-18905 and CVE-2026-45555, and the report of every layout place's route.
2. **New or changed builders.** CVE-2025-66335 (S1, Doris, heavy), GHSA-8g7g-hmwm-6rv2 (S5, real n8n, heavy), CVE-2026-4270 (S4), CVE-2025-11489 (S4, read-write layout), CVE-2026-7785 (S6, tshark from source), CVE-2026-82112 (its own builder, llama.cpp and a GGUF, heavy).
3. **Heavy images on a shared builder.** CVE-2026-46514 (FreePBX, cold build), CVE-2026-35402 (Neo4j), CVE-2026-65831 (ArcadeDB), CVE-2026-5323 (Chromium), CVE-2026-25546 (Godot, Q4), CVE-2026-47394 (praisonai), CVE-2026-26029 (sf CLI, multi-stage rewritten), CVE-2026-3484 (nmap from source).
4. **Stand-in targets on a shared builder.** CVE-2026-2130, CVE-2026-42260, CVE-2025-53818, CVE-2025-65719, CVE-2026-104120, CVE-2026-33060, CVE-2026-58485.
5. **Light ports.** CVE-2026-55787, CVE-2026-55581, CVE-2025-58358, CVE-2026-5603, CVE-2026-5833, CVE-2026-3680, CVE-2026-5602, CVE-2026-55157, CVE-2026-81562, CVE-2026-44717, CVE-2026-15415, CVE-2026-53710, then the four release raises last: CVE-2026-19978, CVE-2025-9654, CVE-2026-85787, CVE-2026-85788 (with its nuisance twin's copy).
6. **Closing.** The v9 shim retired (S13), the working-directory guard, the whole-set calibration, the logs that close the vesting and the living docs at 37.

Disk discipline. Before every step that builds or runs Docker, free space is checked with `df -h /`: below 25 GB free, the step stops and reports to the maintainer, deleting nothing on its own (pre-existing images stay the maintainer's to remove). Every delegated Docker step carries this clause: do not grow Docker disk usage beyond what the step needs, leave removal of pre-existing images to the maintainer. Every target step ends with `docker builder prune -a -f` (all build cache, built images kept). A step that rebuilds an image the repository already builds (a kept target's, the stand-in's, the n8n stand-in's) retags it, so the superseded image of the same tag becomes dangling, and the step runs `docker image prune -f` (dangling only) after its build. Both prunes take `-f`, since they otherwise wait for a confirmation a non-interactive shell never gives. A heavy target is built and calibrated alone. Each batch's last step reports `docker system df`. No step overlaps a nuisance run or calibration, which replace the running backend containers.

Fingerprints. Before the first commit and after every commit, print to a file under the gitignored `output/holdout-vesting/` the grammar fingerprint, `fixture_fingerprint` of the 4 acceptance targets and of every holdout target, and the nuisance fixture fingerprints of `npm:@apify/actors-mcp-server` and `PyPI:doris-mcp-server`. Expected moves: every CVE fixture fingerprint with a change to `cve_environments.py`, `holdout_environments.py` or `public_stand_ins.py` (all three in `ENVIRONMENT_PATHS`), the fingerprint of every target declaring a stand-in (the acceptance fetch target, CVE-2026-104120, 5323, 33060, 58485 until their steps, then each vested stand-in target) with the authority, its leaf or its capture, the apify nuisance fingerprint with the authority, its capture and the stand-in image, a holdout target's own with its step, and the doris nuisance fingerprint never. Any other move stops the step and goes to the maintainer.

## Files and code details

### Shared code

`evals/census_work.py`:

```python
class AgentRecord(BaseModel):
    role: AgentRole
    scope: str
    model: str  # the model the agent was launched on
    fallback_model: str | None = None  # the model that answered, when the provider refused `model`
    set_aside: str | None = None
```

A validator refuses `fallback_model == model`. `_agent_problems` is unchanged (a record counts once whatever its models). `evals/holdout_census_method.md` (the living method note) says an agent that continued on the fallback model is one record with both.

`evals/public_stand_ins.py`:

```python
class StandInCapture(BaseModel):
    host: str
    address: Annotated[str, AfterValidator(_global_unicast)]
    source: Literal["capture", "software_sources"]  # captured, or written from the software's documentation or published examples
    captured_at: str | None = None  # a capture's date, never set on a written file
    command: str = Field(min_length=1)  # the capture command, or the documentation a written file follows
    request_headers: list[tuple[str, str]]
    routes: list[StandInRoute]
    defaults: list[StandInDefault]

class StandInRoute(BaseModel):
    ...
    action: str | None = None
    form_field: str | None = None  # a POST route answered when the form body carries this field
```

`source` takes the two terms of `fixture_provenance.SourceKind` that a capture file can hold. A validator requires `captured_at` exactly when `source == "capture"`. A route's validator allows `form_field` only on a `POST` and never beside an `action`, and `_one_route_per_key` keys on `(scheme, method, target, action, form_field)`. The module docstring says a written file's `address` is a fixed global address of the fixture, not a resolution, and that a form-field route is chosen on a fixed word at a fixed position of the request (the field's name), as both rules ask. The three committed captures (`example.com`, `demo.ckan.org`, `api.apify.com`) gain `"source": "capture"`, a format field, their captured values untouched.

`evals/docker/Dockerfile.stand-in`: after the action lookup, a request with an `application/x-www-form-urlencoded` body takes the route of `(scheme, method, target)` whose `form_field` the body carries, then the action-less and field-less route, then the default, unchanged otherwise. The compose label follows.

`evals/capture_stand_in.py`: a URL argument may be `'POST URL BODY'` (one argument, as `HEAD` is), `BODY` a form body of one field sent as `application/x-www-form-urlencoded`. The route is recorded with `form_field` set to that field's name and the body in `command`. The record always carries `source: "capture"`.

`evals/stand_ins/tls/generate.sh`: a host that is an IPv4 literal gets `subjectAltName = IP:<host>` on its leaf and `permitted;IP.<n> = <host>/255.255.255.255` on the authority instead of the two DNS lines, and its leaf's subject carries no common name (for example `-subj "/O=mcp-auditor fixture stand-in"`): OpenSSL checks the common name of a leaf with no DNS name against the authority's DNS subtrees, so a leaf named `CN=45.55.0.10` fails with "permitted subtree violation" under the single authority (checked with OpenSSL 3.5.5, while the same leaf without the common name verifies).

`evals/cve_layout_check.py` `confirm_admission`: beside the route of each kept place, it prints the route result of each layout place the target does not keep, from the same `route_admits` on the same observation, labelled not kept. It adds no admission failure and changes no decision, so the route and layout golden masters stay unregenerated. A pure helper carries it, `layout_routes(places: Places, kept: Sequence[str], planted: RouteObservations) -> list[LayoutRoute]`, `LayoutRoute` a frozen dataclass beside `LayoutSurface` (`place_id: str`, `kept: bool`, `routed: bool`), a layout place being one whose coordinates carry an anchor, and `planted` the vulnerable version's planted observation (`VersionObservation.planted`, a `cve_route.RouteObservations`).

`evals/cve_environments.py`, new builders, each with the keyword-only `docker: PlantingDocker = DOCKER_PLANTING` and the `(image, spec, shape)` call, on `owned_layout`, `planted` and `layout_mount_args`:

```python
def filesystem_scope_env(image, spec, shape=LaunchShape.NORMAL, *, docker=DOCKER_PLANTING) -> Generator[Launch]:
    # filesystem_env without the leak<i>/report links, launched as filesystem_launch
def command_injection_checkout_env(image, spec, shape=LaunchShape.NORMAL, *, docker=DOCKER_PLANTING) -> Generator[Launch]:
    # command_injection_env whose NORMAL and FALLBACK trees hold an empty `captures` directory in the checkout
def houtini_lm_env(image, spec, shape=LaunchShape.NORMAL, *, docker=DOCKER_PLANTING) -> Generator[Launch]:
    # command_injection_env plus -e HOUTINI_LM_FILE_ROOTS=<checkout> -e HOUTINI_LM_ENDPOINT_URL=<the in-image llama-server>
```

CVE-2025-11489's kit builder `writable_filesystem_env` is `filesystem_scope_env` under a host declaring `layout_mount=LayoutMount.READ_WRITE`, so it adds no builder. CVE-2026-15415's kit builder `healthomics_env` has the effect of `command_injection_env` and is ported as it.

`doris_db_env` (S1) gains the keyword-only `docker` parameter and builds the layout through `owned_layout(docker, lambda root: materialise(root, spec, shape))`, and its launch gains `*unprivileged_user_args()` (imported from `evals.cve_planting_base`, since `evals.cve_planting` keeps it off its public surface), `-w spec.host.working_directory` and `*layout_mount_args(root, spec.host.layout_mount)`. It keeps `DORIS_LAUNCH_LOCK`, `ensure_doris()`, the sentinels of `start_doris_sentinel`, `own_network_args(DORIS_BRIDGE)`, the unique container name and its forced removal, and never calls `planted()`. The "No /srv layout is mounted" comment and the twin note are rewritten: the holdout launch now mounts the layout and runs under 65534 from the checkout, the nuisance launch has no layout and reads its admission host, so the two are no longer twins.

`ssrf_redirect_env` (S5) is replaced by the round 6 kit's real-n8n builder. The n8n backend's start, provisioning (owner, API key, the active webhook workflow, through the kit's node helper) and removal move to a new `evals/n8n_instance_backend.py`, beside `doris_backend.py`, and the target declares it in `backend_sources` so its fingerprint covers what seeds the backend. `evals/n8n_backend.py` already exists and is the nuisance suite's n8n REST responder (`nuisance_backends` fingerprints it for the n8n servers), so it is not touched and the new module takes another name. The kit's bare `TemporaryDirectory` and `build_layout` are replaced by `owned_layout`, and the repository's no-holder branch stays (the reference arm plants no sentinel, joins no holder and starts no backend). The address on the holder's loopback is set as `_start_n8n_stub` sets it today. `Dockerfile.holdout-ghsa-8g7g-hmwm-6rv2-n8n-redirect` becomes `FROM docker.n8n.io/n8nio/n8n:2.46.6@sha256:<digest>` with the kit's workflow, the digest being the one `docker.n8n.io` serves for 2.46.6, checked at build time against Docker Hub's (`sha256:8602f5dfacbe2c931eeafd010de0e68182310e9f309921e780ab69182e92b3ae`) and, when the two differ, the `docker.n8n.io` one pinned, and `_N8N_REDIRECT_IMAGE` keeps its tag. The workflow id the exploits read comes from the provisioning of the same launch.

`contextforge_ssrf_env`, `_gw_tools` and `_GW_PUBLIC_IP` go (no caller), and the nuisance twin's comment in `evals/nuisance_fix_checks/cve_2026_18905_contextforge.py` stops naming them. `evals/cve_environments.py` is 569 lines and, with these changes, grows by roughly 60. The module is split along the line of what its builders serve: the holdout-only builders (`filesystem_scope_env`, `command_injection_checkout_env`, `houtini_lm_env`, `doris_db_env`, `arcadedb_mcp_env`, `mysql_db_env`, the real-n8n builder) move to a new `evals/holdout_environments.py`, added to `ENVIRONMENT_PATHS` in `evals/cve_baseline.py`, and every importer (holdout fixtures, nuisance modules that import one of them) follows. `cve_environments.py` keeps the shared builders the acceptance targets use. The shared helpers the holdout builders reuse become public there, renamed with every caller and no behaviour change: `_materialise` to `materialise`, `_filesystem_launch` to `filesystem_launch`, `_PROJECT` and `_CHECKOUT` to `PROJECT` and `CHECKOUT`, since pyright's strict mode refuses a private name imported from another module (`reportPrivateUsage`, and no module of `evals/` silences it). The split costs no extra fingerprint move, since every CVE fixture fingerprint already moves with this plan's builder changes. The n8n backend's move to its own module keeps the builder module's membership rule (the launches) and puts the backend lifecycle where `doris_backend.py` already put Doris's.

### Leaving targets (S14)

Deleted: `evals/holdout_fixtures/cve_2026_18905_contextforge.py`, `evals/holdout_fixtures/cve_2026_45555_roslyncodelens.py`, `evals/docker/Dockerfile.holdout-2026-18905-contextforge`, `-patched`, `evals/docker/Dockerfile.holdout-2026-45555-roslyncodelens`, `-patched`, their four compose services, `tests/unit/test_contextforge_planting_contract.py`, and their entries in `evals/holdout_targets.py`. The nuisance contextforge Dockerfiles and fix check stay.

### Per-target corrections

Each target's step applies the recipe from its authoritative kit (manifest 1a and 1b give the kit, card and check of each), then what is listed here. Sources are as the manifest cites them.

New targets:

- **CVE-2026-85787** (awslabs.postgres-mcp-server 1.1.6/1.1.7, kit `CVE-2026-85787-r5`): service `holdout-2026-85787-postgres`, module `cve_2026_85787_postgres.py`, `command_injection_env`, kept 18. `mechanisms` is the union of the card's three classes, `frozenset({READ_OUTSIDE_SCOPE, INTERNAL_FETCH, COMMAND_EXECUTION})`, where the kit carries `mechanism=None` (S7). The AWS stand-ins of the shared step (S3). PostgreSQL raised to 18.6 (`postgres:18.6-bookworm@sha256:f1ea2a1a4fb7b68d4836be1fdcb8a6466a89b072158bf9d97663600538c294c5`, decision 5), the data directory initialised at build under 65534 as the kit does. Its first run on the repository's harness is this `calibrate`.
- **CVE-2026-44717** (mcp_calculate_server, kit `CVE-2026-44717-r3`, card from the CARDS pass): service `holdout-2026-44717-calculate`, `command_injection_env`, kept 25, `frozenset({COMMAND_EXECUTION})` from the kit's singular `mechanism` (S7), full commit hashes in the Dockerfiles, base by digest. First run on the repository's harness.
- **CVE-2025-65719** (kubectl-mcp-server v1.1.1/v1.2.0, kit `-r6`): service `holdout-2025-65719-kubectl`, `command_injection_env`, kept 24, the Kubernetes API stand-in on the IP literal `45.55.0.10` (written from the Kubernetes API documentation, `source: software_sources`), its leaf from the single authority with an IP SAN, git tags resolved to commit hashes, base by digest. k8s-api-server and loopback-service stay off both lists: their reach is fetch only and the target's is exec only, so no correction applies.
- **CVE-2026-15415** (awslabs.aws-healthomics-mcp-server 0.0.35/0.0.36, kit `-r5`): service `holdout-2026-15415-healthomics`, `command_injection_env`, kept 21, miniwdl 1.16.0 and cwltool 3.3.20260925135507 pinned to the releases the card records (S11), base by digest.
- **CVE-2026-53710** (mcp-context-forge python_sandbox_server v1.0.1/v1.0.2, kit `-r5`, card from the CARDS pass): service `holdout-2026-53710-python-sandbox`, `command_injection_env`, kept 25. The card gains k8s-api-server and loopback-service in `unkept` (reading r6, decision 3). Its v11 walk step records the server as distinct from 18905's gateway. Tags resolved to commits, base by digest.
- **CVE-2026-47394** (praisonai 4.6.39/4.6.40, kit `-r5`): service `holdout-2026-47394-praisonai`, `command_injection_env`, kept 21, the declared `python -c` entrypoint kept. Its dependency tree is pinned as a constraints list inlined as a heredoc (S11), frozen from the kit's calibrated vulnerable image when it is still present locally (the tree that calibrated, and no extra build), otherwise from a first build of the vulnerable image, then the image built against it. It lists 86 tools in pages of 50, which both clients follow since `698c568`.
- **CVE-2026-35402** (mcp-neo4j-cypher 0.5.3/0.6.0, kit `-r5`, card from the CARDS pass): service `holdout-2026-35402-neo4j-cypher`, `ssrf_env`, kept 3, `images` gains the literal `"sentinel"`. `neo4j:5.26.1@sha256:<digest>`, uv installed from its release archive pinned by checksum in place of `COPY --from=ghcr.io/astral-sh/uv:latest`, its version read from the kit's calibrated image when it is still on disk, otherwise from the kit's build log, the entrypoint as a heredoc (S10). Neo4j stays co-located in the server image as calibrated: moving it to the nuisance Neo4j backend would change the fixture, which is calibration.
- **CVE-2026-82112** (@houtini/lm at commits `fca0da5`/`35d97bc`, kit `-r7`): service `holdout-2026-82112-houtini-lm`, `houtini_lm_env`, kept 21. `FROM ghcr.io/ggml-org/llama.cpp:server-b12124@sha256:c0a11067c72bb1eb330b8bddbf9869274c195e596bf4fae55fd527102e644b85` (the build the floating `server` tag named on the calibration day), the digest the card records, in the Dockerfiles themselves (the kit has the tag only). The Qwen2.5-3B-Instruct q4_k_m GGUF fetched at a Hugging Face commit revision with its sha256 checked (the revision `main` pointed to on the calibration day, which the card's model release names in place of `main`: `7dabda4d13d513e3e842b20f0d435c732f172cbe`, unchanged since 2024-09-20, its `qwen2.5-3b-instruct-q4_k_m.gguf` of 2104932768 bytes with sha256 `626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d`), Node.js from its release tarball pinned by checksum in place of the NodeSource script, its version read from the kit's calibrated image when it is still on disk, otherwise from the kit's build log, the entrypoint as a heredoc (S10, S11).
- **CVE-2026-46514** (frogman 1.6.0/1.6.2, kit `-r8`): service `holdout-2026-46514-frogman`, `command_injection_env`, kept 19, the planted account named after the nonce (uid 60123) owning the FreePBX stack as calibrated. Dockerfiles: `debian:12@sha256:<digest>`, the apt packages `freepbx17`, `asterisk22` and `ioncube-loader-82` pinned to the versions the card records (FreePBX 17.0, framework 17.0.19.32, API 17.0.9, Asterisk 22.11.0), as the apt version strings of `deb.freepbx.org/freepbx17-prod` `bookworm` give them: `freepbx17=17.1-1.sng12` (the package's own version, the card's 17.0 being the product line), `asterisk22=22.11.0-1.sng12`, `ioncube-loader-82=1.0.0-1.sng12`, no `|| true`, the FreePBX installer fetched at a pinned commit with its sha256, the frogman 1.6.0 and 1.6.2 trees fetched at the commits of those tags, the entrypoint as a heredoc. Before relying on a fetched tree, the implementer checks it equals the kit's tree byte for byte, and stops and reports when it does not. A cold build (`--no-cache`) confirms FreePBX installs in the image with MariaDB up through the `freepbx17` postinst in one `RUN` layer, and the step measures the image size and the startup time and records both in the holdout-log entry. Card corrections (reading r7, section 3, and the r8 check): the reason the fixed version is 1.6.2 (both GHSAs give patched 1.6.2, and the 1.6.1 install aborts), bare-remote-url, bare-history-env and workspace-dotenv in `unkept`, a sentence that 46514's own effect is outside the grammar (the union is `command_execution`, carried by sibling 46512), and `seeded_outside_layout` reworded ("FreePBX 17 deployment, with the database, web server and PHP of its installer"). The fixture follows the advisory's vulnerable version 1.6.0, a classifier's record of 1.6.1 stays as that agent wrote it, and the log names the divergence. The card keeps container-hostname and leaves imds, ecs-task-credentials and eks-pod-identity out (the holder's `--hostname` excludes them), as calibrated and checked.

Kept targets, beyond the recipe's rewrite from the kit (the working directory moving to `/srv/app` is not repeated below):

- **CVE-2026-4270** (kit `-r6`): `filesystem_scope_env`, kept 21 to 20 (workspace-dotenv out), `SymbolicUser.HOST` to `UNPRIVILEGED`, aws-credentials unkept with its observed reason, the telemetry variable dropped. `software_releases: []` is accepted: the AWS CLI runs in-process as the server's own Python library, not as a program the server calls (reading r6, decision 3), and the holdout log records the decision. The `planting_host.user` reason cites the 65534 owner (reading r4, R4-T6). The kit's Dockerfile names map onto `Dockerfile.holdout-2026-4270-aws-api-mcp[-patched]`, never onto the nuisance `Dockerfile.aws-api-mcp`.
- **CVE-2026-2130** (kit `-r6`): kept 25 to 24 (etc-hosts out), the new `w3challs.com` stand-in (a real capture) whose leaf the single authority issues in place of the kit's self-signed one, the realistic `docker` stand-in, the benign call on one site tag.
- **CVE-2026-104120** (kit `-r3`, card from the CARDS pass): the fixture extracted from the kit's `kit_target.py`. The card is translated into English, its patched refusal message quoted as the repository `calibrate` observes it, and its dependencies described for both versions from the two Dockerfiles. These are card edits by the maintainer, logged, the card check having read the French card.
- **CVE-2026-85788** (kit `-r5`): kept 21 to 19, moto replaced by the AWS stand-ins (S3), `has_network` true, `AWS_CA_BUNDLE` trusted, the secret's username `postgres`. MySQL raised to 26.10.0 (`mysql:26.10.0@sha256:3819b2b23835c4a73c8b022fafc33c8095c0f81c929a8b7a84613d2fba6c52f5`, decision 5), the card's `software_releases` recording MySQL 26.10.0. Its nuisance twin copies its holdout calibration (nuisance rule v4), so after the step is green the admission's `fix_check` record of CVE-2026-85788 is copied again from this calibration (`exploit_calls`, the surfaces, `patched_benign_errored`) and its `holdout_fingerprint` set to the target's current `fixture_fingerprint`, with a nuisance-log entry. The server's `software_releases` are not copied from the card: the nuisance run of `PyPI:awslabs-mysql-mcp-server` keeps its own backend, `mysql:8.0.46@sha256:7dcddc01…`, so the card's MySQL 26.10.0 would misrecord it, and the re-admission records its releases with the other servers'.
- **CVE-2026-25546** (kit `-r3`, card from the CARDS pass): the real Godot 4.4.1, the exploits building `<payload>/project.godot` from tool arguments under `/opt/base-project` (decision 4), `node:20-bookworm-slim@sha256:<digest>` (S10), the card's seeded item renamed to the new path. If `calibrate` is red after the move and stays red once repaired as Edge cases say, the kit's `/work/base-project` is kept and logged (the target runs from `/srv/app`, so no tmpfs hides it), and the `/work` Dockerfile guard names 25546 as its one exception.
- **CVE-2025-11489** (kit `-r5`, card from the CARDS pass): `filesystem_scope_env` under `layout_mount=LayoutMount.READ_WRITE` (the exploits write their links with `ln -s` through `start_process`), `HOST` to `UNPRIVILEGED`, kept 19 to 20 (container-hostname in), `mechanisms` the card's union `{READ_OUTSIDE_SCOPE, COMMAND_EXECUTION}` (S7), the default configuration.
- **CVE-2025-66335** (the repository fixture, card from the CARDS pass, no kit fixture): S1, and its host becomes `PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/app", has_network=True)`. The card records Apache Doris 4.1.3 and sibling CVE-2025-66336.
- **GHSA-8g7g-hmwm-6rv2** (kit `-r6`): S5, the benign `n8n_test_workflow` on the provisioned workflow, `node:22-bookworm-slim` at the kit's digest.
- **CVE-2026-65831** (kit `-r3`, card from the CARDS pass): `ARCADEDB_SETTINGS` as calibrated (root path, no seed database), `mechanisms` the card's union `{READ_OUTSIDE_SCOPE, INTERNAL_FETCH}` (S7), the literal `"sentinel"` kept in `images` (the kit's convention omits it).
- **CVE-2026-5323** (kit `-r4`): the Debian Chromium, whose NSS database at `/tmp/.pki/nssdb` holds the fixture authority under the label `Local Root CA`, baked as calibrated, with the regenerated authority's PEM inlined. The holdout log records that the Debian Chromium is accepted and that the card check's justification for it was wrong (reading r6, decision 7).
- **CVE-2026-33060, 58485** (kits `-r3`): the working directory only (33060 drops `NODE_ENV`).
- **CVE-2026-55787** (kit `-r3`): the card's `seeded_outside_layout` filled with the pinned server image and the sentinels, `launch_options: []` left as it is (reading r6, decision 3).
- **CVE-2026-42260** (kit `-r5`): the `html.duckduckgo.com` stand-in recaptured by `capture_stand_in` with `'POST https://html.duckduckgo.com/html/ q=wikipedia'` and the request headers of the kit's capture (`--header 'User-Agent: Apifox/1.0.0 (https://apifox.com)' --header 'Accept: */*'`, the server's own), so its route answers the `q` field (S8), `NODE_EXTRA_CA_CERTS` trusted, the benign query `wikipedia`. If the live answer is not a results page (a bot challenge), the kit's captured route (2026-11-05T04:15:55Z) is kept, its `form_field` set, and the log says so.
- **CVE-2026-7785** (kit `-r7`): `command_injection_checkout_env` (S6), tshark 4.6.9 built from its checksummed source on both versions. The `patched_result` was copied from round 1, and `calibrate` replays it.
- **CVE-2025-9654** (kit `-r5`): `MCP_SILENT` dropped, OpenSSH raised to 10.6p1 built from the portable release tarball checked by sha256 (decision 5), the client only installed, and the step verifies the image carries no `sshd` binary (10.6p2's fix concerns sshd only, so 10.6p1 stays the stable release of the calibration day).
- **CVE-2026-19978** (kit `-r5`): the `adbd.js` device transport, inlined as a heredoc byte-identical to CVE-2026-81562's (sha256 `9dcc0875…`), and adb raised to Platform-Tools 37.0.1 from the same checksummed zip as 81562, in place of Debian's adb (decision 5). Its route check goes through the meta-tools (`system_shell`, `device_list` is not listed).
- **CVE-2026-55581** (kit `-r4`), **CVE-2026-5833** (kit `-r6`, the taskrc reduced to what is needed), **CVE-2026-55157** (kit `-r3`, `mechanisms` `{COMMAND_EXECUTION, READ_OUTSIDE_SCOPE}`, S7), **CVE-2025-58358** (kit `-r3`, the benign call reads the README, the seeded `/opt/benign.md` dropped, `mechanisms` `{COMMAND_EXECUTION, READ_OUTSIDE_SCOPE, INTERNAL_FETCH}`, S7, the kit's `build_target()` ported to a plain `TARGET`).
- **CVE-2026-5603** (kit `-r3`, card from the CARDS pass): the magerun2 phar fetched from the 10.1.0 release (`https://github.com/netz98/n98-magerun2/releases/download/10.1.0/n98-magerun2.phar`) with its sha256 checked (`76c931312f3ab6a5a5e1dbd40544cf43f9ecab176bca6a3597ebf4a3413fe270`, S11), PHP 8.2 unchanged (decision 5).
- **CVE-2025-53818** (kit `-r7`): the real gh 2.103.3, working directory `/work`, the `api.github.com` stand-in written from the GraphQL reference (`source: software_sources`), `SSL_CERT_FILE` trusted, kept 25 to 23, no `GH_CONFIG_DIR`.
- **CVE-2026-26029** (kit `-r6`, check attempt 2): the real sf 2.157.8, kept 25 to 24, the `example-org.my.salesforce.com` stand-in written from the Salesforce REST and OAuth documentation (`source: software_sources`). The kit's two stages are rewritten as one: the build-time HTTPS mock is written with a `RUN` heredoc, started, used for the `sf` login and stopped within one `RUN`, so no `COPY <<` and no `COPY --from` remain (S10).
- **CVE-2026-3484** (kit `-r7`): nmap 7.993 from the nmap.org tarball with its sha256 checked (S11).
- **CVE-2026-3680** (kit `-r6`, the accepted check is attempt 2): the real biome 1.9.4, the benign call on a real file outside the layout.
- **CVE-2026-5602** (kit `-r5`): the heim stand-in, its documented deploy output and the published example app inlined as `RUN` heredocs (S10).
- **CVE-2026-81562** (kit `-r6`): Platform-Tools r37.0.1 from its zip with the sha256 checked (S11), the `adbd.js` transport, the benign `device_list`.

S9 for every target: each card's unkept layout places carry `route_checked` from the repository `calibrate` report of that step (only `UnkeptPlace` has the field: a kept layout place's route is `calibrate`'s own condition, a kept layout place without one failing the admission, so `KeptPlace` gains no field), and an exec-only target's unkept layout places give as reason that the frozen table offers them to read reach only.

### Shared stand-in files (S2, S3, Q6)

One run of `generate.sh` with every HTTPS stand-in host: `example.com`, `demo.ckan.org`, `api.apify.com`, `rds.us-east-1.amazonaws.com`, `secretsmanager.us-east-1.amazonaws.com`, `html.duckduckgo.com`, `api.github.com`, `example-org.my.salesforce.com`, `w3challs.com`, `45.55.0.10`. The campaign's captures and written files land in the same step, so every later target step only declares its host: `w3challs.com.json` (capture), `api.github.com.json`, `example-org.my.salesforce.com.json` and `45.55.0.10.json` (written, `source: software_sources`, `captured_at` dropped), the DuckDuckGo capture (recaptured with the form-field route), and the AWS files of S3: one `rds.us-east-1.amazonaws.com.json` with a `POST /` route per action (`DescribeDBInstances` from 85787's us-east-1 body, `DescribeDBClusters` from 85788's), the stale us-west-2 copy dropped, and `secretsmanager.us-east-1.amazonaws.com.json` with its route keyed on `secretsmanager.GetSecretValue`, `VersionStages` restored, the ARN in us-east-1 and the username `postgres`, both written from the AWS API reference examples with their defaults (`400 InvalidAction` on both schemes) declared on both cards. The Salesforce routes' `action` keys are checked to be absent or null on every non-`POST` route. The nuisance apify fingerprint moves, since its backend serves `api.apify.com` from the regenerated leaf and from its capture, which gains `source`.

Three committed guards in `tests/unit/test_public_stand_ins.py` meet this step. `test_the_committed_captures_are_exactly_the_declared_stand_ins` compares the captures with the hosts the CVE and holdout targets declare, and the six new hosts are declared only once their targets are vested (steps 3 to 5). So `declared_stand_in_hosts()` in `tests/unit/support/test_public_stand_ins_given.py` also counts a named set of the hosts whose declaring target is not yet vested, each target step removes its host from it, and the step that empties it deletes the set. `test_the_committed_authority_signs_for_exactly_the_https_stand_in_hosts` and `test_every_committed_leaf_names_an_https_stand_in_host` read DNS names only (`_dns_names`, `committed_leaf_names`): they learn the IP subtrees and IP SANs, an IP-literal host being permitted as `<host>/32` with no excluded subtree and its leaf naming it once as an IP address, with no common name in its subject. The givens that build a capture (`tests/unit/support/test_public_stand_ins_given.py`, `test_cve_planting_stand_ins_given.py`, `test_capture_stand_in_given.py`, `test_cve_baseline_given.py`, and `tests/integration/support/test_cve_planting_stand_ins_given.py`) gain `"source": "capture"`, since the model forbids extra fields and `source` is required.

### The census edit

`evals/holdout_census.json` is edited by a one-off script kept under the gitignored `output/holdout-vesting/`, which loads the file with `HoldoutCensus`, changes the records and writes `model_dump_json(indent=2)` back, then `load_census` must pass. Never `run_census assemble`: `Collection.census()` builds a census without `draw` and takes its agents from the census work files only, which would wipe the draw record and its 90 draw agent records. Records are found by their flaw and criterion, never by list index.

Structural edit, in the shared step:

- Settlements removed, each logged: the void `grammar_class` settlements of CVE-2026-46515, CVE-2026-57496 and CVE-2026-77252 (`grammar_class` is not a draw-order criterion since version 4), the void `stdio_tools_call` settlements of CVE-2026-19516 and GHSA-rp72-5v5q-2446 (each overrode an agreement), and CVE-2025-66335's `grammar_class` settlement (against the classifiers' agreement, no effect). The nuisance walk reads no `grammar_class` settlement since its version 4 code, so `PyPI:doris-mcp-server` stays in the nuisance population, which `run_nuisance walk` confirms. The nuisance walk does read the draw's `effect_in_tool_response` settlements (`nuisance_walk._sets_version`): CVE-2026-7237 settled false leaves `npm:@agiflowai/scaffold-mcp` (position 11, not admitted) with no version-setting flaw, so it leaves the nuisance population, and GHSA-pc2w-4mq8-32qw leaves dynatrace's version-setting list, GHSA-pqh8-p93p-2rx7 keeping it in. A removed `stdio_tools_call` false settlement changes nothing there (`_tools_reached` reads only a true one).
- CVE-2026-45555's settlement reason rests on the source only (the clause "and on the real fixture" goes).
- Settlements added: `effect_in_tool_response` false for CVE-2026-7237 and GHSA-pc2w-4mq8-32qw, true for CVE-2026-18954 and CVE-2026-15415, their reasons stating they were settled for the version 11 re-walk, and CVE-2026-85787's `effect_in_tool_response` true copied verbatim from `evals/nuisance_walk_record.json`.
- Version 10 history of the two leaving targets, as the 2026-11-04 entry promised: a version 10 `given_up` step and the two version 10 give-ups (kits `CVE-2026-18905`, `-recal2`, `CVE-2026-45555`, `-recal2`) for each.
- Version 10 walk of positions 87 to 90, which filled the two vacancies (CVE-2026-30632, CVE-2026-85787, CVE-2026-73530, CVE-2026-44717): their version 10 steps with their version 10 outcomes are recorded as history beside the version 10 history of the two leaving targets, so that history shows who filled the vacancies. The version 11 steps govern.

- Version 11 walk steps, the earlier steps kept as history: one per re-walk entry (41) and for positions 88 to 90 (position 87, CVE-2026-30632, is a re-walk entry). Outcomes: `drawn` for the 7 re-walked targets, CVE-2026-85787 and CVE-2026-44717, `given_up` for the 29, `excluded` for CVE-2026-7237 and GHSA-pc2w-4mq8-32qw (step 1 settlements), `skipped` for CVE-2026-77259 (sibling of 77252, fix `b041733`, v0.22.0), CVE-2026-86544 and CVE-2026-30632 (siblings of 86439) and CVE-2026-73530 (its server already gives CVE-2026-55787). The sibling list of CVE-2026-86439, CVE-2026-86541, CVE-2026-86544, CVE-2026-30632 and CVE-2026-30633, goes in the reasons of 86439's step and of the two skip steps, which are the maintainer's, not into a give-up detail, which is the agent's.
- Version 11 give-ups: the counted pair of each of the 29 exclusions (manifest `census.double_give_ups`, reason, detail, attempts), with the two translations named above.
- `draw.drawn`, cards and card checks: CVE-2026-18905 and CVE-2026-45555 leave `drawn` and lose their card and check (a card beside two give-ups under the governing version is refused). The other 28 keep their old card and check until their own step replaces them.
- Agent records: a calibrator record for each calibration of the 29 exclusions and of the two version 10 pairs, with `fallback_model` where the session fell back, and a record with its cause for every session set aside in the campaign. The agents of the void and redone pairs are not recorded, as their results are not, and the log names them.

Per target, in its step: its card (with the corrections and route results above) replaces the old one, its version 11 card check (reported and confirmed gaps, `rule_version: 11`) replaces the old one, its calibrator and card-checker records are added (requested `claude-opus-5-5`, `fallback_model` `claude-opus-4-8`, including the hand-resumed round 8 session of 46514 and the attempts accepted after the maintainer's reading: the 3680 check attempt 2 and the 46514 round 7 card attempt 1, which are kept results, not set aside), and a new target joins `drawn`. After the last step `drawn` holds the 37.
The records cover every agent whose output the vested census rests on: the authoritative calibrator and card checker of each target, the card writer of a grouped card pass whose card is vested (a `calibrator` row of the same scope as the kit's calibrator, which `_agent_problems` accepts since it reads only the scope), and the agents of each counted give-up pair. Superseded sessions (earlier rounds of a recalibrated target, 33980's round 5 pair) are not recorded: their results are replaced, not used, and the holdout-log entry gives their count per round beside the extent of fallback. The census method's "one line per agent launched" was written for the census steps, where every agent's output counts, and the log entry states this reading.


### Closing (S13 and guards)

With every card carrying its fields, the v9 shim goes, as decision 1 of `plans/2026-11-03_rule-v3-v9-schema-and-vet.md` scheduled it for the commit that fills the last card: `CalibrationCard.seeded_outside_layout`, `stand_ins` and `software_releases` become required (`evals/census_draw.py`), `card.stand_ins or []` and `card.software_releases or []` become plain iteration, `_card_gaps` keeps only "no card" (`evals/holdout_card_readiness.py`), `CardCheck.rule_version` becomes a required `int` and the "rule version unset" gap goes, the version refusal stays (`CARD_CHECK_RULE_VERSION = 11`), the kit README sentence on optional fields goes (`evals/calibration_dossier.py`), and the tests pinning the shim go with it (`tests/unit/test_holdout_card_readiness.py` unset cases, `tests/unit/test_calibration_dossier.py::test_the_readme_requires_every_card_field_the_run_refuses_unset` and its given, the defaults of `tests/unit/support/test_census_draw_given.py`).

## What stays unchanged

- The kits: read, never written. `evals/holdout_places.json`, the layout, its denylist, the route and layout checks' decisions and their golden masters, the grammar and its golden master.
- `docs/holdout-rule.md`: no version opens. Every change here carries out version 11 or corrects a record.
- The acceptance targets, their fixtures, `evals/cve_targets.py` and their working directory (`/`), which predates version 11 and is not this plan's. Their fixture fingerprints move with `cve_environments.py`, `public_stand_ins.py`, the stand-in image and the regenerated authority (the fetch target's `example.com` leaf), and no CVE baseline exists (`evals/baselines/` holds the honeypot and judge baselines only), so nothing is reset: `run_cve_benchmark --calibrate` shows the four live and dead as before.
- `SymbolicUser.HOST` and `host_user_args`: the nuisance run hosts of auto-commit and git-mcp still use them, until the nuisance re-admission.
- The nuisance admission, except CVE-2026-85788's copy. The other 14 holdout-calibration copies keep `holdout_fingerprint` unset, and the re-admission records them. The admitted servers whose flaw is now a drawn target (praisonai, mcp-neo4j-cypher) keep their records, and the re-admission settles how they follow the holdout. `doris_backend.py`, the nuisance Doris launch and fingerprint.
- `draw.rule_commit`, `draw.grammar_fingerprint` and the classifiers' records. The census's own exclusion lists in `evals/holdout_exclusions.py`.
- The order of `HOLDOUT_TARGETS`, which stays the transplant order with the new targets appended.

## Edge cases

- **A red `calibrate` on a kept or new target** (a harness difference from its kit, the 65534-owned tree, the regenerated authority): the implementer repairs it in the repository, in what the vesting carries rather than in what calibration decided (launch settings, permissions, readiness, the image's build, a harness convention as decision 4 does), the kept places, the exploits and the benign call staying the same in meaning, and proves the repair with `calibrate`, as decision 5 does for the release raises. A repair that would change a kept place, an exploit or the benign call in meaning is calibration: the implementer then stops and reports the failing condition, and the maintainer decides, the default being the calibrated state kept and logged. No target is excluded and no recalibration outside the repository is launched at vesting.
- **A release raise that fails.** MySQL 9.x/26.x has no `mysql_native_password` at all (removed in 9.0, so it cannot be re-enabled), PostgreSQL 18's image moves its data directory, OpenSSH 10 drops DSA and changes defaults, and Platform-Tools 37 may differ from adb 29 on the wire protocol `adbd.js` speaks. The implementer adapts the fixture's connection settings, authentication plugin, startup options and readiness until `calibrate` is green, with the exploits and benign call the same in meaning. When the newer release cannot run in the confined container, the target keeps its calibrated release and the log records the reading, the attempt and why it failed.
- **The day of the raised release.** The card records the authoritative card's calibration day, 2026-11-05. OpenSSH 10.6p2 was published later that day and is current on the vesting day, so the release follows the calibration day the reading anchored, and the log says so.
- **Doris under 65534 with a read-only layout.** If `doris-mcp-server` writes beside its install or under the working directory at start, it fails under the new launch. The step reports it as a red `calibrate`. The persistent cluster is shared with the nuisance suite: no step overlaps a nuisance run or calibration.
- **The n8n workflow id.** Each launch provisions its own workflow. An exploit takes `(places, client)` and cannot see its launch, so it reads the id the builder stores before it yields, as the kit does, and the builder clears it on exit. That holds because a target's checked launches never overlap: `calibrate --concurrency` and the run's pre-run check spread targets, and `check_target` exercises a target's two versions one after the other. Sibling audit launches of the run may overlap and overwrite it, but no exploit runs then.
- **A fetched FreePBX installer or frogman tree that differs from the kit's.** The installer (45 KB) is then inlined from the kit as a `RUN` heredoc, which S10 allows. A frogman tree that differs is a difference between the kit and the published tag the advisory names: the tag's tree is used, the difference is recorded in the log, and `calibrate` decides, a red one going as the first edge case says.
- **An IP-literal stand-in host.** The leaf carries an IP SAN and no common name, and the authority an IP constraint. A client that ignores IP constraints still validates, an OpenSSL client validates only because the leaf has no common name (see `generate.sh` above), and the probe of `probe_stand_ins` reaches it by its literal as in the kit.
- **The 5323 baked authority** goes stale at any later regeneration. A unit test requires the PEM inlined in both 5323 Dockerfiles to equal `evals/stand_ins/tls/fixture-authority.pem`.
- **Positions 87 to 90 enter the holdout walk.** `reached_identifiers` gains them, so they leave the nuisance addition part: the admitted `https://github.com/611711Dark/mcp_calculate_server` (CVE-2026-44717) moves from the addition to the holdout walk's part, and the addition's count of admitted servers (25 of 43 at `39fc0ff`) drops with it. `test_nuisance_walk_record_loads.py` must still pass, and the nuisance admission must still load.
- **A settlement on a flaw the nuisance walk record also settles.** `_contradiction_problems` refuses opposite verdicts, so the four added settlements and the copied 85787 one are checked against the walk record before the census commit.
- **The census script's output.** A diff that reformats untouched records means the serialisation differs from the committed one: the script is fixed, the file is not hand-patched.

## Test scenarios

Each test file keeps its given and then modules, and each new test is red before its code. `tests/unit/test_holdout_targets.py` has none yet: the setup of its new guards that abstracts something (reading a Dockerfile's instructions for a path whose component is `/work`, extracting the PEM a 5323 Dockerfile inlines in its heredoc, loading the census's `draw.drawn`) goes into a new `tests/unit/support/test_holdout_targets_given.py`, one-liners staying inline (CLAUDE.md, Given/When/Then pattern).

`tests/unit/test_public_stand_ins.py` is 285 lines and the new tests take it past 300, so the guards on the committed files (`test_every_committed_capture_loads_with_its_leaf`, `test_the_committed_captures_are_exactly_the_declared_stand_ins`, the authority and leaf tests, the new IP subtree and pending-host tests) move to a new `tests/unit/test_committed_stand_ins.py` with its given and then modules, and the loader tests on `tmp_path` stay.

- `tests/unit/test_census_draw.py` (or a new `test_census_work.py` with its given): an agent record with a `fallback_model` loads and satisfies `_agent_problems` once. A record whose `fallback_model` equals its `model` is refused. Two records of one role and scope with no fallback still read as two agents.
- `tests/unit/test_public_stand_ins.py`: a capture with `source: capture` and no `captured_at` is refused. A written file (`software_sources`) with a `captured_at` is refused and without one loads. A `form_field` on a `GET` route is refused, beside an `action` is refused. Two routes of one target differing only by `form_field` load. Every committed capture loads.
- `tests/unit/test_capture_stand_in.py`: `'POST URL q=wikipedia'` parses to a POST with that body and records a route with `form_field="q"`. A body with two fields is refused. The record carries `source: "capture"`.
- `tests/integration/test_cve_planting_stand_ins.py` (Docker): the stand-in answers a form `POST` carrying the route's field from that route and one lacking it with the default.
- `tests/unit/test_cve_launches.py`, with the fake port: `filesystem_scope_env` hands over a tree with no `leak<i>` entries and launches with the checkout as scope. `command_injection_checkout_env` hands over a checkout holding an empty `captures` directory in the normal shape and none in the empty-layout arm. `houtini_lm_env` puts the two `-e` before the image. Each mounts the layout read-only by default and read-write under a `READ_WRITE` host.
- `tests/unit/test_cve_layout_check.py` (or the module's existing test): `layout_routes` lists each layout place once with its kept flag and route, and adds no admission failure for an unrouted unkept place.
- `tests/unit/test_holdout_targets.py`: `HOLDOUT_TARGETS` identifiers equal the census's `draw.drawn` as sets (the two orders differ, transplant against draw), from the first commit on. No holdout target runs as `SymbolicUser.HOST` (with the step that moves the last of 4270, 11489 and 66335 off it). No image a CVE or holdout target names has a Dockerfile whose instructions name a path under `/work` (the path component, so `/api/v1/workflows` in the n8n image does not match) (with 25546). Every holdout target's working directory is the checkout or `/work` (at the closing step). The 5323 baked authority equals the committed one (with 5323). The GHSA target declares `evals/n8n_instance_backend.py` among its backend sources (with the n8n step).
- `tests/unit/test_holdout_card_readiness.py` and `test_calibration_dossier.py` at the closing step: the unset cases go, a check without a version no longer loads, a check below 11 is still a gap.
- The existing guards pass for every vested target: `test_holdout_targets.py` (vocabulary, offered and placeable kept places, planted together, no tools filter or CI skip, digest-pinned backend images), `test_holdout_kit_isolation.py`, `test_cve_compose_labels.py` (labels, no `COPY`/`ADD`, every base by digest), `test_cve_baseline.py` (a stand-in target lists the stand-in service), `test_holdout_fixture_sources.py` (live once the cards carry stand-ins: every card stand-in is a file its target's fingerprint covers), `test_holdout_census.py`, `test_nuisance_walk_record_loads.py`, `test_nuisance_admission_loads.py`.
- No unit test enters a Doris or backend lifecycle: the per-target Docker `calibrate` is their gate. The real-n8n builder keeps its no-holder branch, which `test_cve_launches.py` already enters through `_LAYOUT_BUILDERS` with an empty spec and the fake port (no holder, so no backend), and the three new builders join `_LAYOUT_BUILDERS`.
- `tests/unit/test_committed_stand_ins.py`: the committed authority's IP subtree and the IP-literal leaf (no common name), and the pending-host set of "Shared stand-in files".

## Verification

- Every step: `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright` with no file argument, and the step's `uv run python -m evals.run_holdout calibrate --cve <ID>` green after `docker compose -f evals/docker/compose.yml build <services>` (`--no-cache` for 46514).
- `uv run python -m evals.run_cve_benchmark --calibrate`, the four acceptance targets live and dead as before: after step 1 (the stand-in format, image and authority reach the fetch target's `example.com`), after any step that changes code an acceptance builder runs (`filesystem_env`, `git_init_traversal_env`, `command_injection_env`, `ssrf_env`, `materialise`, `filesystem_launch`, `_git_launch`, the planting or layout modules, a rename with no behaviour change excepted), and at closing. A step that only adds or rewrites a holdout-only builder leaves the acceptance launches as they are, and the fingerprint listing already shows the expected moves.
- After the authority and stand-in step: `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-46341` and `uv run python -m evals.run_nuisance vet --server npm:@apify/actors-mcp-server`. S1 needs no nuisance check: `doris_backend.py` and the cluster's launch do not change, which the unmoved doris nuisance fingerprint confirms. After 85788: `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-85788` and `vet --server PyPI:awslabs-mysql-mcp-server` (the admission's normalised name, which `--server` matches exactly), the copy matching.
- After the structural census edit: `load_census` passes, `uv run python -m evals.run_holdout draw-order` is unchanged, and `uv run python -m evals.run_nuisance walk`, compared with its output before the edit, differs only by scaffold-mcp leaving, dynatrace's shorter version-setting list and positions 87 to 90 moving to the holdout walk's part with the addition's admitted count, all named in the nuisance log; `PyPI:doris-mcp-server` is still listed.
- At the closing step: `uv run python -m evals.run_holdout calibrate` green on all 37 under the reported Docker version, every kept layout place routed, except a target the maintainer kept in its calibrated state under the first edge case, named in the log with its failing condition. `CVE_PLANTING_REQUIRED=1 uv run pytest tests/integration -n auto`. The fingerprint listing of the 37 and the 4 acceptance targets. `uv run python -m evals.run_holdout calibration-dossier --cve CVE-2026-44717 --out output/holdout-vesting/kit` writes a kit whose README no longer calls the card fields optional. `run_holdout run` is not launched: this plan runs no scored audit.

## Logs

- **Holdout log**, one entry per step that changes a holdout target, in the style of the existing entries, with the fingerprints before and after, plus the closing entry. The closing entry records: the 37 targets and their kits, CVE-2026-18905 and CVE-2026-45555 out with their reasons in the census, the census acts (settlements removed and added, the version 10 history, the version 11 steps and give-ups, the sibling lists), the void and redone pairs with their reasons (decision 2), the extent of fallback (every authoritative artifact requested on `claude-opus-5-5` and answered on `claude-opus-4-8`, with the per-round session counts of manifest 1c), the translated texts, the 4270 `software_releases: []` decision, the 46514 version divergence, image size and startup time, the 5323 reading, the 25546 harness-convention fix, the four release raises (the release raised at vesting after the stable-release reading and proven by the Docker calibration, the version 11 card check having been made on the earlier release, MySQL 26.10.0 taken as the latest GA over the 9.7.4 LTS of the same day, OpenSSH 10.6p1 kept over the later 10.6p2 whose fix concerns sshd only), the Docker version, the current grammar fingerprint beside the draw's, and that no holdout run has taken place.
- **Labeling log**, an entry with the four questions of ADR 016 for each shared fixture-code change: the stand-in format, image and capture command (Q6, S8), the single authority (S2), the builders and `cve_environments.py` changes (S1, S4 to S6, the Houtini builder, the removed contextforge builder), and the route report. Each states that no CVE baseline exists and no label moves.
- **Nuisance log**: the apify fingerprint moving with the authority, its capture and the stand-in image, positions 87 to 90 entering the holdout walk (mcp_calculate_server out of the addition, its new admitted count), scaffold-mcp leaving the population and dynatrace's version-setting list shortened by the new `effect_in_tool_response` settlements, the removed `grammar_class` settlement of 66335 leaving the population unchanged, and CVE-2026-85788's copy refreshed with its fingerprint.

## Living docs

- `README.md` (the holdout paragraph): "All thirty drawn targets" becomes the 37, the 30 drawn and the 7 the version 11 re-walk let in, every card ready under version 11.
- `CONTRIBUTING.md` (the holdout paragraph): the same count, and a sentence on the heavy holdout images (Doris, FreePBX, llama.cpp with its model, Neo4j, ArcadeDB, Chromium, n8n, Godot) and on pruning the build cache after building them.
- `CLAUDE.md`. Commands: `capture_stand_in` (the `POST URL BODY` form, the `form_field` route, the `source` marker, a written file carrying no `captured_at`), `generate.sh` (an IPv4-literal host gets an IP SAN, a leaf with no common name and an IP constraint), `run_holdout calibrate` (the 46514 image builds FreePBX from network sources and is built cold), `run_holdout run` (at closing, the refusal is a missing card or a card check below version 11, the "lacks a field" clause gone). Landmines: the 5323 images bake the fixture authority, so a regeneration rebuilds them and the test catches a stale copy. The holdout Doris launch mounts the layout and runs under 65534 while the nuisance one does not.
- `CHANGELOG.md` `[Unreleased]`: the count in the `run_holdout` entry (line 16), the field-refusal lines (47 and 103) amended at closing, and Changed entries for `AgentRecord.fallback_model`, the capture format's `source` and form-field route, `capture_stand_in`'s `POST`, `generate.sh`'s IP literal and the per-layout-place route report.
- `evals/holdout_census_method.md`: the fallback record.

## Due diligence record

What the plan's due-diligence pass concluded about the external facts this plan cites or defers, checked against live sources on 2026-11-06. Later passes, the implementation-phase fact check included, read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it, so this section never asserts something nobody checked. Per-target calibrated facts (vulnerable and patched versions, mechanisms, CVSS, the card's software releases) come from the calibration kits and were not moved by any lookup.

- SETTLED: Platform-Tools `37.0.1` is the stable release on 2026-11-05 (July 2026, 37.0.2 being a November 2026 canary) (verified against developer.android.com/tools/releases/platform-tools)
- SETTLED: OpenSSH `10.6p1` published 2026-10-06, `10.6p2` published 2026-11-05 as a security release whose fix (password authentication bypass) concerns sshd only, the 9654 image carrying the client only (verified against openssh.org/releasenotes.html and /txt/release-10.6p2)
- SETTLED: PostgreSQL `18.6` published 2026-08-13 and the latest release on 2026-11-05 (19 at RC 1 only) (verified against postgresql.org/docs/release/18.6 and /support/versioning)
- SETTLED: `postgres:18.6-bookworm@sha256:f1ea2a1a4fb7b68d4836be1fdcb8a6466a89b072158bf9d97663600538c294c5`, the PostgreSQL 18 image's `PGDATA` at `/var/lib/postgresql/18/docker` and `VOLUME /var/lib/postgresql` (verified against Docker Hub tag API and the docker-library postgres README)
- SETTLED: `mysql:26.10.0@sha256:3819b2b23835c4a73c8b022fafc33c8095c0f81c929a8b7a84613d2fba6c52f5`, MySQL Community Server 26.10.0 published 2026-10-20 (the same day as the 9.7.4 LTS), the official image tagging it `latest` and `innovation` (verified against Docker Hub tag API, docker-library official-images `library/mysql`, dev.mysql.com 26.10 release notes and downloads page)
- SETTLED: `mysql_native_password` removed as of MySQL 9.0.0, so absent from 9.x and 26.x (verified against dev.mysql.com native pluggable authentication page)
- SETTLED: n8n `2.46.6` released 2026-11-04, `n8nio/n8n:2.46.6` on Docker Hub at `sha256:8602f5dfacbe2c931eeafd010de0e68182310e9f309921e780ab69182e92b3ae` (verified against GitHub release and Docker Hub tag API)
- OPEN (deferred): the digest `docker.n8n.io` serves for `n8nio/n8n:2.46.6`, checked at build time against Docker Hub's and pinned from `docker.n8n.io` when the two differ
- SETTLED: `ghcr.io/ggml-org/llama.cpp:server-b12124@sha256:c0a11067c72bb1eb330b8bddbf9869274c195e596bf4fae55fd527102e644b85`, the build the floating `server` tag named, published about 2026-11-05 (verified against the GHCR package versions page)
- SETTLED: Qwen2.5-3B-Instruct-GGUF revision `7dabda4d13d513e3e842b20f0d435c732f172cbe` (`main` unchanged since 2024-09-20), `qwen2.5-3b-instruct-q4_k_m.gguf` sha256 `626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d` (verified against the Hugging Face model and tree API)
- SETTLED: `freepbx17=17.1-1.sng12`, `asterisk22=22.11.0-1.sng12`, `ioncube-loader-82=1.0.0-1.sng12` (verified against deb.freepbx.org freepbx17-prod bookworm Packages index)
- SETTLED: `https://github.com/netz98/n98-magerun2/releases/download/10.1.0/n98-magerun2.phar` sha256 `76c931312f3ab6a5a5e1dbd40544cf43f9ecab176bca6a3597ebf4a3413fe270`, published 2026-10-07 and marked latest (verified against the GitHub releases API)
- SETTLED: `neo4j:5.26.1` exists (verified against Docker Hub tag API)
- SETTLED: nmap `7.993` source tarball dated 2026-10-23 (verified against nmap.org/dist)
- SETTLED: `wireshark-4.6.9.tar.xz` dated 2026-09-23 (verified against wireshark.org/download/src/all-versions)
- SETTLED: gh `v2.103.3` published 2026-10-26 (verified against the GitHub releases API)
- SETTLED: `@salesforce/cli` `2.157.8` (verified against the npm registry)
- SETTLED: Godot `4.4.1-stable` (verified against the GitHub releases API)
- SETTLED: `@biomejs/biome` `1.9.4` (verified against the npm registry)
- SETTLED: miniwdl `1.16.0` and cwltool `3.3.20260925135507` (verified against PyPI)
- SETTLED: openssl name constraints take `permitted;IP:<address>/<mask>` and a leaf `subjectAltName = IP:<address>` (verified against the OpenSSL x509v3_config manual)
- SETTLED: `docker builder prune -a -f` removes all unused build cache and no image, `docker image prune -f` dangling images only, both prompting without `-f` (verified against docs.docker.com CLI reference)
- OPEN (deferred): the digests of `neo4j:5.26.1`, `debian:12` (46514) and `node:20-bookworm-slim` (25546), the uv release and its checksum (35402) and the Node.js release and its checksum (82112), both read from the kit's calibrated image when still on disk, otherwise from its build log, the FreePBX installer commit and sha256, the frogman tag commits, the OpenSSH 10.6p1 tarball's hex sha256 (its release notes give base64 `qdyVZd/+hkD2TYY80poyvEo9vewFZqf8RMXW7nZ9Xzk=`) and the Platform-Tools 37.0.1 zip's sha256, all resolved at implementation from the kit or the source

## Implementation steps

Forty-three steps: four shared steps, one step per target in the Approach order (37), and two closing steps. Each step is one commit. The plan's first Approach step (shared code) touches about thirty files across four unrelated concerns, so it is cut into four: the census record and route report code with the module split, the stand-in format, the authority and the campaign's stand-in files, and the structural census edit with the two leaving targets. Every target step ports seven files from a kit read outside the repository and closes on a Docker calibration, which is one agent session's budget, so targets are never grouped (the plan's "one target per step and commit"). The v9 shim's retirement and the whole-set closing are split because the second runs the 37 calibrations and the living docs.

Verification commands (from `CLAUDE.md`): full check `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright` (no file argument), which closes every step. Short loop `uv run pytest tests/unit -n auto --maxprocesses 6`, red tests `uv run pytest <files> -n 0`, `uv run pyright <files>` on changed files. Image build `docker compose -f evals/docker/compose.yml build <services>`. Calibration `uv run python -m evals.run_holdout calibrate --cve <ID>`. Acceptance `uv run python -m evals.run_cve_benchmark --calibrate`.

### Rules for every step

- **Kits and manifest.** The maintainer gives their location at launch. They are read, never written, and no committed file names their location.
- **Fingerprint listing.** Step 1 writes a script under the gitignored `output/holdout-vesting/` that prints `cve_baseline.grammar_fingerprint()`, `cve_baseline.fixture_fingerprint` of the 4 acceptance targets and of every holdout target, and `nuisance_fingerprint.nuisance_fixture_fingerprint` of `npm:@apify/actors-mcp-server` and `PyPI:doris-mcp-server`, into `output/holdout-vesting/fingerprints-step-<N>.txt`. Step 1 runs it once before any change (`fingerprints-step-0.txt`), and every step runs it after its change and compares with the previous listing against the expected moves of the plan's "Fingerprints" paragraph. Any other move stops the step and goes to the maintainer.
- **Docker disk.** Before a step that builds or runs Docker (the full check's integration tests included), check `df -h /`: below 25 GB free, stop and report to the maintainer, deleting nothing on its own. Do not grow Docker disk usage beyond what the step needs. Leave removal of pre-existing images to the maintainer. A step that rebuilds an image the repository already builds (a kept target's, the stand-in's, the n8n stand-in's) runs `docker image prune -f` (dangling only) after its build, since the replaced image becomes dangling. Every target step ends with `docker builder prune -a -f` (all build cache, built images kept). A step marked **heavy** builds and calibrates its target alone. Each batch's last step reports `docker system df`. No step overlaps a nuisance run or calibration.
- **Census edits** go through the one-off script under `output/holdout-vesting/` that step 4 creates (load with `HoldoutCensus`, change the records found by flaw and criterion, never by index, write `model_dump_json(indent=2)` back, then `load_census` passes). Never `run_census assemble`. A diff that reformats untouched records means the script is wrong: fix the script, never hand-patch the file.
- **Living docs** change in the step that changes the behaviour they describe, as `CLAUDE.md` asks, and each step names its own.

### Recipe for every target step (steps 5 to 41)

Stated once, applied by each target step, whose **Do** lists only what is specific to it. The plan's "Approach" paragraph and the target's bullet under "Per-target corrections" govern.

1. **Dockerfiles.** From the authoritative kit, the two server Dockerfiles into `evals/docker/Dockerfile.holdout-<year>-<num>-<service>` and `-patched` (GHSA form for the GHSA target), each `COPY` or `ADD` turned into an inline `RUN` heredoc or a pinned download, each base pinned by digest, git refs resolved to full commit hashes. A kept target's Dockerfiles are rewritten in place.
2. **Compose.** The two services in `evals/docker/compose.yml` with their image tag and fingerprint label, printed by `uv run pytest tests/unit/test_cve_compose_labels.py -n 0`.
3. **Fixture.** The kit's fixture into `evals/holdout_fixtures/<slug>.py` with the import swaps (`kit_client.KitClient` to `mcp_auditor.domain.ports.MCPClientPort`, `kit_launch.<builder>` to `evals.cve_environments` or `evals.holdout_environments`), `mechanisms` as a `frozenset`, the acceptance-only fields (`severity`, `awaited_capability=None`, `note`, `tools_filter=None`, `ci_skip_reason=None`), the literal `"sentinel"` in `images` for a target that keeps a network place, the kit's `planting_host` (its working directory `/srv/app`, `/work` for CVE-2025-53818, set on the host, never as a Dockerfile `WORKDIR`), the kit's launch argv and `scope` kept exactly, the kit's exploits and benign call kept. Kit harness copies and kit helpers are never vested. A kept target's module is rewritten in place. A new target's `TARGET` is appended to `HOLDOUT_TARGETS` in `evals/holdout_targets.py`.
4. **Calibrate.** Build both services, then `uv run python -m evals.run_holdout calibrate --cve <ID>` until green. A red calibration is handled as the plan's first edge case says: repair what the vesting carries (launch settings, permissions, readiness, the image's build, a harness convention), never a kept place, an exploit or the benign call in meaning. When only such a change would make it green, stop and report the failing condition to the maintainer. No target is excluded, no recalibration outside the repository is launched.
5. **Census record**, through the census script: the version 11 card from the kit with the target's corrections, each unkept layout place carrying `route_checked` from this calibration's report (the "not kept" lines step 1 adds), an exec-only target's unkept layout places giving as reason that the frozen table offers them to read reach only (S9). The version 11 card check (`rule_version: 11`, reported and confirmed gaps) replaces the old one. Agent records: the authoritative calibrator and card checker, and the card writer of a grouped CARDS pass as a `calibrator` row of the kit calibrator's scope, each `model="claude-opus-5-5"`, `fallback_model="claude-opus-4-8"`. A new target joins `draw.drawn`.
6. **Stand-in host.** When the target declares a host of the pending set step 3 creates, the step removes it from the set.
7. **Holdout log.** One entry in `docs/holdout-log.md` in the style of the existing ones, with the fingerprints before and after, every repair made under the edge cases and the step's own items.
8. **Disk.** `df -h /` before the build (the rule above), `docker image prune -f` after the build of a kept target, `docker builder prune -a -f` at the end of the step.

**Files** of every target step: the two Dockerfiles, `evals/docker/compose.yml`, the fixture module, `evals/holdout_census.json`, `docs/holdout-log.md`, and `evals/holdout_targets.py` for a new target. Each step lists only its extra files.

**Test** of every target step: the calibration above green, and the existing guards green on the target (`tests/unit/test_holdout_targets.py`, `test_holdout_kit_isolation.py`, `test_cve_compose_labels.py`, `test_cve_baseline.py`, `test_holdout_fixture_sources.py`, `test_holdout_census.py`), including the tie between `HOLDOUT_TARGETS` and `draw.drawn`.

**Verify** of every target step: `uv run pytest tests/unit/test_cve_compose_labels.py tests/unit/test_holdout_targets.py tests/unit/test_holdout_kit_isolation.py tests/unit/test_cve_baseline.py tests/unit/test_holdout_fixture_sources.py tests/unit/test_holdout_census.py -n 0`, the calibration green, the fingerprint listing with only the target's own fingerprint moving (plus the moves the step's **Do** names, and every CVE fixture fingerprint when the step changes `holdout_environments.py`, as the plan's "Fingerprints" paragraph expects), then the full check.

### Shared steps

#### Step 1: Agent fallback model, per-place route report, the drawn tie, the holdout builders module

- **Files**: `tests/unit/test_census_work.py` and `tests/unit/support/test_census_work_given.py` (new), `evals/census_work.py`, `evals/holdout_census_method.md`; `tests/unit/test_cve_layout_check.py` (and its given), `evals/cve_layout_check.py`; `tests/unit/test_holdout_targets.py`, `tests/unit/support/test_holdout_targets_given.py` (new); `evals/holdout_environments.py` (new), `evals/cve_environments.py`, `evals/cve_baseline.py`, the importers (`evals/holdout_fixtures/cve_2025_66335_doris.py`, `cve_2026_65831_arcadedb.py`, `cve_2026_85788_mysql.py`, `ghsa_8g7g_hmwm_6rv2_n8n.py`, `tests/unit/test_cve_launches.py`, `tests/unit/test_doris_backend.py`, `tests/unit/test_doris_serialization.py` and its given, the twin comments in `evals/holdout_kit/kit_launch.py` and `evals/nuisance_backends.py`); `CHANGELOG.md`, `docs/labeling-log.md`.
- **Do**: Check free space with `df -h /` first (the full check builds images), as the disk rule says. Write the fingerprint script and `fingerprints-step-0.txt` before any change.
  - Tests first: in `test_census_work.py`, an agent record with a `fallback_model` loads and counts once in `_agent_problems`, a record whose `fallback_model` equals its `model` is refused, two records of one role and scope with no fallback read as two agents. In `test_cve_layout_check.py`, `layout_routes` lists each layout place once with its kept flag and its route, and an unrouted unkept place adds no admission failure. In `test_holdout_targets.py`, the identifiers of `HOLDOUT_TARGETS` equal `draw.drawn` of `evals/holdout_census.json` as sets (the census loaded in the new given). It is green today, both listing the same 30.
  - `AgentRecord.fallback_model: str | None = None` with a validator refusing `fallback_model == model` (plan, "Shared code"). The method note says an agent that continued on the fallback model is one record with both.
  - `LayoutRoute` (frozen dataclass beside `LayoutSurface`: `place_id`, `kept`, `routed`) and the pure `layout_routes(places, kept, planted) -> list[LayoutRoute]`. `confirm_admission` prints each unkept layout place's route labelled not kept, adds no failure and changes no decision. The route and layout golden masters stay unregenerated.
  - Move the holdout-only builders that exist today (`doris_db_env`, `arcadedb_mcp_env`, `mysql_db_env`, `ssrf_redirect_env`, with the private helpers and constants only they use, such as `_joins_holder`, `_start_n8n_stub` and the Doris imports) to `evals/holdout_environments.py`, unchanged, and add the module to `ENVIRONMENT_PATHS`. `contextforge_ssrf_env` stays until step 4 removes it. Every importer follows (the 66335 fixture takes `DORIS_DB` from `evals.doris_backend`). `cve_environments.py` keeps the acceptance builders and the shared launch types, and its helpers the holdout builders reuse become public, renamed with every caller (`_materialise` to `materialise`, `_filesystem_launch` to `filesystem_launch`, `_PROJECT` and `_CHECKOUT` to `PROJECT` and `CHECKOUT`): pyright's strict mode refuses a private name imported from another module.
  - `CHANGELOG.md` `[Unreleased]` Changed: `AgentRecord.fallback_model` and the per-layout-place route report. `docs/labeling-log.md`: one entry with the four questions of ADR 016 for the route report and the module split (every CVE fixture fingerprint moves with `ENVIRONMENT_PATHS`, no CVE baseline exists, no label moves).
- **Test**: the three new test groups above, `tests/unit/test_cve_launches.py` unchanged in substance (the moved builders still in `_LAYOUT_BUILDERS`), the doris tests on the new module.
- **Verify**: the new tests red then green with `-n 0`, the short loop, the fingerprint listing (every CVE fixture fingerprint moves, the grammar and both nuisance fingerprints do not), the full check. No acceptance calibration: the code an acceptance builder runs is only renamed.

#### Step 2: The stand-in format: source marker, form-field route, `POST` capture

- **Files**: `tests/unit/test_public_stand_ins.py`, `tests/unit/test_committed_stand_ins.py` with `tests/unit/support/test_committed_stand_ins_given.py` and `_then.py` (new), `tests/unit/test_capture_stand_in.py`, the capture givens (`tests/unit/support/test_public_stand_ins_given.py`, `test_cve_planting_stand_ins_given.py`, `test_capture_stand_in_given.py`, `test_cve_baseline_given.py`, `tests/integration/support/test_cve_planting_stand_ins_given.py`), `tests/integration/test_cve_planting_stand_ins.py`; `evals/public_stand_ins.py`, `evals/capture_stand_in.py`, `evals/docker/Dockerfile.stand-in`, `evals/docker/compose.yml` (its label), `evals/stand_ins/example.com.json`, `demo.ckan.org.json`, `api.apify.com.json`; `CLAUDE.md`, `CHANGELOG.md`, `docs/labeling-log.md`.
- **Do**:
  - Move the guards on the committed files (`test_every_committed_capture_loads_with_its_leaf`, `test_the_committed_captures_are_exactly_the_declared_stand_ins`, the authority and leaf tests) to `tests/unit/test_committed_stand_ins.py` with its given and then modules, the loader tests on `tmp_path` staying. The givens that build a capture gain `"source": "capture"`.
  - Tests first: a capture with `source: capture` and no `captured_at` is refused, a `software_sources` file with a `captured_at` is refused and without one loads (the `command`/`captured_at` required-field parametrization changes accordingly), a `form_field` on a `GET` route is refused, beside an `action` is refused, two routes of one target differing only by `form_field` load. In `test_capture_stand_in.py`, `'POST URL q=wikipedia'` parses to a POST with that body and records a route with `form_field="q"`, a body with two fields is refused, the record carries `source: "capture"`. In the integration test (Docker), the stand-in answers a form `POST` carrying the route's field from that route and one lacking it with the default.
  - `StandInCapture.source: Literal["capture", "software_sources"]`, `captured_at` optional and required exactly for a capture, `StandInRoute.form_field` with its validator, `_one_route_per_key` on `(scheme, method, target, action, form_field)`, the module docstring sentences (plan, "Shared code"). The three committed captures gain `"source": "capture"`, captured values untouched. `Dockerfile.stand-in`'s form-field lookup after the action lookup and its compose label. `capture_stand_in`'s `'POST URL BODY'` argument.
  - `CLAUDE.md` Commands, the `capture_stand_in` entry: the `POST URL BODY` form, the `form_field` route, the `source` marker, a written file carrying no `captured_at`. `CHANGELOG.md` Changed: the capture format's `source`, the form-field route, `capture_stand_in`'s `POST`. `docs/labeling-log.md`: the ADR 016 entry for the format, image and capture command (Q6, S8).
- **Test**: as above, plus every committed capture loads.
- **Verify**: the short loop, `uv run pytest tests/integration/test_cve_planting_stand_ins.py -n 0` (builds the stand-in image, then `docker image prune -f` for the image it replaces), `uv run python -m evals.run_cve_benchmark --calibrate` with the four acceptance targets live and dead as before, `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-46341` and `uv run python -m evals.run_nuisance vet --server npm:@apify/actors-mcp-server` green, the fingerprint listing (every CVE fixture fingerprint and the apify one move, the doris one does not), the full check.

#### Step 3: The single authority and the campaign's stand-in files

- **Files**: `tests/unit/test_committed_stand_ins.py` (and its given), `tests/unit/support/test_public_stand_ins_given.py` (the pending set); `evals/stand_ins/tls/generate.sh`, every file under `evals/stand_ins/tls/` (regenerated), `evals/stand_ins/w3challs.com.json`, `html.duckduckgo.com.json`, `api.github.com.json`, `example-org.my.salesforce.com.json`, `45.55.0.10.json`, `rds.us-east-1.amazonaws.com.json`, `secretsmanager.us-east-1.amazonaws.com.json` (new); `CLAUDE.md`, `CHANGELOG.md`, `docs/labeling-log.md`, `docs/nuisance-log.md`.
- **Do**:
  - Tests first: the authority test and `test_every_committed_leaf_names_an_https_stand_in_host` learn IP subtrees and IP SANs (an IP-literal host permitted as `<host>/32` with no excluded subtree, its leaf naming it once as an IP address, with no common name in its subject). `declared_stand_in_hosts()` also counts a named set of the hosts whose declaring target is not yet vested: `w3challs.com` (CVE-2026-2130), `html.duckduckgo.com` (CVE-2026-42260), `api.github.com` (CVE-2025-53818), `example-org.my.salesforce.com` (CVE-2026-26029), `45.55.0.10` (CVE-2025-65719), `rds.us-east-1.amazonaws.com` and `secretsmanager.us-east-1.amazonaws.com` (CVE-2026-85787, CVE-2026-85788). A test pins the set to hosts that have a committed capture and no declaring target.
  - `generate.sh`: an IPv4-literal host gets `subjectAltName = IP:<host>` and `permitted;IP.<n> = <host>/255.255.255.255` instead of the two DNS lines, and a leaf subject with no common name (plan, "Shared code"). One run with the ten HTTPS hosts of the plan's "Shared stand-in files".
  - The stand-in files as that section lists them: `w3challs.com.json` the kit's real capture (`source: "capture"`), `api.github.com.json`, `example-org.my.salesforce.com.json` and `45.55.0.10.json` written (`source: "software_sources"`, `captured_at` dropped), the DuckDuckGo route recaptured with `uv run python -m evals.capture_stand_in --out evals/stand_ins/html.duckduckgo.com.json 'POST https://html.duckduckgo.com/html/ q=wikipedia' --header 'User-Agent: Apifox/1.0.0 (https://apifox.com)' --header 'Accept: */*'` (network, no LLM). When the live answer is a bot challenge rather than a results page, the kit's captured route of 2026-11-05T04:15:55Z is kept with its `form_field` set and the log says so. The AWS files of S3: one `rds.us-east-1.amazonaws.com.json` with a `POST /` route per action (`DescribeDBInstances` from 85787's body, `DescribeDBClusters` from 85788's), the us-west-2 copy dropped, `secretsmanager.us-east-1.amazonaws.com.json` keyed on `secretsmanager.GetSecretValue` with `VersionStages`, the us-east-1 ARN and the username `postgres`, both with the `400 InvalidAction` default on both schemes. The Salesforce routes carry no `action` on a non-`POST` route.
  - `CLAUDE.md` Commands, the `generate.sh` entry: an IPv4-literal host gets an IP SAN, a leaf with no common name and an IP constraint. `CHANGELOG.md` Changed: `generate.sh`'s IP literal. `docs/labeling-log.md`: the ADR 016 entry for the single authority (S2). `docs/nuisance-log.md`: the apify fingerprint moving with the authority, its capture and the stand-in image (steps 2 and 3).
- **Test**: the IP subtree and leaf tests, the pending-set test, every committed capture loads with its leaf.
- **Verify**: the short loop, `uv run python -m evals.run_cve_benchmark --calibrate` as before, `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-46341` and `vet --server npm:@apify/actors-mcp-server` green, the fingerprint listing (the fingerprints of the targets declaring a stand-in, the acceptance fetch target, CVE-2026-104120, 5323, 33060 and 58485, and the apify one move, no other: a target that declares none hashes no stand-in file), the full check.

#### Step 4: The structural census edit and the two leaving targets

- **Files**: the census script under `output/holdout-vesting/` (gitignored), `evals/holdout_census.json`; `evals/holdout_targets.py`; deleted: `evals/holdout_fixtures/cve_2026_18905_contextforge.py`, `cve_2026_45555_roslyncodelens.py`, `evals/docker/Dockerfile.holdout-2026-18905-contextforge` and `-patched`, `Dockerfile.holdout-2026-45555-roslyncodelens` and `-patched`, `tests/unit/test_contextforge_planting_contract.py`; `evals/docker/compose.yml` (four services out), `evals/cve_environments.py` (`contextforge_ssrf_env`, `_gw_tools`, `_GW_PUBLIC_IP` out), the comment in `evals/nuisance_fix_checks/cve_2026_18905_contextforge.py`; `docs/holdout-log.md`, `docs/nuisance-log.md`, `docs/labeling-log.md`.
- **Do**: Save `uv run python -m evals.run_nuisance walk` and `uv run python -m evals.run_holdout draw-order` outputs under `output/holdout-vesting/` before the edit. Then the census script applies the plan's "The census edit" structural list, from the manifest:
  - The six settlements removed, CVE-2026-45555's settlement reason trimmed, the five settlements added (`effect_in_tool_response` false for CVE-2026-7237 and GHSA-pc2w-4mq8-32qw, true for CVE-2026-18954 and CVE-2026-15415, CVE-2026-85787's copied verbatim from `evals/nuisance_walk_record.json`), checked against the walk record before writing.
  - The version 10 history: the `given_up` steps and the two version 10 give-ups of each leaving target, and the version 10 steps of positions 87 to 90.
  - The version 11 walk steps (41 re-walk entries and positions 88 to 90) with the outcomes and sibling lists the plan gives, CVE-2026-53710's step recording its server as distinct from 18905's gateway.
  - The counted version 11 give-up pair of each of the 29 exclusions (decision 2 for 77252 and 33980, none for 46514), the five French details as faithful English translations.
  - CVE-2026-18905 and CVE-2026-45555 out of `drawn` with their card and check.
  - The agent records of the 29 exclusions' calibrations and the two version 10 pairs, with `fallback_model` where the session fell back, and every set-aside session with its cause.
  Then remove the two targets from `HOLDOUT_TARGETS` and delete their files, services and the contextforge contract test, and remove the contextforge builder. The nuisance contextforge Dockerfiles and fix check stay.
  Logs: the holdout-log entry for the census acts and the two leaving targets (fingerprints before and after), the nuisance-log entry (positions 87 to 90 entering the holdout walk with mcp_calculate_server leaving the addition and its new admitted count, scaffold-mcp leaving the population, dynatrace's shorter version-setting list, 66335's removed `grammar_class` settlement leaving the population unchanged), and the labeling-log ADR 016 entry for the removed contextforge builder.
- **Test**: `tests/unit/test_holdout_census.py`, `test_holdout_targets.py` (the drawn tie with 28), `test_nuisance_walk_record_loads.py`, `test_nuisance_admission_loads.py` green. No new test.
- **Verify**: `load_census` passes, `draw-order` output unchanged, the new `run_nuisance walk` output differs from the saved one only by the moves named in the nuisance log with `PyPI:doris-mcp-server` still listed, the census diff touches no untouched record, the fingerprint listing (every CVE fixture fingerprint moves with `cve_environments.py`, the two leaving targets gone), the full check.

### Batch 1: new or changed builders

#### Step 5: CVE-2025-66335 (Doris), the holdout Doris launch under 65534 (heavy)

- **Files**: `evals/holdout_environments.py` (`doris_db_env`), `tests/unit/test_doris_serialization.py` and its given if the builder's signature reaches them, `CLAUDE.md`, `docs/labeling-log.md`. No kit fixture: the repository fixture is updated, the card comes from the CARDS pass.
- **Do**: S1: `doris_db_env` gains the keyword-only `docker`, builds the layout through `owned_layout`, and its launch gains `*unprivileged_user_args()` (from `evals.cve_planting_base`), `-w spec.host.working_directory` and `*layout_mount_args(root, spec.host.layout_mount)`, keeping everything the plan's S1 paragraph lists. The comment and twin note rewritten. `doris_backend.py` untouched. The host becomes `PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/app", has_network=True)`. The card records Apache Doris 4.1.3 and sibling CVE-2025-66336. `CLAUDE.md` Landmines: the holdout Doris launch mounts the layout and runs under 65534, the nuisance one does not. Labeling log: the ADR 016 entry for S1. If `doris-mcp-server` writes beside its install or under the working directory at start, it is a red calibration handled by the recipe.
- **Test**: the recipe's, with the doris unit tests green.
- **Verify**: the recipe's, the doris nuisance fingerprint unmoved.

#### Step 6: GHSA-8g7g-hmwm-6rv2 (n8n-mcp), the real-n8n builder (heavy)

- **Files**: `tests/unit/test_holdout_targets.py`, `tests/unit/test_cve_launches.py`, `evals/n8n_instance_backend.py` (new), `evals/holdout_environments.py` (the real-n8n builder replaces `ssrf_redirect_env`), `evals/docker/Dockerfile.holdout-ghsa-8g7g-hmwm-6rv2-n8n-redirect` (and its compose service and label), `docs/labeling-log.md`.
- **Do**: Test first: the GHSA target declares `evals/n8n_instance_backend.py` among its `backend_sources`. S5 as the plan's paragraph gives it: the n8n backend's start, provisioning (owner, API key, the active webhook workflow) and removal in `evals/n8n_instance_backend.py` (`evals/n8n_backend.py` untouched), `owned_layout`, the no-holder branch kept (still entered by `_LAYOUT_BUILDERS` with the fake port), the workflow id stored by the builder before it yields and cleared on exit. The n8n image `FROM docker.n8n.io/n8nio/n8n:2.46.6@sha256:<digest>`, the digest `docker.n8n.io` serves, compared at build time with Docker Hub's `sha256:8602f5dfacbe2c931eeafd010de0e68182310e9f309921e780ab69182e92b3ae` and the `docker.n8n.io` one pinned when they differ, `_N8N_REDIRECT_IMAGE` keeping its tag. The benign `n8n_test_workflow` on the provisioned workflow, `node:22-bookworm-slim` at the kit's digest. The nuisance fix checks' own `ssrf_redirect_env` (`evals/nuisance_fix_checks/cve_2026_44694_n8n.py`) is not touched. Labeling log: the ADR 016 entry for S5. Calibrate with `--cve GHSA-8g7g-hmwm-6rv2`.
- **Test**: the backend-sources test, the recipe's.
- **Verify**: the recipe's.

#### Step 7: CVE-2026-4270 (aws-api-mcp), `filesystem_scope_env`

- **Files**: `tests/unit/test_cve_launches.py` (and its given if needed), `evals/holdout_environments.py`, `docs/labeling-log.md`. Dockerfiles `Dockerfile.holdout-2026-4270-aws-api-mcp[-patched]`, never the nuisance `Dockerfile.aws-api-mcp`.
- **Do**: Tests first: `filesystem_scope_env` hands over a tree with no `leak<i>` entries, launches with the checkout as scope, and joins `_LAYOUT_BUILDERS` (read-only by default, read-write under a `READ_WRITE` host). Then the builder (S4), reusing the shared `materialise` and `filesystem_launch` without changing them. When a shared helper has to change, the acceptance calibration runs in Verify. The target per its correction bullet: kept 21 to 20, `UNPRIVILEGED`, aws-credentials unkept with its observed reason, the telemetry variable dropped, `software_releases: []` with the decision logged, the `planting_host.user` reason citing the 65534 owner. Labeling log: the ADR 016 entry for `filesystem_scope_env`.
- **Test**: the builder tests, the recipe's.
- **Verify**: the recipe's, plus `uv run python -m evals.run_cve_benchmark --calibrate` when a shared helper changed.

#### Step 8: CVE-2025-11489 (desktop-commander), read-write layout

- **Files**: `tests/unit/test_holdout_targets.py`.
- **Do**: Test first: no holdout target runs as `SymbolicUser.HOST` (green once this target moves, 66335 and 4270 having moved). `filesystem_scope_env` under `layout_mount=LayoutMount.READ_WRITE`, `UNPRIVILEGED`, kept 19 to 20 (container-hostname in), `mechanisms` `{READ_OUTSIDE_SCOPE, COMMAND_EXECUTION}`, the default configuration, card from the CARDS pass.
- **Test**: the HOST guard, the recipe's.
- **Verify**: the recipe's.

#### Step 9: CVE-2026-7785 (wireshark), `command_injection_checkout_env` (heavy)

- **Files**: `tests/unit/test_cve_launches.py`, `evals/holdout_environments.py`, `docs/labeling-log.md`.
- **Do**: Tests first: `command_injection_checkout_env` hands over a checkout holding an empty `captures` directory in the normal and fallback shapes and none in the empty-layout arm, and joins `_LAYOUT_BUILDERS`. The builder (S6) wraps `command_injection_env`'s materialisation without changing the shared one (acceptance calibration in Verify otherwise). tshark 4.6.9 built from its checksummed source on both versions. The `patched_result` copied from round 1 is replayed by `calibrate`. Labeling log: the ADR 016 entry for S6.
- **Test**: the builder tests, the recipe's.
- **Verify**: the recipe's, plus the acceptance calibration when a shared helper changed.

#### Step 10: CVE-2026-82112 (@houtini/lm), `houtini_lm_env`, new target (heavy, batch end)

- **Files**: `tests/unit/test_cve_launches.py`, `evals/holdout_environments.py`, `docs/labeling-log.md`.
- **Do**: Tests first: `houtini_lm_env` puts `-e HOUTINI_LM_FILE_ROOTS=<checkout>` and `-e HOUTINI_LM_ENDPOINT_URL=<the in-image llama-server>` before the image, and joins `_LAYOUT_BUILDERS`. Service `holdout-2026-82112-houtini-lm`, kept 21. Dockerfiles from `ghcr.io/ggml-org/llama.cpp:server-b12124@sha256:c0a11067c72bb1eb330b8bddbf9869274c195e596bf4fae55fd527102e644b85`, the GGUF at revision `7dabda4d13d513e3e842b20f0d435c732f172cbe` with sha256 `626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d` checked, Node.js from its release tarball pinned by checksum (version read from the kit's calibrated image when on disk, otherwise its build log), the entrypoint as a heredoc. Labeling log: the ADR 016 entry for the Houtini builder. Batch end: report `docker system df`.
- **Test**: the builder test, the recipe's.
- **Verify**: the recipe's.

### Batch 2: heavy images on a shared builder (every step heavy)

#### Step 11: CVE-2026-46514 (frogman), new target, FreePBX cold build

- **Files**: `CLAUDE.md`.
- **Do**: Service `holdout-2026-46514-frogman`, `command_injection_env`, kept 19, the planted account named after the nonce (uid 60123) owning the FreePBX stack. Dockerfiles as the correction bullet gives them: `debian:12@sha256:<digest>`, `freepbx17=17.1-1.sng12`, `asterisk22=22.11.0-1.sng12`, `ioncube-loader-82=1.0.0-1.sng12`, no `|| true`, the installer at a pinned commit with its sha256 (inlined from the kit as a `RUN` heredoc when the fetched one differs), the frogman 1.6.0 and 1.6.2 trees at their tag commits, each checked byte for byte against the kit's tree (a difference recorded and the tag's tree used, as the edge case says), the entrypoint as a heredoc. Build with `--no-cache`, confirm FreePBX installs with MariaDB up in one `RUN` layer, measure the image size and startup time. Card corrections of the bullet (the 1.6.2 reason, the three unkept places, the sentence on 46514's own effect, `seeded_outside_layout` reworded, container-hostname kept). The log entry carries the version divergence, size and startup time. `CLAUDE.md` Commands, the `run_holdout calibrate` entry: the 46514 image builds FreePBX from network sources and is built cold.
- **Test**: the recipe's.
- **Verify**: the recipe's, with `docker compose -f evals/docker/compose.yml build --no-cache` for the two services.

#### Step 12: CVE-2026-35402 (mcp-neo4j-cypher), new target

- **Do**: Service `holdout-2026-35402-neo4j-cypher`, `ssrf_env`, kept 3, `"sentinel"` in `images`. `neo4j:5.26.1@sha256:<digest>`, uv from its release archive pinned by checksum in place of `COPY --from=ghcr.io/astral-sh/uv:latest` (version read from the kit's calibrated image when on disk, otherwise its build log), the entrypoint as a heredoc, Neo4j co-located in the server image as calibrated. Card from the CARDS pass.
- **Test**, **Verify**: the recipe's.

#### Step 13: CVE-2026-65831 (ArcadeDB)

- **Files**: `evals/holdout_environments.py` and `tests/unit/test_cve_launches.py` only if the kit's builder differs from `arcadedb_mcp_env`.
- **Do**: `ARCADEDB_SETTINGS` as calibrated (root path, no seed database), `mechanisms` `{READ_OUTSIDE_SCOPE, INTERNAL_FETCH}`, `"sentinel"` kept in `images`. Card from the CARDS pass.
- **Test**, **Verify**: the recipe's.

#### Step 14: CVE-2026-5323 (a11y, Chromium), the baked authority

- **Files**: `tests/unit/test_holdout_targets.py`, `tests/unit/support/test_holdout_targets_given.py`, `CLAUDE.md`.
- **Do**: Test first: the PEM inlined in both 5323 Dockerfiles equals `evals/stand_ins/tls/fixture-authority.pem` (the extraction in the given). The Debian Chromium with its NSS database at `/tmp/.pki/nssdb` holding the fixture authority under the label `Local Root CA`, the regenerated authority's PEM inlined. The log records the Debian Chromium accepted and the card check's wrong justification (reading r6, decision 7). `CLAUDE.md` Landmines: the 5323 images bake the fixture authority, so a regeneration rebuilds them, and the test catches a stale copy.
- **Test**: the PEM test, the recipe's.
- **Verify**: the recipe's.

#### Step 15: CVE-2026-25546 (godot-mcp), the base project out of `/work`

- **Files**: `tests/unit/test_holdout_targets.py`, `tests/unit/support/test_holdout_targets_given.py`.
- **Do**: Test first: no image a CVE or holdout target names has a Dockerfile whose instructions name a path whose component is `/work` (`/api/v1/workflows` does not match). The real Godot 4.4.1, the base project baked at `/opt/base-project`, the two `create_scene` exploits building `<payload>/project.godot` under it (decision 4), `node:20-bookworm-slim@sha256:<digest>`, the card's seeded item renamed. If the calibration stays red after the move and its repairs, the kit's `/work/base-project` is kept and logged, and the guard names 25546 as its one exception. Card from the CARDS pass. The log records the harness-convention fix.
- **Test**: the `/work` guard, the recipe's.
- **Verify**: the recipe's.

#### Step 16: CVE-2026-47394 (praisonai), new target

- **Do**: Service `holdout-2026-47394-praisonai`, `command_injection_env`, kept 21, the declared `python -c` entrypoint kept. The dependency tree pinned as a constraints list inlined as a heredoc, frozen from the kit's calibrated vulnerable image when still present locally, otherwise from a first build of the vulnerable image, then the image built against it. 86 tools in pages of 50.
- **Test**, **Verify**: the recipe's.

#### Step 17: CVE-2026-26029 (sf-mcp), single-stage sf image

- **Files**: `tests/unit/support/test_public_stand_ins_given.py` (the pending set).
- **Do**: The real sf 2.157.8, kept 25 to 24, the `example-org.my.salesforce.com` stand-in declared (out of the pending set). The kit's two stages rewritten as one: the build-time HTTPS mock written by a `RUN` heredoc, started, used for the `sf` login and stopped in one `RUN`, no `COPY <<` and no `COPY --from` left. The accepted check is the kit's attempt 2.
- **Test**, **Verify**: the recipe's.

#### Step 18: CVE-2026-3484 (nmap), batch end

- **Do**: nmap 7.993 from the nmap.org tarball with its sha256 checked. Batch end: report `docker system df`.
- **Test**, **Verify**: the recipe's.

### Batch 3: stand-in targets on a shared builder

Each step that declares a pending host also lists `tests/unit/support/test_public_stand_ins_given.py` and removes the host from the pending set.

#### Step 19: CVE-2026-2130 (maigret)

- **Do**: Kept 25 to 24 (etc-hosts out), the `w3challs.com` stand-in declared (its leaf from the single authority), the realistic `docker` stand-in, the benign call on one site tag.
- **Test**, **Verify**: the recipe's.

#### Step 20: CVE-2026-42260 (open-websearch)

- **Do**: The `html.duckduckgo.com` stand-in declared, its route answering the `q` field, `NODE_EXTRA_CA_CERTS` trusted, the benign query `wikipedia`.
- **Test**, **Verify**: the recipe's.

#### Step 21: CVE-2025-53818 (github-kanban)

- **Do**: The real gh 2.103.3, working directory `/work`, the `api.github.com` stand-in declared, `SSL_CERT_FILE` trusted, kept 25 to 23, no `GH_CONFIG_DIR`. The kit's hand-patched harness copies are not vested.
- **Test**, **Verify**: the recipe's.

#### Step 22: CVE-2025-65719 (kubectl-mcp-server), new target

- **Do**: Service `holdout-2025-65719-kubectl`, `command_injection_env`, kept 24, the Kubernetes API stand-in on `45.55.0.10` declared, git tags resolved to commits, base by digest. k8s-api-server and loopback-service stay off both lists.
- **Test**, **Verify**: the recipe's.

#### Step 23: CVE-2026-104120 (fetch)

- **Do**: The fixture extracted from the kit's `kit_target.py`. Card from the CARDS pass, translated into English, its patched refusal message quoted as this step's calibration observes it, its dependencies described for both versions from the two Dockerfiles, these edits logged as the maintainer's card edits.
- **Test**, **Verify**: the recipe's.

#### Step 24: CVE-2026-33060 (ckan)

- **Do**: The working directory, `NODE_ENV` dropped.
- **Test**, **Verify**: the recipe's.

#### Step 25: CVE-2026-58485 (searxng), batch end

- **Do**: The working directory only. Batch end: report `docker system df`.
- **Test**, **Verify**: the recipe's.

### Batch 4: light ports, then the release raises

#### Step 26: CVE-2026-55787 (flyto)

- **Do**: The card's `seeded_outside_layout` filled with the pinned server image and the sentinels, `launch_options: []` left as is.
- **Test**, **Verify**: the recipe's.

#### Step 27: CVE-2026-55581 (mcp-shell)

- **Do**: The recipe from kit `-r4`.
- **Test**, **Verify**: the recipe's.

#### Step 28: CVE-2025-58358 (markdownify)

- **Do**: The benign call reads the README, the seeded `/opt/benign.md` dropped, `mechanisms` `{COMMAND_EXECUTION, READ_OUTSIDE_SCOPE, INTERNAL_FETCH}`, the kit's `build_target()` ported to a plain `TARGET`.
- **Test**, **Verify**: the recipe's.

#### Step 29: CVE-2026-5603 (magento2)

- **Do**: The magerun2 phar from `https://github.com/netz98/n98-magerun2/releases/download/10.1.0/n98-magerun2.phar` with sha256 `76c931312f3ab6a5a5e1dbd40544cf43f9ecab176bca6a3597ebf4a3413fe270` checked, PHP 8.2 unchanged. Card from the CARDS pass.
- **Test**, **Verify**: the recipe's.

#### Step 30: CVE-2026-5833 (taskwarrior)

- **Do**: The taskrc reduced to what is needed.
- **Test**, **Verify**: the recipe's.

#### Step 31: CVE-2026-3680 (biome)

- **Do**: The real biome 1.9.4, the benign call on a real file outside the layout, the accepted check attempt 2 (recorded as a kept result).
- **Test**, **Verify**: the recipe's.

#### Step 32: CVE-2026-5602 (heim)

- **Do**: The heim stand-in, its documented deploy output and the published example app inlined as `RUN` heredocs.
- **Test**, **Verify**: the recipe's.

#### Step 33: CVE-2026-55157 (token-optimizer)

- **Do**: `mechanisms` `{COMMAND_EXECUTION, READ_OUTSIDE_SCOPE}`.
- **Test**, **Verify**: the recipe's.

#### Step 34: CVE-2026-81562 (claude-in-mobile)

- **Do**: Platform-Tools r37.0.1 from its zip with the sha256 checked, the `adbd.js` transport, the benign `device_list`.
- **Test**, **Verify**: the recipe's.

#### Step 35: CVE-2026-44717 (mcp_calculate_server), new target

- **Do**: Service `holdout-2026-44717-calculate`, `command_injection_env`, kept 25, `frozenset({COMMAND_EXECUTION})`, full commit hashes in the Dockerfiles, base by digest, card from the CARDS pass.
- **Test**, **Verify**: the recipe's.

#### Step 36: CVE-2026-15415 (aws-healthomics), new target

- **Do**: Service `holdout-2026-15415-healthomics`, `command_injection_env` (the kit's `healthomics_env`), kept 21, miniwdl 1.16.0 and cwltool 3.3.20260925135507 pinned, base by digest.
- **Test**, **Verify**: the recipe's.

#### Step 37: CVE-2026-53710 (python_sandbox_server), new target

- **Do**: Service `holdout-2026-53710-python-sandbox`, `command_injection_env`, kept 25, tags resolved to commits, base by digest, card from the CARDS pass with k8s-api-server and loopback-service in `unkept`.
- **Test**, **Verify**: the recipe's.

#### Step 38: CVE-2026-19978 (android), adb raised to Platform-Tools 37.0.1

- **Do**: The `adbd.js` transport inlined byte-identical to CVE-2026-81562's (sha256 `9dcc0875…`), adb from the same checksummed Platform-Tools 37.0.1 zip as 81562 in place of Debian's adb, the route check through the meta-tools. Once green, the card's `software_releases` records Platform-Tools 37.0.1 (day 2026-11-05, the source line the reading cites). A raise that cannot run in the confined container is handled as the plan's release edge case says, logged.
- **Test**, **Verify**: the recipe's.

#### Step 39: CVE-2025-9654 (mcp-ssh), OpenSSH raised to 10.6p1

- **Do**: `MCP_SILENT` dropped, OpenSSH 10.6p1 built from the portable tarball checked by sha256 (its hex digest resolved from the source, the release notes giving base64 `qdyVZd/+hkD2TYY80poyvEo9vewFZqf8RMXW7nZ9Xzk=`), the client only installed, and the step checks the image carries no `sshd` binary. `software_releases` records OpenSSH 10.6p1 once green, the log saying why 10.6p1 is kept over 10.6p2.
- **Test**, **Verify**: the recipe's.

#### Step 40: CVE-2026-85787 (postgres-mcp-server), new target, PostgreSQL 18.6

- **Files**: `tests/unit/support/test_public_stand_ins_given.py`.
- **Do**: Service `holdout-2026-85787-postgres`, `command_injection_env`, kept 18, `mechanisms` `frozenset({READ_OUTSIDE_SCOPE, INTERNAL_FETCH, COMMAND_EXECUTION})`, the AWS stand-ins declared (out of the pending set). `postgres:18.6-bookworm@sha256:f1ea2a1a4fb7b68d4836be1fdcb8a6466a89b072158bf9d97663600538c294c5`, the data directory initialised at build under 65534 (the 18 image's `PGDATA` moved, see the edge case), `software_releases` recording PostgreSQL 18.6 once green.
- **Test**, **Verify**: the recipe's.

#### Step 41: CVE-2026-85788 (mysql-mcp-server), MySQL 26.10.0 and its nuisance copy (batch end)

- **Files**: `tests/unit/support/test_public_stand_ins_given.py` (the pending set deleted), `evals/holdout_environments.py` and `tests/unit/test_cve_launches.py` only if the kit's builder differs from `mysql_db_env`, `evals/nuisance_admission.json`, `docs/nuisance-log.md`.
- **Do**: Kept 21 to 19, moto replaced by the AWS stand-ins, `has_network` true, `AWS_CA_BUNDLE` trusted, the secret's username `postgres`. `mysql:26.10.0@sha256:3819b2b23835c4a73c8b022fafc33c8095c0f81c929a8b7a84613d2fba6c52f5`, the authentication adapted without `mysql_native_password` (edge case), `software_releases` recording MySQL 26.10.0 once green. The pending set is empty now: delete it and its test. Once green, copy the admission's `fix_check` record of CVE-2026-85788 again from this calibration (`exploit_calls`, the surfaces, `patched_benign_errored`) and set its `holdout_fingerprint` to the target's current `fixture_fingerprint`, the server's `software_releases` not copied, with a nuisance-log entry. Batch end: report `docker system df`.
- **Test**: the recipe's, plus `test_nuisance_admission_loads.py` and `test_nuisance_holdout_copies.py`.
- **Verify**: the recipe's, plus `uv run python -m evals.run_nuisance calibrate --cve CVE-2026-85788` and `uv run python -m evals.run_nuisance vet --server PyPI:awslabs-mysql-mcp-server` green with the copy matching.

### Closing

#### Step 42: Retire the v9 shim

- **Files**: `tests/unit/test_holdout_card_readiness.py`, `tests/unit/test_calibration_dossier.py` and its given, `tests/unit/support/test_census_draw_given.py`; `evals/census_draw.py`, `evals/holdout_card_readiness.py`, `evals/calibration_dossier.py`; `CLAUDE.md`, `CHANGELOG.md`.
- **Do**: Tests first: the unset cases and `test_the_readme_requires_every_card_field_the_run_refuses_unset` go, a check without a version no longer loads, a check below 11 is still a gap, the given's defaults for the three fields go. Then S13 as the plan's "Closing" paragraph gives it: `seeded_outside_layout`, `stand_ins` and `software_releases` required, plain iteration where `or []` was, `_card_gaps` keeping only "no card", `CardCheck.rule_version` a required `int` with the "rule version unset" gap gone and the version refusal kept, the kit README sentence on optional fields gone. `CLAUDE.md` Commands, the `run_holdout run` entry: the refusal is a missing card or a card check below version 11. `CHANGELOG.md`: the field-refusal lines amended.
- **Test**: as above, `test_holdout_census.py` loading the 37 cards.
- **Verify**: the short loop, `uv run python -m evals.run_holdout calibration-dossier --cve CVE-2026-44717 --out output/holdout-vesting/kit` writing a kit whose README no longer calls the card fields optional, the full check.

#### Step 43: Close the vesting

- **Files**: `tests/unit/test_holdout_targets.py`, `docs/holdout-log.md`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Do**: Test first: every holdout target's working directory is the checkout or `/work`. Run `uv run python -m evals.run_holdout calibrate` on all 37 and `CVE_PLANTING_REQUIRED=1 uv run pytest tests/integration -n auto`, and `uv run python -m evals.run_cve_benchmark --calibrate` with the four acceptance targets as before. The closing holdout-log entry with every item the plan's "Logs" lists (the Docker version, the current grammar fingerprint beside the draw's, the fingerprint listing of the 37 and the 4 acceptance targets, that no holdout run has taken place, and any target the maintainer kept in its calibrated state with its failing condition). `README.md` and `CONTRIBUTING.md` holdout paragraphs at 37 (the 30 drawn and the 7 the version 11 re-walk let in, every card ready under version 11), `CONTRIBUTING.md`'s sentence on the heavy holdout images and pruning the build cache after them, the count in `CHANGELOG.md`'s `run_holdout` entry. `run_holdout run` is not launched. Final `docker image prune -f`, `docker builder prune -a -f` and `docker system df`.
- **Test**: the working-directory guard, the whole-set calibration green, every kept layout place routed.
- **Verify**: the whole-set calibration, the integration run with `CVE_PLANTING_REQUIRED=1`, the acceptance calibration, the final fingerprint listing, the full check.
