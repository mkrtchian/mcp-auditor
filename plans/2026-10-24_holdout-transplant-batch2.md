# Holdout transplant, remaining targets

## Context

The holdout draw is finished at 30 targets. The first transplant plan (`plans/2026-10-23_holdout-transplant-batch1.md`) built the shared machinery and carried six targets to a green calibration: the image-tag namespace, the `run_holdout calibrate` command and its per-target gate, the per-target fixture package (`evals/holdout_fixtures/`), the thin `holdout_targets.py` assembler, and the first custom environment builder (`mysql_db_env`). That plan is the fixed recipe. This plan carries the remaining twenty-four, written from what the first batch learned rather than from a guess, so it does not re-derive the mechanics: it names the recipe once and applies it, calling out only what is new per target.

A target is done when it calibrates: its exploits surface the nonce on the vulnerable image, the benign call is clean on both versions, no nonce surfaces on the patched image, and every kept layout place has a route. Calibration needs Docker but no LLM. This plan does not run a scored holdout audit; the first scored run happens later, at the frozen commit, under the chosen model. When all twenty-four calibrate, `HOLDOUT_TARGETS` holds all thirty drawn targets and the living docs match.

The recipe, carried from batch 1 and not restated per target below: copy the authoritative kit's two server Dockerfiles into `evals/docker/` under the namespace `holdout-<year>-<num>-<service>`; add the services to `compose.yml` with their `image:` tag and `org.mcp-auditor.dockerfile-fingerprint` label (regenerate with `tests/unit/test_cve_compose_labels.py`); a Dockerfile must contain no `COPY`/`ADD` from the build context, so a kit support file is baked with an inline `RUN` heredoc; port the kit's authored fixture into `evals/holdout_fixtures/<slug>.py` by swapping the kit imports (`kit_client` to `mcp_auditor.domain.ports.MCPClientPort`, `kit_launch` to `evals.cve_environments`, `kit_target`'s `KitTarget`/`KitExploit` to `cve_targets.CVETarget` and the repo callable type), dropping the `image_tag` import, namespacing the service names, and setting `images`/`server_image`/`patched_image` to the namespaced plain service names; add the four acceptance-only `CVETarget` fields (`severity`, `awaited_capability=None`, `note`, `tools_filter=None`) and `ci_skip_reason=None`; append the `TARGET` to the assembler. Port the body, do not paste it (drop comments that restate the code, keep a non-obvious why). An SSRF target carries the literal `"sentinel"` as a second `images` entry and reuses the shared, non-namespaced `sentinel` service, never a per-target one. When a target was recalibrated, its latest kit is authoritative.

`severity` follows the batch-1 convention and its literal format, `"CVSS <score> (v<version>, <source token>)"` (the source token is the scorer slot inside the parenthetical, as in `"CVSS 6.8 (v4.0, kit card)"` and `"CVSS 7.5 (v3.1, placeholder)"`): the CVSS number from the kit's calibration card when the card carries it inline, with source token `kit card` (no unconfirmed external scorer asserted); an honest `placeholder` number and the `placeholder` token when the card carries none. No web lookup (the holdout is measured blind). `severity` is read by no holdout module (only `cve_oracle` reads it, for acceptance `CVE_TARGETS`, which holdout targets are not in); it becomes load-bearing only if a target later moves to acceptance by retire-on-read, when the real cve.org CVSS and source are filled by hand.

## What was verified against the kits and the code before writing this

- The twenty-four remaining targets and their builders: a majority use the shared `command_injection_env` (node, python, one go), five use the shared `ssrf_env` with the shared sentinel, and five carry a new environment builder or a heavy backend not seen in batch 1 (see "Batch A"). No remaining target uses `git_init_traversal_env`; that builder stays exercised only by the acceptance git target, so this plan ports no git-traversal builder.
- Custom builders live in the target's kit: in its fixture module (`doris_builder` in the doris kit's fixture, the arcadedb builder in the kit's `arcadedb_target.py`) or in its `kit_launch.py` (where batch 1's `mysql_db_env` came from). Each is ported into `evals/cve_environments.py` within its target's step, beside the four shared builders and batch 1's `mysql_db_env`, so the import recipe stays uniform (every fixture swaps `kit_launch` to `cve_environments`) and all environment builders stay in one cohesive module. On port each takes the module's `_env` naming convention (every builder there ends in `_env`): `doris_builder` becomes `doris_db_env`, the arcadedb builder a matching `_env` name; `ssrf_redirect_env` already conforms. This grows `cve_environments.py` from 294 lines to roughly 360-385, within the repository's de facto norm for this layer (`cve_targets.py` is 364, `domain/models.py` 375, `holdout_run.py` 362), a deliberate and consistent use of the "rarely exceed 300" latitude rather than a split into a grab-bag module. If the module later grows well past that norm, split it along a real cohesion axis then. Each ported builder adds a builder and changes none.
- The places catalogue is the shared 36-id `evals/holdout_places.json`; batch 1 confirmed the sampled kits match it exactly. Each target step re-confirms its kit introduces no new place id (a new id would need a catalogue change, out of this plan's scope and not expected).
- `HOLDOUT_TARGETS` currently holds the six batch-1 targets; `evals/holdout_fixtures/` holds their modules and the empty `__init__.py`; `run_holdout calibrate` exists and gates per `--cve`. This plan extends all three, it does not rebuild them.

## Approach

Three batches, ordered to surface the new frictions first, each target an independent Docker calibration gate and its own commit (as in batch 1). Within a batch, targets are independent; the batch boundary is where the build cache is pruned.

Batch A first (five targets with a new builder or a heavy backend): these are the only frictions batch 1 did not already cover, so they carry the plan's risk and are done while attention is freshest. Batch B next (five SSRF targets on the shared `ssrf_env` and sentinel). Batch C last (the command-execution run on the shared `command_injection_env`, the most numerous and the most mechanical now that the recipe is fixed). A final step updates the living docs and the count once all thirty targets are present.

Disk discipline, tighter than batch 1 because batch A pulls heavy base images (a Doris cluster, an ArcadeDB server, the .NET SDK, a Go toolchain, a Chromium for Puppeteer): `docker builder prune` after each target calibrates green, and `docker image prune` for dangling layers at each batch boundary. Confirm `docker system df` stays within free space at each boundary; the heavy bases are the ones to watch.

## Batch A: new builder or heavy backend (five targets)

These five are the new frictions. Each is one step, one commit, calibrated green before the next.

1. CVE-2025-66335, doris-mcp-server (SQL identifier injection reaching `internal_fetch` via Doris's `http()` TVF): ports the kit fixture's `doris_builder` into `cve_environments` as `doris_db_env` (the `_env` convention, mirroring `mysql_db_env`). The builder provisions a persistent Doris cluster reused across exercises and stands a sentinel; the backend's readiness is part of the benign-call-clean check, so make the cluster start deterministic (a flaky backend reads as a dead condition). The flaw's reach is `internal_fetch`, so the target carries the literal `"sentinel"` in `images` and reuses the shared sentinel. This is the heaviest backend in the plan; build and calibrate it alone, prune before the next.
2. GHSA-8g7g-hmwm-6rv2, n8n-mcp (redirect-following SSRF): ports `ssrf_redirect_env` from the kit fixture into `cve_environments`. It differs from `ssrf_env` in that the sentinel serves a redirect the server follows inward; confirm the shared sentinel image serves the redirect the builder expects (the nonce is still injected at runtime via `-e FLAG=...`). SSRF reach, literal `"sentinel"` in `images`. This is the one drawn target with a GHSA id and no CVE, so the CVE-shaped naming has no year and number slot. Naming form for a GHSA target, applied to the service keys, image tags, Dockerfile names, fixture module and `images`/`server_image`/`patched_image`: `holdout-ghsa-<id lowercased, hyphenated>-<service>`, so service `holdout-ghsa-8g7g-hmwm-6rv2-n8n` (and `-patched`), tag `mcp-auditor-cve-holdout-ghsa-8g7g-hmwm-6rv2-n8n:local`, Dockerfile `Dockerfile.holdout-ghsa-8g7g-hmwm-6rv2-n8n`, fixture module `ghsa_8g7g_hmwm_6rv2_n8n.py`. `cve_id` carries the GHSA string `GHSA-8g7g-hmwm-6rv2` (no format validation forbids it), and `run_holdout calibrate --cve GHSA-8g7g-hmwm-6rv2` filters on it.
3. CVE-2026-65831, arcadedb (read plus fetch, JS sandbox escape): the kit ships its fixture as `arcadedb_target.py` and a custom builder; port the builder into `cve_environments` under an `_env` name. Heavy backend (the ArcadeDB server image); make its readiness deterministic for the benign check. Confirm the target's `reaches` set and `kept_places` match what the fixture declares.
4. CVE-2026-45555, RoslynCodeLens .NET (command execution): base image `mcr.microsoft.com/dotnet/sdk:10.0`, heavy. Confirm the builder (shared `command_injection_env` unless the kit fixture defines its own); if custom, port it. The .NET server's startup under the repository confinement is the friction to watch.
5. CVE-2026-5323, a11y-mcp (SSRF via Puppeteer `page.goto`): Puppeteer downloads a Chromium into the image, heavy. Confirm the builder (likely `ssrf_env` or a kit-local variant; port if custom). SSRF reach, shared sentinel, literal `"sentinel"` in `images`. Chromium under `--network none` plus the sidecar is the friction: the exploit fetches the sentinel endpoint, the benign call must stay clean.

Batch A boundary: `docker image prune`, confirm `docker system df` within free space, then `run_holdout calibrate` green over the batch-A targets.

## Batch B: SSRF on the shared builder (five targets)

Each uses the shared `ssrf_env` and the shared `sentinel` service (literal `"sentinel"` in `images`, `has_network=True` in the `PlantingHost`), one step and one commit each. The recipe is batch 1's fetch target; the only per-target work is the server Dockerfiles, the namespaced services, and the fixture port.

1. CVE-2026-33060, ckan (internal fetch SSRF).
2. CVE-2026-55787, flyto-core (SSRF via IPv6-mapped literal).
3. CVE-2026-58485, mcp-searxng (SSRF by rebinding).
4. CVE-2026-42260, open-websearch (SSRF via bracketed IPv4-mapped IPv6 literal).
5. CVE-2026-18905, contextforge (internal fetch SSRF by rebinding): confirm whether the kit uses `ssrf_env` or a rebinding variant; if a variant builder, port it (this one may belong in batch A if it ships a custom builder, settle at transplant).

Batch B boundary: `docker builder prune`, `run_holdout calibrate` green over the batch-A and batch-B targets.

## Batch C: command execution on the shared builder (the remaining targets)

Each uses the shared `command_injection_env`, one step and one commit each. The recipe is batch 1's maigret and godot targets; the only new per-target work is the server Dockerfiles, the namespaced services, the fixture port, and, where the kit stubs an external CLI, carrying that stub faithfully (baked with an inline `RUN` heredoc, no `COPY`).

1. CVE-2026-7785, wireshark-mcp.
2. CVE-2025-9654, mcp-ssh.
3. CVE-2026-19978, android-mcp-server.
4. CVE-2026-55581, mcp-shell (allowlist bypass via escape alias, go toolchain base image).
5. CVE-2025-58358, mcp-markdownify.
6. CVE-2026-5603, magento2-dev-mcp.
7. CVE-2025-53818, github-kanban-mcp (injection in `add_comment`).
8. CVE-2026-5833, mcp-server-taskwarrior (injection in `mark_task_done`).
9. CVE-2026-26029, sf-mcp-server (injection in `query_records`).
10. CVE-2026-3484, mcp-nmap-server (injection in the advertised `run_nmap_scan`).
11. CVE-2026-3680, biome-mcp-server (injection in the advertised `biome-lint`/`biome-format`).
12. CVE-2026-5602, heim-mcp (injection in `deploy_heim_application`, benign CLI stub like godot).
13. CVE-2026-55157, token-optimizer.
14. CVE-2026-81562, claude-in-mobile.

Each of these needs its builder confirmed from its kit fixture at transplant; the family is `command_injection_env` for all, but a target that ships a kit-local builder gets it ported in its own step (not expected here, flagged so the implementer checks). Batch C boundary: `docker builder prune`, then the whole-set gate below.

## Final step: living docs and the whole-set calibration

- `run_holdout calibrate` green over all thirty targets (`HOLDOUT_TARGETS` now holds 30).
- Update the living docs in the same work. Three places carry the current count and say six of the thirty drawn targets are transplanted: `CHANGELOG.md` `[Unreleased]` ("now holds six of its thirty targets"), `README.md` (the holdout paragraph, "Six of the thirty drawn targets have entered the run command's list"), and `CONTRIBUTING.md` (the holdout paragraph of the CVE benchmark section, "Six of the thirty drawn targets are transplanted so far, the rest a later batch"). Each is rewritten to say all thirty are transplanted. Leave intact the statement that the run command has not yet been run and publishes no capability number: this plan runs no scored audit, so that stays true. `CLAUDE.md`'s `run_holdout calibrate`/`run` command entries carry no target count and need no change. No change to `plans/` or `docs/adr/`.

## What stays unchanged

- `evals/cve_targets.py`, `CVE_TARGETS`, the acceptance baselines and gate. Filling `HOLDOUT_TARGETS` does not touch the acceptance layer; the isolation test keeps instruments from importing `holdout_targets`.
- The honeypot and judge instruments, their baselines and gates.
- `image_tag`, `cve_calibration`, `cve_route`, `cve_layout_check`, `cve_places` and the places file. In `cve_environments` the four shared builders and batch 1's `mysql_db_env` keep their behaviour; the module only gains the new custom builders (additive, none changed).
- The selection rule, the census and its draw record, the run conditions file, and the run mode's reporting. This plan fills the target list the run mode already reads.
- The six batch-1 targets, their fixtures, Dockerfiles and services, and the `run_holdout calibrate` command. This plan extends, it does not edit them.

## Edge cases and confinement frictions

- The batch-A backends (Doris cluster, ArcadeDB, .NET SDK, Chromium) are the heavy, slow, order-sensitive cases: a backend that is not ready when the benign call runs reads as a dead condition, so each must be made deterministic, and each is built and calibrated alone with a prune after it.
- A redirect-following SSRF (n8n) and a Puppeteer SSRF (a11y) exercise the sentinel differently from a plain fetch: the sentinel still serves a runtime nonce, but the server reaches it by following a redirect or by driving a headless browser. Calibration confirms the nonce surfaces in the tool response on the vulnerable image and not on the patched one.
- A command-execution target that stubs an external CLI (heim, like godot) carries the stub faithfully, baked into the image; calibration confirms the injection still surfaces the nonce with the stub in place.
- A target whose kit ships a builder not among the shared four is ported into `cve_environments` in its own step; the plan expects this only for batch A, and each batch-C step checks for it before assuming `command_injection_env`.
- A kit that introduces a place id absent from the shared catalogue would need a catalogue change, which is out of scope; the per-target check catches it so it is surfaced, not silently worked around.
- The GHSA target's non-`CVE-YYYY-N` id passes the calibrate path (a plain-string `--cve` filter, no format validation), but the scored `run_holdout run` reporting is out of this plan's scope and was not exercised with such an id. The n8n step confirms `holdout_run`/`holdout_report` do not assume a CVE-shaped id (no parse that would raise, no label that would mis-render), so the GHSA target does not break only later at the first scored run.

## Test scenarios

- Each target calibrates: `run_holdout calibrate --cve <CVE>` green (exploits surface the nonce on the vulnerable image, benign call clean on both, no nonce on the patched image, kept places route).
- `test_holdout_targets.py` structural guards pass for each new target (reaches in vocabulary, kept places within reach and placeable, kept list plants together, no `tools_filter`, `ci_skip_reason is None`).
- `test_holdout_kit_isolation.py` still passes (field parity unchanged).
- The unit test pinning that no instrument imports `holdout_targets` still passes.
- `test_cve_compose_labels.py` passes with the new services and their fingerprints, and with no Dockerfile copying from the build context.
- The existing `cve_environments` builders keep their behaviour (additive change), so their tests still pass; each new builder is verified by the per-target Docker calibration gate (as batch 1 verified `mysql_db_env`).
- The acceptance gate and the batch-1 targets are unaffected (separate module, no shared mutation).

## Verification

- `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (no file argument) all green at each step's close.
- `python -m evals.run_holdout calibrate` green over all thirty targets at the end (Docker, no LLM).
- `docker system df` within free space at each batch boundary, the build cache pruned per target and dangling images pruned per batch.
- `HOLDOUT_TARGETS` holds 30 targets, disjoint from the acceptance targets (the isolation test).
- Living docs match: no doc still says the holdout has no transplanted targets.

## Due diligence record

This section records what the pre-execution diligence pass concluded about this plan's external facts. Later passes (the implementation-phase fact check) read it. Two standing rules: no pass may treat a line here as a reason to skip a verification, since a line says what was concluded once, not what is true now; and a human who edits the corresponding fact by hand must delete its line rather than update it, so the section never asserts something nobody re-checked.

No live web verification was performed, by design, as in batch 1. This is a blind holdout: each target's external per-target facts (affected and first-patched versions, CVSS, mechanism, base images) are pinned in the maintainer's calibration kit held outside the repository, and re-checking them against live PyPI/NVD/GHSA is contraindicated (an upstream rescore or a yanked release must not move a fixture pinned to a calibrated vulnerable/patched pair). The authoritative source for every per-target value is the target's own kit. The settled lines below were checked against the in-repo code and the batch-1 state, not the web.

- SETTLED: the batch count sums to the draw. Batch A 5 + batch B 5 + batch C 14 = 24 remaining, plus batch 1's 6 = 30, matching the closed draw (`HOLDOUT_TARGETS` currently holds the six batch-1 targets; `evals/cve_environments.py` carries `mysql_db_env`).
- SETTLED: the new custom builders are added to `evals/cve_environments.py` (294 lines today), landing around 360-385 lines, within the repository's de facto norm for this layer (`cve_targets.py` 364, `domain/models.py` 375, `holdout_run.py` 362). No split into a separate module: that kept the import recipe uniform and all environment builders cohesive, rather than a grab-bag module with a blurred membership rule.
- SETTLED: a GHSA id as `cve_id` is accepted. `CVETarget.cve_id` is a plain `str` with no format validation anywhere in the calibrate path, and `run_holdout calibrate --cve` filters by plain string equality, so `GHSA-8g7g-hmwm-6rv2` and `--cve GHSA-8g7g-hmwm-6rv2` work. (The scored `run_holdout run` reporting is out of this plan's scope; the implementer confirms it tolerates a non-`CVE-` id before the first scored run.)
- SETTLED: the three living-doc sentences the final step rewrites exist verbatim: `CHANGELOG.md` `[Unreleased]` ("now holds six of its thirty targets"), `README.md` ("Six of the thirty drawn targets have entered the run command's list"), `CONTRIBUTING.md` ("Six of the thirty drawn targets are transplanted so far, the rest a later batch"). `CLAUDE.md`'s `run_holdout` entries carry no count, so they need no change.
- SETTLED: the closed reach vocabulary is `{arbitrary_read, command_execution, internal_fetch}` (`REACHABLE_BY` in `evals/cve_places.py`). Every reach this plan names (SSRF to `internal_fetch`, command execution to `command_execution`, read/read-plus-fetch to `arbitrary_read`/both) is inside it.
- OPEN (deferred): `severity` (the CVSS string, `kit card` or `placeholder` token per the batch-1 convention) for each of the 24 targets, taken from the kit's calibration card at transplant. No web lookup.
- OPEN (deferred): `note` (one line naming the mechanism) for each target, drawn from the kit card's flaw description at transplant.
- OPEN (deferred): the per-target builder for `contextforge` (Batch B item 5), `RoslynCodeLens` (A4) and `a11y-mcp` (A5), confirmed from each kit's fixture at transplant. `contextforge` may move from batch B to batch A if its kit ships a custom rebinding builder; the 24-count is robust to that reshuffle (B 4 + A 6). Every batch-C target likewise has its `command_injection_env` assumption confirmed against its kit before porting.
- OPEN (deferred): the batch-A base images (Doris cluster, ArcadeDB server, `mcr.microsoft.com/dotnet/sdk:10.0`, Puppeteer Chromium) come from the kits' Dockerfiles verbatim; not web-verified, per the blind-holdout stance.
- OPEN (deferred): the kept layout places and their route settlement for every multi-place or guarded-place target, decided by the in-repo route check at transplant (as batch 1 settled CVE-2026-4270 and CVE-2025-11489).

## Implementation steps

One step per drawn target (24), ordered batch A then B then C as the plan sequences them, each closing on a Docker calibration (no LLM) and its own commit, exactly the granularity batch 1 used. Step 1 (first batch-A target) runs the one-time Docker disk prep. A final step (25) updates the living docs once all thirty targets are present. The shared machinery (image-tag namespace, `run_holdout calibrate`, the `evals/holdout_fixtures/` package, the thin `holdout_targets.py` assembler) already exists from batch 1, so there is no scaffold step: every target step extends them.

Verification commands (from `CLAUDE.md`): full check `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` (no file argument); short loop `uv run pytest tests/unit -n auto --maxprocesses 4`; compose-labels guard `uv run pytest tests/unit/test_cve_compose_labels.py`; structural guards `uv run pytest tests/unit/test_holdout_targets.py tests/unit/test_holdout_kit_isolation.py`; image build `docker compose -f evals/docker/compose.yml build <service> <service-patched>`; holdout calibrate `uv run python -m evals.run_holdout calibrate [--cve <CVE>]`.

Shared recipe for every target step (carried from batch 1, stated once here, applied in each step below; see the plan's "The recipe" paragraph and the batch-1 plan's "Shared facts for the fixture ports"): from the target's authoritative kit, (a) copy its two server Dockerfiles into `evals/docker/` renamed `Dockerfile.<service>` / `Dockerfile.<service>-patched` under the namespace `holdout-<year>-<num>-<service>` (for the GHSA target, `holdout-ghsa-<id-lowercased-hyphenated>-<service>`), converting any `COPY`/`ADD` of a kit support file into an inline `RUN` heredoc so the fingerprint covers the baked content (`tests/unit/test_cve_compose_labels.py::test_no_dockerfile_copies_from_the_build_context` forbids context copies); (b) add the two services to `evals/docker/compose.yml` with their `image:` tag and `org.mcp-auditor.dockerfile-fingerprint` label, running `uv run pytest tests/unit/test_cve_compose_labels.py` to print the fingerprints to paste; (c) build `docker compose -f evals/docker/compose.yml build <service> <service-patched>`; (d) port the kit's fixture into `evals/holdout_fixtures/<slug>.py` (slug `<cve-with-underscores>_<service>`): swap the imports (`kit_client.KitClient` to `mcp_auditor.domain.ports.MCPClientPort` on every closure annotation, `kit_launch.<builder>` to `evals.cve_environments.<builder>`, drop the `kit_target` and `image_tag` imports), namespace the service names, set `images`/`server_image`/`patched_image` to the namespaced plain service names (SSRF and internal-fetch targets add the literal `"sentinel"` as a second `images` entry and reuse the shared, non-namespaced `sentinel`), add the four `CVETarget` fields `severity` (the CVSS from the kit's calibration card inline with source token `kit card`, else an honest `placeholder` token, no web lookup), `awaited_capability=None`, `note` (one English line naming the mechanism from the card's flaw description), `tools_filter=None`, and `ci_skip_reason=None`; port the body to the repository comment rule (drop comments that restate the code, keep a non-obvious why); (e) append the module's `TARGET` to `HOLDOUT_TARGETS` in `holdout_targets.py`; (f) re-confirm the kit introduces no place id absent from `evals/holdout_places.json` (a new id is out of scope and surfaces here rather than being worked around), and settle any multi-place or guarded-place `kept_places` by the in-repo route check, recording the keep/drop in a `kept_places` comment. Each step's **Files** lists these; each step's **Do** states only what is new for that target.

Every target step's **Test** is the Docker calibration gate (`uv run python -m evals.run_holdout calibrate --cve <CVE>` green: exploits surface the nonce on the vulnerable image, benign call clean on both versions, no nonce on the patched image, every kept layout place routes) plus the structural guards (`test_holdout_targets.py`: reaches in vocabulary, kept places within reach and placeable, kept list plants together, `tools_filter` absent, `ci_skip_reason is None`) and `test_holdout_kit_isolation.py` (field parity unchanged). Every target step's **Verify** is `uv run pytest tests/unit/test_cve_compose_labels.py tests/unit/test_holdout_targets.py tests/unit/test_holdout_kit_isolation.py`, then `uv run python -m evals.run_holdout calibrate --cve <CVE>` green, then the full check green. Only deviations from this are noted per step.

### Batch A: new builder or heavy backend

Built and calibrated one at a time; `docker builder prune` after each calibrates green, `docker image prune` and `docker system df` within free space at the batch boundary.

#### Step 1: Transplant CVE-2025-66335 (doris-mcp-server), port `doris_db_env`

Runs the one-time Docker disk prep first (this is the first Docker-touching step of batch 2): `docker volume prune`, `docker builder prune`, confirm `docker system df` within free space.

- **Files**: `evals/cve_environments.py` (add `doris_db_env`, ported from the doris kit's fixture `doris_builder` under the `_env` convention, mirroring `mysql_db_env`; changes no existing builder); `evals/docker/Dockerfile.holdout-2025-66335-doris`, `-patched`; `evals/docker/compose.yml` (two services + labels); `evals/holdout_fixtures/cve_2025_66335_doris.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port `doris_db_env` into `cve_environments.py` first so the fixture's `builder` resolves after the import swap. The builder provisions a persistent Doris cluster reused across exercises and stands a sentinel; the backend's readiness is part of the benign-call-clean check, so make the cluster start deterministic (a flaky backend reads as a dead condition). Reach is `internal_fetch` via Doris's `http()` TVF, so `images` carries the literal `"sentinel"` beside the namespaced server service. Heaviest backend in the plan: build and calibrate alone, prune before step 2.
- **Verify**: the shared per-target verify, then `docker builder prune`.

#### Step 2: Transplant GHSA-8g7g-hmwm-6rv2 (n8n-mcp), port `ssrf_redirect_env`

- **Files**: `evals/cve_environments.py` (add `ssrf_redirect_env`, ported from the kit fixture; additive); `evals/docker/Dockerfile.holdout-ghsa-8g7g-hmwm-6rv2-n8n`, `-patched`; `evals/docker/compose.yml` (two services + labels, image tag `mcp-auditor-cve-holdout-ghsa-8g7g-hmwm-6rv2-n8n:local`); `evals/holdout_fixtures/ghsa_8g7g_hmwm_6rv2_n8n.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Redirect-following SSRF: `ssrf_redirect_env` differs from `ssrf_env` in that the shared sentinel serves a redirect the server follows inward (nonce still injected at runtime via `-e FLAG=...`); confirm the shared sentinel image serves the redirect the builder expects. SSRF reach, literal `"sentinel"` in `images`. `cve_id` carries the GHSA string `GHSA-8g7g-hmwm-6rv2` (no format validation forbids it). This is the one GHSA target: additionally confirm `holdout_run`/`holdout_report` tolerate a non-`CVE-YYYY-N` id (no parse that raises, no label that mis-renders), so the scored run does not break later on this id; if a parse or label assumes a CVE shape, widen it minimally in this step.
- **Verify**: the shared per-target verify (with `--cve GHSA-8g7g-hmwm-6rv2`), then `docker builder prune`.

#### Step 3: Transplant CVE-2026-65831 (arcadedb), port the arcadedb `_env` builder

- **Files**: `evals/cve_environments.py` (add the arcadedb builder under an `_env` name, ported from the kit's `arcadedb_target.py`; additive); `evals/docker/Dockerfile.holdout-2026-65831-arcadedb`, `-patched`; `evals/docker/compose.yml` (two services + labels); `evals/holdout_fixtures/cve_2026_65831_arcadedb.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Read-plus-fetch via a JS sandbox escape: confirm the target's `reaches` set and `kept_places` match what the fixture declares (expected `arbitrary_read` plus `internal_fetch`, so the literal `"sentinel"` in `images` if the fixture fetches). Heavy ArcadeDB server image: make its readiness deterministic for the benign check.
- **Verify**: the shared per-target verify, then `docker builder prune`.

#### Step 4: Transplant CVE-2026-45555 (RoslynCodeLens .NET), command execution on the .NET SDK

- **Files**: `evals/docker/Dockerfile.holdout-2026-45555-roslyncodelens`, `-patched` (base `mcr.microsoft.com/dotnet/sdk:10.0`); `evals/docker/compose.yml` (two services + labels); `evals/holdout_fixtures/cve_2026_45555_roslyncodelens.py` (new); `evals/holdout_targets.py` (append). Add `evals/cve_environments.py` only if the kit ships a custom builder.
- **Do**: Confirm the builder from the kit fixture: `command_injection_env` unless the kit defines its own, in which case port it into `cve_environments.py` under an `_env` name in this step. The .NET server's startup under the repository confinement (`--network none`, the `/srv` layout, the uid/gid tmpfs home) is the friction to watch; fix it in the Dockerfile or launch, never by loosening the shared confinement.
- **Verify**: the shared per-target verify, then `docker builder prune`.

#### Step 5: Transplant CVE-2026-5323 (a11y-mcp), SSRF via Puppeteer

- **Files**: `evals/docker/Dockerfile.holdout-2026-5323-a11y`, `-patched` (Puppeteer downloads a Chromium into the image, heavy); `evals/docker/compose.yml` (two services + labels); `evals/holdout_fixtures/cve_2026_5323_a11y.py` (new); `evals/holdout_targets.py` (append). Add `evals/cve_environments.py` only if the kit ships a custom builder.
- **Do**: Confirm the builder: `ssrf_env` or a kit-local variant (port if custom). SSRF reach, shared sentinel, literal `"sentinel"` in `images`. The friction is Chromium under `--network none` plus the sentinel sidecar: the exploit fetches the sentinel endpoint via `page.goto`, the benign call must stay clean.
- **Verify**: the shared per-target verify. Batch A boundary: `docker image prune`, confirm `docker system df` within free space, `uv run python -m evals.run_holdout calibrate` green over the batch-A targets.

### Batch B: SSRF on the shared `ssrf_env` and shared sentinel

Each uses `ssrf_env` and the shared `sentinel` (literal `"sentinel"` in `images`, `has_network=True` in the `PlantingHost`). Per-target work is only the two server Dockerfiles, the namespaced services, and the fixture port. `docker builder prune` at the batch boundary.

#### Step 6: Transplant CVE-2026-33060 (ckan), internal-fetch SSRF
- **Files**: `evals/docker/Dockerfile.holdout-2026-33060-ckan`, `-patched`; `evals/docker/compose.yml` (two services + labels); `evals/holdout_fixtures/cve_2026_33060_ckan.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=ssrf_env`, `images=("holdout-2026-33060-ckan", "sentinel")`.

#### Step 7: Transplant CVE-2026-55787 (flyto-core), SSRF via IPv6-mapped literal
- **Files**: `evals/docker/Dockerfile.holdout-2026-55787-flyto`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_55787_flyto.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=ssrf_env`, literal `"sentinel"` in `images`.

#### Step 8: Transplant CVE-2026-58485 (mcp-searxng), SSRF by rebinding
- **Files**: `evals/docker/Dockerfile.holdout-2026-58485-searxng`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_58485_searxng.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=ssrf_env`, literal `"sentinel"` in `images`. Confirm the kit uses `ssrf_env` and not a rebinding variant; if a variant builder, port it in this step.

#### Step 9: Transplant CVE-2026-42260 (open-websearch), SSRF via bracketed IPv4-mapped IPv6 literal
- **Files**: `evals/docker/Dockerfile.holdout-2026-42260-open-websearch`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_42260_open_websearch.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=ssrf_env`, literal `"sentinel"` in `images`.

#### Step 10: Transplant CVE-2026-18905 (contextforge), internal-fetch SSRF by rebinding
- **Files**: `evals/docker/Dockerfile.holdout-2026-18905-contextforge`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_18905_contextforge.py` (new); `evals/holdout_targets.py` (append). Add `evals/cve_environments.py` only if the kit ships a custom rebinding builder.
- **Do**: Confirm whether the kit uses `ssrf_env` or a rebinding variant; if a variant builder, port it into `cve_environments.py` under an `_env` name in this step (this is the one batch-B target that may carry a custom builder). SSRF reach, literal `"sentinel"` in `images`.
- **Verify**: the shared per-target verify. Batch B boundary: `docker builder prune`, `uv run python -m evals.run_holdout calibrate` green over the batch-A and batch-B targets.

### Batch C: command execution on the shared `command_injection_env`

Each uses `command_injection_env`, one step and one commit. Per-target work is the two server Dockerfiles, the namespaced services, the fixture port, and, where the kit stubs an external CLI, carrying that stub faithfully (baked via inline `RUN` heredoc, no `COPY`). Each step first confirms the `command_injection_env` assumption against the kit fixture and ports a kit-local builder in its own step if one is shipped (not expected). `docker builder prune` at the batch boundary.

#### Step 11: Transplant CVE-2026-7785 (wireshark-mcp)
- **Files**: `evals/docker/Dockerfile.holdout-2026-7785-wireshark`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_7785_wireshark.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`.

#### Step 12: Transplant CVE-2025-9654 (mcp-ssh)
- **Files**: `evals/docker/Dockerfile.holdout-2025-9654-mcp-ssh`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2025_9654_mcp_ssh.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`.

#### Step 13: Transplant CVE-2026-19978 (android-mcp-server)
- **Files**: `evals/docker/Dockerfile.holdout-2026-19978-android`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_19978_android.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`. If the exploit needs the Android CLI (`adb`) the container lacks, carry the kit's benign stub faithfully (baked, no `COPY`).

#### Step 14: Transplant CVE-2026-55581 (mcp-shell), allowlist bypass via escape alias
- **Files**: `evals/docker/Dockerfile.holdout-2026-55581-mcp-shell`, `-patched` (go toolchain base image); `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_55581_mcp_shell.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`. The injection is an allowlist bypass via an escape alias; the go toolchain base is the only new friction (heavier build).

#### Step 15: Transplant CVE-2025-58358 (mcp-markdownify)
- **Files**: `evals/docker/Dockerfile.holdout-2025-58358-markdownify`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2025_58358_markdownify.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`.

#### Step 16: Transplant CVE-2026-5603 (magento2-dev-mcp)
- **Files**: `evals/docker/Dockerfile.holdout-2026-5603-magento2`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_5603_magento2.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`.

#### Step 17: Transplant CVE-2025-53818 (github-kanban-mcp), injection in `add_comment`
- **Files**: `evals/docker/Dockerfile.holdout-2025-53818-github-kanban`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2025_53818_github_kanban.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`; the injection is in `add_comment`.

#### Step 18: Transplant CVE-2026-5833 (mcp-server-taskwarrior), injection in `mark_task_done`
- **Files**: `evals/docker/Dockerfile.holdout-2026-5833-taskwarrior`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_5833_taskwarrior.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`; the injection is in `mark_task_done`.

#### Step 19: Transplant CVE-2026-26029 (sf-mcp-server), injection in `query_records`
- **Files**: `evals/docker/Dockerfile.holdout-2026-26029-sf-mcp`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_26029_sf_mcp.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`; the injection is in `query_records`.

#### Step 20: Transplant CVE-2026-3484 (mcp-nmap-server), injection in `run_nmap_scan`
- **Files**: `evals/docker/Dockerfile.holdout-2026-3484-nmap`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_3484_nmap.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`; the injection is in the advertised `run_nmap_scan`. If the exploit needs `nmap` the container lacks, carry the kit's benign stub faithfully (baked, no `COPY`).

#### Step 21: Transplant CVE-2026-3680 (biome-mcp-server), injection in `biome-lint`/`biome-format`
- **Files**: `evals/docker/Dockerfile.holdout-2026-3680-biome`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_3680_biome.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`; the injection is in the advertised `biome-lint`/`biome-format`.

#### Step 22: Transplant CVE-2026-5602 (heim-mcp), injection in `deploy_heim_application` with a benign CLI stub
- **Files**: `evals/docker/Dockerfile.holdout-2026-5602-heim`, `-patched` (carry the kit's benign CLI stub faithfully, baked via inline `RUN` heredoc, no `COPY`, like godot in batch 1); `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_5602_heim.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`. The injection lives in `deploy_heim_application` in the real server code; the external CLI is stubbed benign inside the image. Calibration confirms the injection still surfaces the nonce with the stub in place.

#### Step 23: Transplant CVE-2026-55157 (token-optimizer)
- **Files**: `evals/docker/Dockerfile.holdout-2026-55157-token-optimizer`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_55157_token_optimizer.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`.

#### Step 24: Transplant CVE-2026-81562 (claude-in-mobile)
- **Files**: `evals/docker/Dockerfile.holdout-2026-81562-claude-in-mobile`, `-patched`; `evals/docker/compose.yml`; `evals/holdout_fixtures/cve_2026_81562_claude_in_mobile.py` (new); `evals/holdout_targets.py` (append).
- **Do**: Port per the shared recipe, `builder=command_injection_env`.
- **Verify**: the shared per-target verify. Batch C boundary: `docker builder prune`, then `uv run python -m evals.run_holdout calibrate` green over all thirty targets (`HOLDOUT_TARGETS` now holds 30), `docker system df` within free space.

### Step 25: Update the living docs

- **Files**: `CHANGELOG.md` (`[Unreleased]`), `README.md` (the holdout paragraph), `CONTRIBUTING.md` (the holdout paragraph of the CVE benchmark section).
- **Do**: Rewrite the three sentences that say six of the thirty drawn targets are transplanted to say all thirty are: `CHANGELOG.md` "now holds six of its thirty targets", `README.md` "Six of the thirty drawn targets have entered the run command's list", `CONTRIBUTING.md` "Six of the thirty drawn targets are transplanted so far, the rest a later batch". Leave intact the statement that the run command has not been run and publishes no capability number (this plan runs no scored audit, so it stays true). `CLAUDE.md`'s `run_holdout` entries carry no count and need no change. No change to `plans/` or `docs/adr/`. French prose per the user's writing preferences (no em dashes, avoid semicolons) where the edited text is French.
- **Test**: none (docs only).
- **Verify**: `uv run ruff format --check .` unaffected; re-read each edited sentence to confirm it matches the shipped 30-target state. The full check was already green after step 24.
